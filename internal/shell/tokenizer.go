package shell

import (
	"path"
	"strings"
)

// statement is one command in a `;`/newline/`&`/`&&`/`||`-separated chain;
// a newline or background `&` is recorded as ";". Sep is the
// operator that preceded it ("" for the first statement in a line).
type statement struct {
	Sep  string // "", ";", "&&", "||"
	Text string
	Line int // 1-based line its text starts on, for bash -c's "line N:"
}

// splitStatements breaks a line into statements on top-level `;`, `&&`, and
// `||`, without splitting inside quotes or inside a parenthesized/`$(...)`
// span. A statement's Text may still contain a `|` pipeline and
// `>`/`>>`/`<` redirects — see splitPipeline and extractRedirects.
func splitStatements(line string) []statement {
	var stmts []statement
	var cur strings.Builder
	sep := ""

	var quote byte // 0, '\'', or '"'
	parenDepth := 0
	var cs caseScope

	start := 0 // index in line where cur began
	flush := func() {
		raw := cur.String()
		text := strings.TrimSpace(raw)
		if text != "" {
			lead := len(raw) - len(strings.TrimLeft(raw, " \t\r\n"))
			n := 1 + strings.Count(line[:start], "\n") + strings.Count(raw[:lead], "\n")
			stmts = append(stmts, statement{Sep: sep, Text: text, Line: n})
		}
		cur.Reset()
	}

	runes := []byte(line)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if cur.Len() == 0 {
			start = i
		}

		if quote != 0 {
			if quote == '"' && c == '\\' && i+1 < len(runes) {
				// Inside double quotes backslash-newline vanishes, and backslash keeps a following
				// $ ` " or \ from acting as syntax. Any other backslash is an ordinary character.
				if n := continuationLen(runes, i); n > 0 {
					i += n - 1
					continue
				}
				if strings.IndexByte("$`\"\\", runes[i+1]) >= 0 {
					cur.WriteByte(c)
					cur.WriteByte(runes[i+1])
					i++
					continue
				}
			}
			cur.WriteByte(c)
			if c == quote {
				quote = 0
			}
			continue
		}

		// Outside quotes a backslash either continues the line (backslash-newline is deleted, which
		// joins `a \` + newline + `b` and even splits of a word) or makes the next character an
		// ordinary one: an escaped ; & | ( ) quote or space never separates or quotes anything.
		if c == '\\' && i+1 < len(runes) {
			if n := continuationLen(runes, i); n > 0 {
				i += n - 1
				continue
			}
			cur.WriteByte(c)
			cur.WriteByte(runes[i+1])
			i++
			continue
		}

		skip := cs.step(line, i)
		switch {
		case c == '#' && atWordStart(line, i):
			// A comment runs to the end of the line; the newline stays.
			for i+1 < len(runes) && runes[i+1] != '\n' {
				i++
			}
		case c == '\'' || c == '"':
			quote = c
			cur.WriteByte(c)
		case c == '(' && !skip:
			parenDepth++
			cur.WriteByte(c)
		case c == ')' && !skip:
			if parenDepth > 0 {
				parenDepth--
			}
			cur.WriteByte(c)
		case parenDepth == 0 && c == ';':
			flush()
			sep = ";"
			if i+1 < len(runes) && runes[i+1] == ';' {
				sep = ";;"
				i++
			}
		case parenDepth == 0 && (c == '\n' || c == '\r'):
			// A newline right after an operator (`a &&\nb`) or another newline
			// continues the chain rather than starting a `;` statement.
			if strings.TrimSpace(cur.String()) != "" {
				flush()
				sep = ";"
			}
		case parenDepth == 0 && c == '&' && i+1 < len(runes) && runes[i+1] == '&':
			flush()
			sep = "&&"
			i++
		case parenDepth == 0 && c == '|' && i+1 < len(runes) && runes[i+1] == '|':
			flush()
			sep = "||"
			i++
		case parenDepth == 0 && c == '&' && !(i+1 < len(runes) && runes[i+1] == '>') && !(i > 0 && runes[i-1] == '>'):
			flush()
			sep = ";"
		default:
			cur.WriteByte(c)
		}
	}
	flush()

	return stmts
}

// splitPipeline breaks one statement's text into pipeline stages on
// top-level single `|`, quote- and paren-aware like splitStatements. A
// statement with no `|` returns a single-element slice.
func splitPipeline(text string) []string {
	var stages []string
	var cur strings.Builder

	var quote byte
	parenDepth := 0
	var cs caseScope

	runes := []byte(text)
	for i := 0; i < len(runes); i++ {
		c := runes[i]

		if quote != 0 {
			cur.WriteByte(c)
			if c == quote {
				quote = 0
			}
			continue
		}

		skip := cs.step(text, i)
		switch {
		case c == '\'' || c == '"':
			quote = c
			cur.WriteByte(c)
		case c == '(' && !skip:
			parenDepth++
			cur.WriteByte(c)
		case c == ')' && !skip:
			if parenDepth > 0 {
				parenDepth--
			}
			cur.WriteByte(c)
		case parenDepth == 0 && c == '|' && !(i+1 < len(runes) && runes[i+1] == '|'):
			stages = append(stages, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	stages = append(stages, strings.TrimSpace(cur.String()))

	return stages
}

// redirects holds the `>`/`>>`/`<`/`2>`/`2>>`/`2>&1`/`&>` targets pulled out
// of one pipeline stage's word list by extractRedirects.
//
// Only the stderr-goes-somewhere direction is modeled (2>, 2>>, 2>&1, &>) --
// not the reverse (1>&2 / >&2, "send stdout to stderr"). That direction is
// rare in real recon (which wants to *capture* error text, not discard it
// into the noisier stream) and would need a fourth flag for a case attackers
// essentially never use against a honeypot; scoped out rather than modeled
// half-heartedly.
type redirects struct {
	stdoutFile string
	appendMode bool
	stdinFile  string

	stderrFile          string
	stderrAppendMode    bool
	mergeStderrToStdout bool   // 2>&1
	combinedFile        string // &>file (both streams to one file)
}

// extractRedirects pulls redirect operators and their filename out of an
// already-tokenized word list, returning the remaining command+args words
// separately. Recognizes `cmd > file`/`cmd >file` (and `<`) as before, plus
// `2>file`/`2>>file`/`2>&1`/`&>file` in both spaced and attached form.
// Redirects before the command name are still not recognized (matches the
// existing `>`/`<` limitation, not a new gap).
func extractRedirects(words []string) ([]string, redirects) {
	var r redirects
	var out []string

	for i := 0; i < len(words); i++ {
		w := words[i]

		op, rest := "", ""
		switch {
		case w == "2>&1":
			r.mergeStderrToStdout = true
			continue
		case w == "2>" || w == "2>>" || w == "&>" || w == ">" || w == ">>" || w == "<":
			op = w
			if i+1 < len(words) {
				i++
				rest = words[i]
			}
		case strings.HasPrefix(w, "2>>") && len(w) > 3:
			op, rest = "2>>", w[3:]
		case strings.HasPrefix(w, "2>") && len(w) > 2:
			op, rest = "2>", w[2:]
		case strings.HasPrefix(w, "&>") && len(w) > 2:
			op, rest = "&>", w[2:]
		case strings.HasPrefix(w, ">>") && len(w) > 2:
			op, rest = ">>", w[2:]
		case strings.HasPrefix(w, ">") && len(w) > 1:
			op, rest = ">", w[1:]
		case strings.HasPrefix(w, "<") && len(w) > 1:
			op, rest = "<", w[1:]
		default:
			out = append(out, w)
			continue
		}

		switch op {
		case ">":
			r.stdoutFile, r.appendMode = rest, false
		case ">>":
			r.stdoutFile, r.appendMode = rest, true
		case "<":
			r.stdinFile = rest
		case "2>":
			r.stderrFile, r.stderrAppendMode = rest, false
		case "2>>":
			r.stderrFile, r.stderrAppendMode = rest, true
		case "&>":
			r.combinedFile = rest
		}
	}

	return out, r
}

// tokenizeWords splits a single statement into words, honoring single and
// double quotes (stripped from the output) and treating a `$(...)` span as
// an opaque unit that whitespace inside it does not split on. The `$(...)`
// spans themselves are left intact in the returned words for the caller to
// resolve via substitution.
// litDollar stands for a `$` that was quoted ('$x', "\$x" or \$x): the
// tokenizer writes it, substitute never expands it and turns it back into
// "$". A private-use rune, so it does not occur in typed commands.
const litDollar = "\uE000"

func tokenizeWords(text string) []string {
	var words []string
	var cur strings.Builder
	hasCur := false

	var quote byte
	verbatim := false // quote opened inside $( ): the inner text is parsed again later
	parenDepth := 0
	var cs caseScope

	flush := func() {
		if hasCur {
			words = append(words, cur.String())
			cur.Reset()
			hasCur = false
		}
	}

	runes := []byte(text)
	for i := 0; i < len(runes); i++ {
		c := runes[i]

		if quote != 0 {
			if verbatim {
				// Inside $( ) the whole span is evaluated again by evalLine,
				// which does its own quote handling; stripping the quotes
				// here turned `printf '\n'` into `printf n`.
				cur.WriteByte(c)
				if quote == '"' && c == '\\' && i+1 < len(runes) {
					i++
					cur.WriteByte(runes[i])
				} else if c == quote {
					quote = 0
				}
				hasCur = true
				continue
			}
			switch {
			case c == quote:
				quote = 0
			case c == '$' && quote == '"' && i+1 < len(runes) && runes[i+1] == '(':
				// "...$(cmd "quoted")...": the whole substitution is one unit.
				if e := matchingParen(text, i+2); e >= 0 {
					cur.WriteString(text[i : e+1])
					i = e
				} else {
					cur.WriteByte(c)
				}
			case c == '$' && quote == '\'':
				cur.WriteString(litDollar) // '...' never expands
			case c == '\\' && quote == '"' && i+1 < len(runes) && strings.IndexByte("$`\"\\", runes[i+1]) >= 0:
				i++
				if runes[i] == '$' {
					cur.WriteString(litDollar)
				} else {
					cur.WriteByte(runes[i])
				}
			default:
				cur.WriteByte(c)
			}
			hasCur = true
			continue
		}

		skip := cs.step(text, i)
		switch {
		case c == '\\' && parenDepth == 0 && i+1 < len(runes):
			i++
			if runes[i] == '$' {
				cur.WriteString(litDollar)
			} else {
				cur.WriteByte(runes[i])
			}
			hasCur = true
		case c == '\'' || c == '"':
			quote = c
			hasCur = true
			if verbatim = parenDepth > 0; verbatim {
				cur.WriteByte(c)
			}
		case c == '$' && parenDepth == 0 && i+1 < len(runes) && runes[i+1] == '{':
			// ${...} is one word even when it holds spaces (${y:-a b}, ${y: -2}). It is expanded later,
			// and the quotes inside its operands are removed then.
			if end := matchingBrace(text, i+2); end >= 0 {
				cur.WriteString(text[i : end+1])
				i = end
			} else {
				cur.WriteByte(c)
			}
			hasCur = true
		case c == '$' && i+1 < len(runes) && runes[i+1] == '(':
			cur.WriteByte(c)
			cur.WriteByte('(')
			hasCur = true
			parenDepth++
			i++
		case parenDepth > 0 && c == '(' && !skip:
			parenDepth++
			cur.WriteByte(c)
		case parenDepth > 0 && c == ')' && !skip:
			parenDepth--
			cur.WriteByte(c)
		case parenDepth == 0 && (c == ' ' || c == '\t'):
			flush()
		default:
			cur.WriteByte(c)
			hasCur = true
		}
	}
	flush()

	return words
}

// Invocation is one simple command from a line, as logged: Name is the
// basename of the cleaned command path, with leading NAME=value words and
// redirects dropped.
type Invocation struct {
	Name string
	Args []string
}

// ParseCommands lists every simple command in line, across statements,
// pipeline stages and if/case/{ } bodies, without evaluating anything. A line
// that fails to parse is read as a flat list of statements.
func ParseCommands(line string) []Invocation {
	stmts := splitStatements(line)
	var texts []string
	if items, err := parseStatements(append([]statement{}, stmts...)); err == nil {
		texts = statementTexts(items, nil)
	} else {
		for _, st := range stmts {
			texts = append(texts, st.Text)
		}
	}
	var out []Invocation
	for _, text := range texts {
		for _, stage := range splitPipeline(text) {
			words, _ := extractRedirects(tokenizeWords(stage))
			for len(words) > 0 && isAssignmentOnly(words[:1]) {
				words = words[1:]
			}
			if len(words) == 0 {
				continue
			}
			for i, w := range words {
				words[i] = strings.ReplaceAll(w, litDollar, "$")
			}
			out = append(out, Invocation{
				Name: path.Base(path.Clean(words[0])),
				Args: append([]string{}, words[1:]...),
			})
		}
	}
	return out
}

func statementTexts(items []item, out []string) []string {
	for _, it := range items {
		switch it.kind {
		case kindSimple:
			out = append(out, it.text)
		case kindGroup, kindFor, kindSubshell:
			out = statementTexts(it.body, out)
		case kindWhile, kindUntil:
			out = statementTexts(it.conds[0], out)
			out = statementTexts(it.body, out)
		case kindIf:
			for i := range it.conds {
				out = statementTexts(it.conds[i], out)
				out = statementTexts(it.bodies[i], out)
			}
			out = statementTexts(it.elseBody, out)
		case kindCase:
			for _, arm := range it.arms {
				out = statementTexts(arm.body, out)
			}
		}
	}
	return out
}

// NeedsContinuation reports whether line is incomplete the way an
// interactive shell sees it -- an unclosed quote or a trailing backslash --
// so the caller should read another line before running it.
func NeedsContinuation(line string) bool {
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\\':
			if i == len(line)-1 {
				return true
			}
			i++
		case quote == '"':
			if c == '"' {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		}
	}
	return quote != 0
}

// continuationLen is the length of a backslash-newline (or backslash-CRLF) starting at runes[i], else 0.
func continuationLen(runes []byte, i int) int {
	if runes[i] != '\\' || i+1 >= len(runes) {
		return 0
	}
	if runes[i+1] == '\n' {
		return 2
	}
	if runes[i+1] == '\r' && i+2 < len(runes) && runes[i+2] == '\n' {
		return 3
	}
	return 0
}
