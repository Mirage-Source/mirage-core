package shell

import "strings"

// statement is one command in a `;`/`&&`/`||`-separated chain. Sep is the
// operator that preceded it ("" for the first statement in a line).
type statement struct {
	Sep  string // "", ";", "&&", "||"
	Text string
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

	flush := func() {
		text := strings.TrimSpace(cur.String())
		if text != "" {
			stmts = append(stmts, statement{Sep: sep, Text: text})
		}
		cur.Reset()
	}

	runes := []byte(line)
	for i := 0; i < len(runes); i++ {
		c := runes[i]

		if quote != 0 {
			cur.WriteByte(c)
			if c == quote {
				quote = 0
			}
			continue
		}

		switch {
		case c == '\'' || c == '"':
			quote = c
			cur.WriteByte(c)
		case c == '(':
			parenDepth++
			cur.WriteByte(c)
		case c == ')':
			if parenDepth > 0 {
				parenDepth--
			}
			cur.WriteByte(c)
		case parenDepth == 0 && c == ';':
			flush()
			sep = ";"
		case parenDepth == 0 && c == '&' && i+1 < len(runes) && runes[i+1] == '&':
			flush()
			sep = "&&"
			i++
		case parenDepth == 0 && c == '|' && i+1 < len(runes) && runes[i+1] == '|':
			flush()
			sep = "||"
			i++
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

		switch {
		case c == '\'' || c == '"':
			quote = c
			cur.WriteByte(c)
		case c == '(':
			parenDepth++
			cur.WriteByte(c)
		case c == ')':
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
func tokenizeWords(text string) []string {
	var words []string
	var cur strings.Builder
	hasCur := false

	var quote byte
	parenDepth := 0

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
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
				hasCur = true
			}
			continue
		}

		switch {
		case c == '\'' || c == '"':
			quote = c
			hasCur = true
		case c == '$' && i+1 < len(runes) && runes[i+1] == '(':
			cur.WriteByte(c)
			cur.WriteByte('(')
			hasCur = true
			parenDepth++
			i++
		case parenDepth > 0 && c == '(':
			parenDepth++
			cur.WriteByte(c)
		case parenDepth > 0 && c == ')':
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
