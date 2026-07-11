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
// span. This intentionally does not support pipes (`|`) or redirects (`>`,
// `<`) — those are out of scope for this pass.
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
