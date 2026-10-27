package shell

// caseScope follows `case WORD in PATTERN) ... ;; ... esac` while a scanner
// walks a line byte by byte. The `)` that ends a case pattern (and the
// optional `(` that opens one) is case syntax, not a parenthesis, so a scanner
// that counts parens to find the end of `$( ... )` or `( ... )` must not count
// it. Without this, `$(case a in a) echo x;; esac)` looked closed after `a)`,
// and the `;;` that followed was split off as a top-level separator.
type caseScope struct {
	stack []caseState
}

type caseState struct {
	sawIn     bool // the `in` after the subject word has been seen
	inPattern bool // between `in` or `;;` and the `)` that ends the pattern
}

// step advances the tracker over s[i] and reports whether that byte is case
// pattern syntax whose paren must not change a scanner's nesting depth.
// Call it for every byte outside quotes, in order.
func (c *caseScope) step(s string, i int) bool {
	b := s[i]
	top := len(c.stack) - 1
	switch {
	case isIdentStart(b) && (i == 0 || !isIdentPart(s[i-1])):
		j := i
		for j < len(s) && isIdentPart(s[j]) {
			j++
		}
		if j < len(s) && !isWordBoundary(s[j]) {
			return false // `case-x`, `in.txt`: part of a longer word
		}
		switch s[i:j] {
		case "case":
			if atCommandStart(s, i) {
				c.stack = append(c.stack, caseState{})
			}
		case "in":
			if top >= 0 && !c.stack[top].sawIn {
				c.stack[top] = caseState{sawIn: true, inPattern: true}
			}
		case "esac":
			if top >= 0 && c.stack[top].sawIn {
				c.stack = c.stack[:top]
			}
		}
	case b == ';' && i+1 < len(s) && s[i+1] == ';':
		if top >= 0 && c.stack[top].sawIn {
			c.stack[top].inPattern = true
		}
	case b == ')' && top >= 0 && c.stack[top].inPattern:
		c.stack[top].inPattern = false
		return true
	case b == '(' && top >= 0 && c.stack[top].inPattern:
		return true
	}
	return false
}

func isWordBoundary(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n', ';', '&', '|', '(', ')', '<', '>':
		return true
	}
	return false
}

// atCommandStart reports whether the word at s[i] starts a command: it is
// first on the line, follows a separator or opening bracket, or follows a
// keyword such as then/do/else that introduces one.
func atCommandStart(s string, i int) bool {
	j := i - 1
	for j >= 0 && (s[j] == ' ' || s[j] == '\t') {
		j--
	}
	if j < 0 {
		return true
	}
	switch s[j] {
	case ';', '&', '|', '(', ')', '{', '\n', '\r', '`', '!':
		return true
	}
	k := j
	for k >= 0 && isIdentPart(s[k]) {
		k--
	}
	switch s[k+1 : j+1] {
	case "then", "do", "else", "elif":
		return true
	}
	return false
}

// atWordStart reports whether s[i] begins a word: first on the line or after
// blank space or a separator. A `#` there starts a comment; `a#b`, `$#` and
// `${#x}` do not.
func atWordStart(s string, i int) bool {
	if i == 0 {
		return true
	}
	switch s[i-1] {
	case ' ', '\t', '\n', '\r', ';', '&', '|', '(', ')':
		return true
	}
	return false
}
