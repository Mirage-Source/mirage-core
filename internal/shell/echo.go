package shell

import (
	"strconv"
	"strings"
)

// echoBuiltin follows bash: leading words made only of n, e and E are
// options; anything else, including "--", is printed.
func echoBuiltin(args []string) (out string, noNewline bool) {
	interpret := false
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' || strings.Trim(a[1:], "neE") != "" {
			break
		}
		for _, c := range a[1:] {
			switch c {
			case 'n':
				noNewline = true
			case 'e':
				interpret = true
			case 'E':
				interpret = false
			}
		}
	}
	text := strings.Join(args[i:], " ")
	if interpret {
		text = expandEchoEscapes(text)
	}
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", "\r\n")
	return text, noNewline
}

var simpleEscapes = map[byte]byte{
	'a': '\a', 'b': '\b', 'e': 0x1b, 'E': 0x1b, 'f': '\f', 'n': '\n',
	'r': '\r', 't': '\t', 'v': '\v', '\\': '\\',
}

func expandEchoEscapes(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		c := s[i+1]
		if r, ok := simpleEscapes[c]; ok {
			b.WriteByte(r)
			i++
			continue
		}
		switch c {
		case 'c':
			return b.String()
		case '0':
			j := i + 2
			for j < len(s) && j < i+5 && s[j] >= '0' && s[j] <= '7' {
				j++
			}
			n, _ := strconv.ParseUint("0"+s[i+2:j], 8, 16)
			b.WriteByte(byte(n))
			i = j - 1
		case 'x':
			j := i + 2
			for j < len(s) && j < i+4 && strings.IndexByte("0123456789abcdefABCDEF", s[j]) >= 0 {
				j++
			}
			if j == i+2 {
				b.WriteString(`\x`)
				i++
				continue
			}
			n, _ := strconv.ParseUint(s[i+2:j], 16, 8)
			b.WriteByte(byte(n))
			i = j - 1
		default:
			b.WriteByte('\\')
		}
	}
	return b.String()
}
