package shell

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// printfBuiltin is bash's printf: the format is reused until the arguments
// run out, %b expands escapes in its argument, and a bad number prints 0
// with an error on stderr and exit 1. Measured against bash 5.1.16.
func (s *Interpreter) printfBuiltin(args []string) (string, int) {
	if len(args) == 0 {
		return "printf: usage: printf [-v var] format [arguments]", 2
	}
	format, args := args[0], args[1:]
	var out strings.Builder
	code := 0
	for first := true; first || len(args) > 0; first = false {
		consumed := false
		for i := 0; i < len(format); i++ {
			c := format[i]
			if c == '\\' {
				n := printfEscape(format[i+1:], &out, true)
				i += n
				continue
			}
			if c != '%' {
				out.WriteByte(c)
				continue
			}
			if i+1 < len(format) && format[i+1] == '%' {
				out.WriteByte('%')
				i++
				continue
			}
			j := i + 1
			for j < len(format) && strings.IndexByte("-+ #0123456789.", format[j]) >= 0 {
				j++
			}
			if j >= len(format) {
				out.WriteString(format[i:])
				break
			}
			flags, verb := format[i+1:j], format[j]
			i = j
			arg := ""
			if len(args) > 0 {
				arg, args = args[0], args[1:]
				consumed = true
			}
			switch verb {
			case 's':
				fmt.Fprintf(&out, "%"+flags+"s", arg)
			case 'b':
				var b strings.Builder
				for k := 0; k < len(arg); k++ {
					if arg[k] == '\\' {
						k += printfEscape(arg[k+1:], &b, false)
						continue
					}
					b.WriteByte(arg[k])
				}
				fmt.Fprintf(&out, "%"+flags+"s", b.String())
			case 'c':
				if arg != "" {
					fmt.Fprintf(&out, "%"+flags+"s", arg[:1])
				}
			case 'd', 'i', 'u', 'x', 'X', 'o':
				n, ok := printfNumber(arg)
				if !ok {
					s.pendingErr = append(s.pendingErr, "bash: printf: "+arg+": invalid number")
					code = 1
				}
				v := map[byte]string{'d': "d", 'i': "d", 'u': "d", 'x': "x", 'X': "X", 'o': "o"}[verb]
				fmt.Fprintf(&out, "%"+flags+v, n)
			default:
				out.WriteString(format[i-len(flags)-1 : i+1])
			}
		}
		if !consumed {
			break
		}
	}
	text := out.String()
	if strings.HasSuffix(text, "\n") {
		// Terminal display adds the final newline back.
		text = strings.TrimSuffix(text, "\n")
	} else {
		s.noTrailingNewline = true
	}
	return strings.ReplaceAll(text, "\n", "\r\n"), code
}

// printfNumber parses a printf numeric argument; 'c is the code of c.
func printfNumber(arg string) (int64, bool) {
	if arg == "" {
		return 0, true
	}
	if arg[0] == '\'' || arg[0] == '"' {
		if len(arg) > 1 {
			return int64(arg[1]), true
		}
		return 0, true
	}
	n, err := strconv.ParseInt(arg, 0, 64)
	return n, err == nil
}

// printfEscape writes the escape at the start of rest (the text after a
// backslash) and returns how many bytes of rest it used. In a format,
// octal is \NNN; in a %b argument it is \0NNN.
func printfEscape(rest string, out *strings.Builder, inFormat bool) int {
	if rest == "" {
		out.WriteByte('\\')
		return 0
	}
	simple := map[byte]byte{'n': '\n', 't': '\t', 'r': '\r', 'a': 7, 'b': 8, 'f': 12, 'v': 11, 'e': 27, '\\': '\\', '"': '"', '\'': '\''}
	if b, ok := simple[rest[0]]; ok {
		out.WriteByte(b)
		return 1
	}
	digits := func(s string, max int, base int, valid string) (int, int) {
		n, v := 0, 0
		for n < len(s) && n < max && strings.IndexByte(valid, s[n]) >= 0 {
			d, _ := strconv.ParseInt(s[n:n+1], base, 8)
			v = v*base + int(d)
			n++
		}
		return n, v
	}
	switch c := rest[0]; {
	case c == 'x':
		n, v := digits(rest[1:], 2, 16, "0123456789abcdefABCDEF")
		if n == 0 {
			out.WriteString("\\x")
			return 1
		}
		out.WriteByte(byte(v))
		return 1 + n
	case c >= '0' && c <= '7':
		start, max := 0, 3
		if !inFormat {
			if c != '0' {
				out.WriteByte('\\')
				return 0
			}
			start = 1
		}
		n, v := digits(rest[start:], max, 8, "01234567")
		out.WriteByte(byte(v))
		return start + n
	}
	out.WriteByte('\\')
	return 0
}

// loginEnvOrder is the order sshd + pam leave the login environment in
// (measured on 8.9p1); env prints these first, then other exported names.
var loginEnvOrder = []string{"SHELL", "PWD", "LOGNAME", "MOTD_SHOWN", "HOME", "LANG", "SSH_CONNECTION", "USER", "SHLVL", "SSH_CLIENT", "PATH", "OLDPWD"}

// exportedEnv lists exported variables as env prints them. bash lowers
// SHLVL before exec'ing a command in place (the -c string's last command,
// or a pipeline stage), so only those see SHLVL one lower.
func (s *Interpreter) exportedEnv(prog string) []string {
	var lines []string
	seen := map[string]bool{}
	add := func(k string) {
		v, ok := s.Env[k]
		if !ok || seen[k] || !s.isExported(k) {
			return
		}
		seen[k] = true
		if k == "SHLVL" && s.exec && s.direct {
			if n, err := strconv.Atoi(v); err == nil {
				v = strconv.Itoa(n - 1)
			}
		}
		lines = append(lines, k+"="+v)
	}
	for _, k := range loginEnvOrder {
		add(k)
	}
	var rest []string
	for k := range s.Env {
		rest = append(rest, k)
	}
	sort.Strings(rest)
	for _, k := range rest {
		add(k)
	}
	return append(lines, "_="+prog)
}

func (s *Interpreter) isExported(k string) bool {
	if s.exported[k] {
		return true
	}
	if s.profile.loginEnv == nil {
		return false
	}
	_, login := s.profile.loginEnv("", "")[k]
	return login || k == "SSH_CLIENT" || k == "SSH_CONNECTION" || k == "OLDPWD"
}

func (s *Interpreter) envBuiltin(args []string, bait *[]BaitHit, action string, stdin *string) (string, int) {
	for len(args) > 0 {
		k, v, ok := strings.Cut(args[0], "=")
		if !ok || k == "" {
			break
		}
		s.Env[k] = v
		s.markExported(k)
		args = args[1:]
	}
	if len(args) > 0 {
		return s.execBuiltin(args[0], args[1:], bait, action, stdin)
	}
	return strings.Join(s.exportedEnv("/usr/bin/env"), "\r\n"), 0
}

func (s *Interpreter) printenvBuiltin(args []string) (string, int) {
	if len(args) == 0 {
		return strings.Join(s.exportedEnv("/usr/bin/printenv"), "\r\n"), 0
	}
	env := s.exportedEnv("/usr/bin/printenv")
	var vals []string
	code := 0
	for _, k := range args {
		found := false
		for _, kv := range env {
			if v, ok := strings.CutPrefix(kv, k+"="); ok {
				vals = append(vals, v)
				found = true
				break
			}
		}
		if !found {
			code = 1
		}
	}
	return strings.Join(vals, "\r\n"), code
}

func (s *Interpreter) markExported(k string) {
	if s.exported == nil {
		s.exported = map[string]bool{}
	}
	s.exported[k] = true
}
