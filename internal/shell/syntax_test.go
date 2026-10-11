package shell

import (
	"strings"
	"testing"
)

func TestCompoundCommands(t *testing.T) {
	cases := []struct {
		line, want string
		code       int
	}{
		{"if [ -d /tmp ]; then echo yes; fi", "yes", 0},
		{"if [ -d /nope ]; then echo yes; fi", "", 0},
		{"if [ -d /nope ]; then echo a; elif [ -d /tmp ]; then echo b; else echo c; fi", "b", 0},
		{"if [ -d /nope ]; then echo a; else echo c; fi", "c", 0},
		{"if [ -d /tmp ]\nthen\n  echo multi\nfi", "multi", 0},
		{"if [ -d /tmp ]; then if [ -d /nope ]; then echo x; else echo inner; fi; fi", "inner", 0},
		{"if [ -d /nope ]; then echo a; fi && echo after", "after", 0},
		{"{ echo a; echo b; }", "a\r\nb", 0},
		{"[ -d /nope ] || { echo fallback; uname -s; }", "fallback\r\nLinux", 0},
		{"[ -d /tmp ] || { echo skipped; }", "", 0},
		{"case $(uname -m) in x86_64) echo amd;; arm*|aarch64) echo arm;; esac", "amd", 0},
		{"case abc in a*) echo first;; *) echo second;; esac", "first", 0},
		{"case zzz in a) echo a;; *) echo default;; esac", "default", 0},
		{"case zzz in a) echo a;; esac", "", 0},
		{"case \"x y\" in \"x y\") echo quoted;; esac", "quoted", 0},
		{"case x in\n  (x) echo paren\n  ;;\nesac", "paren", 0},
		{"case x in x) ;; esac; echo next", "next", 0},
		{"echo }", "}", 0},
	}
	for _, tc := range cases {
		s := NewInterpreter("root")
		if out, code := run(t, s, tc.line); out != tc.want || code != tc.code {
			t.Errorf("%q = %q %d, want %q %d", tc.line, out, code, tc.want, tc.code)
		}
	}
}

func TestSyntaxErrorsRunNothing(t *testing.T) {
	cases := []struct{ line, want string }{
		{"echo a; fi", "bash: syntax error near unexpected token `fi'"},
		{"echo a; }", "bash: syntax error near unexpected token `}'"},
		{"if true; then echo a", "bash: syntax error: unexpected end of file"},
		{"{ echo a", "bash: syntax error: unexpected end of file"},
		{"case x in x) echo a;;", "bash: syntax error: unexpected end of file"},
		{"echo a;; echo b", "bash: syntax error near unexpected token `;;'"},
		{"if then echo a; fi", "bash: syntax error near unexpected token `then'"},
	}
	for _, tc := range cases {
		s := NewInterpreter("root")
		if out, code := run(t, s, tc.line); out != tc.want || code != 2 {
			t.Errorf("%q = %q %d, want %q 2", tc.line, out, code, tc.want)
		}
	}
}

func TestForLoops(t *testing.T) {
	cases := []struct {
		line, want string
		code       int
	}{
		{"for i in a b c; do echo $i; done", "a\r\nb\r\nc", 0},
		{"for i in a b\ndo\n  echo x$i\ndone", "xa\r\nxb", 0},
		{"for a in x86 arm; do wget -q http://198.51.100.7/$a; echo $a; done", "x86\r\narm", 0},
		{"for w in $(echo one two); do echo $w; done", "one\r\ntwo", 0},
		{`for w in "one two"; do echo $w; done`, "one two", 0},
		{"for i in; do echo never; done; echo after", "after", 0},
		{"for i in a b; do if [ $i = b ]; then echo found; fi; done", "found", 0},
		{"for i in 1 2; do for j in x y; do echo $i$j; done; done", "1x\r\n1y\r\n2x\r\n2y", 0},
		{"for i in a b; do echo $i; done && echo ok", "a\r\nb\r\nok", 0},
	}
	for _, tc := range cases {
		s := NewInterpreter("root")
		if out, code := run(t, s, tc.line); out != tc.want || code != tc.code {
			t.Errorf("%q = %q %d, want %q %d", tc.line, out, code, tc.want, tc.code)
		}
	}
	for _, line := range []string{"for i in a b; do echo $i", "for i in a; echo x; done", "echo a; done"} {
		s := NewInterpreter("root")
		if _, code := run(t, s, line); code != 2 {
			t.Errorf("%q code = %d, want syntax error 2", line, code)
		}
	}
}

func TestForLoopIterationsAreCapped(t *testing.T) {
	s := NewInterpreter("root")
	words := strings.Repeat("x ", 5000)
	out, _ := run(t, s, "for i in "+words+"; do echo $i; done")
	if n := strings.Count(out, "x"); n != maxLoopIterations {
		t.Fatalf("ran %d iterations, want cap %d", n, maxLoopIterations)
	}
}

func TestTestBuiltinComparisons(t *testing.T) {
	s := NewInterpreter("root")
	cases := map[string]int{
		"[ a = a ]": 0, "[ a = b ]": 1, "[ a == a ]": 0, "[ a != b ]": 0,
		"[ 3 -gt 2 ]": 0, "[ 2 -ge 3 ]": 1, "[ 1 -eq 1 ]": 0, "[ 1 -ne 1 ]": 1, "[ 1 -lt 2 ]": 0, "[ 2 -le 2 ]": 0,
		"[ x -eq 1 ]": 2, "[ -z '' ]": 0, "[ -n '' ]": 1, "[ -n x ]": 0, "[ ! -d /nope ]": 0, "[ ! a = a ]": 1,
		"[ x ]": 0, "[ ]": 1, "test -f /etc/hostname": 0, "[ \"$(id -u)\" = 0 ]": 0,
	}
	for line, want := range cases {
		if _, code := run(t, s, line); code != want {
			t.Errorf("%s -> %d, want %d", line, code, want)
		}
	}
}

func TestIdFlags(t *testing.T) {
	for user, want := range map[string][]string{"root": {"0", "root", "0", "0"}, "admin": {"1000", "ubuntu", "1000", "1000 27"}} {
		s := NewInterpreter(user)
		for i, line := range []string{"id -u", "id -un", "id -g", "id -G"} {
			if out, _ := run(t, s, line); out != want[i] {
				t.Errorf("%s: %s = %q, want %q", user, line, out, want[i])
			}
		}
	}
}
