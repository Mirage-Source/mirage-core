package shell

import "testing"

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
