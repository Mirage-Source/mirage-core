package shell

import "testing"

func TestEchoFlags(t *testing.T) {
	cases := []struct{ line, want string }{
		{`echo -e "a\tb"`, "a\tb"},
		{`echo -e 'one\ntwo'`, "one\r\ntwo"},
		{`echo -e 'a\\b'`, `a\b`},
		{`echo -e 'stop\cignored'`, "stop"},
		{`echo -e '\x41\x42\0103'`, "ABC"},
		{`echo -E 'a\tb'`, `a\tb`},
		{`echo 'a\tb'`, `a\tb`},
		{`echo -n hi`, "hi"},
		{`echo -ne 'x\ty'`, "x\ty"},
		{`echo -en 'x\ty'`, "x\ty"},
		{`echo -e -n 'x'`, "x"},
		{`echo -x hi`, "-x hi"},
		{`echo -- hi`, "-- hi"},
		{`echo -e`, ""},
		{`echo hi -e`, "hi -e"},
	}
	for _, tc := range cases {
		s := NewInterpreter("root")
		if out, code := run(t, s, tc.line); out != tc.want || code != 0 {
			t.Errorf("%s = %q %d, want %q", tc.line, out, code, tc.want)
		}
	}
}

func TestEchoEWritesBinaryToFile(t *testing.T) {
	s := NewInterpreter("root")
	run(t, s, `echo -ne '\x7f\x45\x4c\x46\x01' > /tmp/.x`)
	_, n := s.lookup("/tmp/.x")
	if n == nil || n.Content != "\x7fELF\x01" {
		t.Fatalf("file content = %q", n.Content)
	}
}
