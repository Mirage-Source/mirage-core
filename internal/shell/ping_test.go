package shell

import (
	"strings"
	"testing"
)

func TestPingFailsLikeAHostWithNoEgress(t *testing.T) {
	cases := []struct {
		line, want string
		code       int
	}{
		{"ping -c 2 198.51.100.7", "PING 198.51.100.7 (198.51.100.7) 56(84) bytes of data.\r\n\r\n--- 198.51.100.7 ping statistics ---\r\n2 packets transmitted, 0 received, 100% packet loss, time 1023ms", 1},
		{"ping -c1 -W1 198.51.100.7", "PING 198.51.100.7 (198.51.100.7) 56(84) bytes of data.\r\n\r\n--- 198.51.100.7 ping statistics ---\r\n1 packets transmitted, 0 received, 100% packet loss, time 0ms", 1},
		{"ping -c 3 evil.example", "ping: evil.example: Temporary failure in name resolution", 2},
		{"ping", "ping: usage error: Destination address required", 2},
		{"ping -q -c 1 198.51.100.7 > /dev/null", "", 1},
	}
	for _, tc := range cases {
		s := NewInterpreter("root")
		if out, code := run(t, s, tc.line); out != tc.want || code != tc.code {
			t.Errorf("%q = %q %d, want %q %d", tc.line, out, code, tc.want, tc.code)
		}
	}
	s := NewInterpreter("root")
	if out, _ := run(t, s, "ping 198.51.100.7"); !strings.Contains(out, "4 packets transmitted, 0 received") {
		t.Errorf("default count = %q", out)
	}
}
