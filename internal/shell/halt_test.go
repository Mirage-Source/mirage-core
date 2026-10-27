package shell

import (
	"strings"
	"testing"
)

// In a login shell `exit` closes the session (the server watches for ExitRequested); only an exec
// request (`bash -c`) stops the script and carries the status. And a command failing under `set -e`
// must end the line being run, not freeze every line typed afterwards.

func TestExitInALoginShellStillClosesTheSession(t *testing.T) {
	_, code, _ := NewMachine(Ubuntu).NewInterpreter("root").Run("exit")
	if code != ExitRequested {
		t.Errorf("code = %d, want ExitRequested (%d)", code, ExitRequested)
	}
}

func TestAFailureUnderSetEDoesNotFreezeALoginShell(t *testing.T) {
	it := NewMachine(Ubuntu).NewInterpreter("root")
	it.Run("set -e")
	if out, _, _ := it.Run("false; echo skipped"); strings.Contains(out, "skipped") {
		t.Errorf("the line should have stopped at the failure, got %q", out)
	}
	if out, _, _ := it.Run("echo later"); !strings.Contains(out, "later") {
		t.Errorf("a later line must still run, got %q", out)
	}
}

func TestExitStatusIsMaskedToOneByte(t *testing.T) {
	for _, tc := range []struct {
		cmd  string
		want int
	}{{"exit 256", 0}, {"exit 257", 1}, {"exit -1", 255}, {"exit 3", 3}} {
		_, _, code, _ := NewMachine(Ubuntu).NewInterpreter("root").RunExec(tc.cmd)
		if code != tc.want {
			t.Errorf("%q: status %d, want %d", tc.cmd, code, tc.want)
		}
	}
}

func TestEachExecStartsWithoutSetEFromTheLast(t *testing.T) {
	m := NewMachine(Ubuntu)
	m.NewInterpreter("root").RunExec("set -e")
	out, _, _, _ := m.NewInterpreter("root").RunExec("false; echo ran")
	if out != "ran\n" {
		t.Errorf("a new exec must not inherit set -e, got %q", out)
	}
}
