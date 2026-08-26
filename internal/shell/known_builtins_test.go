package shell

import "testing"

// wantBuiltins is an independent transcription of execBuiltin's switch cases
// (shell.go). It is deliberately hand-maintained rather than derived from
// knownBuiltins, so that adding a case to the switch without adding it here
// (or vice versa) fails loudly instead of silently desynchronising the
// "is this command handled?" answer that the LLM-completion fallback keys
// off -- a builtin missing from knownBuiltins would get its deterministic
// output silently replaced by an LLM's invention.
var wantBuiltins = []string{
	"", "echo", "whoami", "pwd", "hostname", "id", "uname", "export",
	"test", "[", "cat", "ls", "cd", "grep", "head", "tail", "wc",
	"which", "find", "ps", "netstat", "crontab", "exit",
}

func TestIsKnownBuiltinCoversEveryExecBuiltinCase(t *testing.T) {
	for _, name := range wantBuiltins {
		if !IsKnownBuiltin(name) {
			t.Errorf("IsKnownBuiltin(%q) = false, want true -- execBuiltin handles it", name)
		}
	}
}

func TestKnownBuiltinsHasNoExtras(t *testing.T) {
	want := map[string]struct{}{}
	for _, name := range wantBuiltins {
		want[name] = struct{}{}
	}
	for name := range knownBuiltins {
		if _, ok := want[name]; !ok {
			t.Errorf("knownBuiltins contains %q, which execBuiltin's switch does not handle", name)
		}
	}
}

func TestIsKnownBuiltinRejectsUnhandledCommands(t *testing.T) {
	// Commands the preprint observed in real sessions that this shell does
	// NOT implement -- these are exactly the ones the completion fallback
	// exists to serve.
	for _, name := range []string{"uptime", "nproc", "lspci", "nvidia-smi", "free", "df", "lscpu", "last"} {
		if IsKnownBuiltin(name) {
			t.Errorf("IsKnownBuiltin(%q) = true, want false -- execBuiltin has no case for it", name)
		}
	}
}
