package shell

import "testing"

func TestLsCdConsistency(t *testing.T) {
	s := NewInterpreter()
	out, code, _ := s.Run("ls /")
	if code != 0 {
		t.Fatalf("ls / failed: code=%d out=%s", code, out)
	}
	// Every top-level dir ls claims exists must actually be cd-able.
	for _, dir := range []string{"bin", "boot", "dev", "etc", "home", "lib", "lib64", "opt", "proc", "root", "run", "sbin", "srv", "tmp", "usr", "var"} {
		s := NewInterpreter()
		_, code, _ := s.Run("cd /" + dir)
		if code != 0 {
			t.Errorf("cd /%s failed even though ls / lists it", dir)
		}
	}
}

func TestBaitFires(t *testing.T) {
	s := NewInterpreter()
	out, code, bait := s.Run("cat .env")
	if code != 0 {
		t.Fatalf("cat .env failed: %s", out)
	}
	if len(bait) != 1 || bait[0].BaitID != "home-env-file" {
		t.Fatalf("expected .env bait hit, got %v", bait)
	}
}

func TestUnameNoLongerCommandNotFound(t *testing.T) {
	s := NewInterpreter()
	out, code, _ := s.Run("uname -s -v -n -r -m")
	if code != 0 {
		t.Fatalf("uname failed: %s", out)
	}
	if out == "" {
		t.Fatal("expected uname output, got empty string")
	}
}

func TestChainedStatements(t *testing.T) {
	s := NewInterpreter()
	out, code, _ := s.Run(`export FOO=bar; echo ok`)
	if code != 0 || out != "ok" {
		t.Fatalf("expected 'ok' with code 0, got out=%q code=%d", out, code)
	}
}

func TestShortCircuit(t *testing.T) {
	s := NewInterpreter()
	out, _, _ := s.Run(`[ -f /proc/version ] && echo has_it`)
	if out != "has_it" {
		t.Fatalf("expected has_it, got %q", out)
	}
	out, _, _ = s.Run(`[ -f /nope ] && echo should_not_print`)
	if out != "" {
		t.Fatalf("expected empty output on short-circuited &&, got %q", out)
	}
}

func TestCommandSubstitution(t *testing.T) {
	s := NewInterpreter()
	out, _, _ := s.Run(`echo "UNAME:$(uname -s)"`)
	if out != "UNAME:Linux" {
		t.Fatalf("expected UNAME:Linux, got %q", out)
	}
}

func TestUnknownCommandStillReported(t *testing.T) {
	s := NewInterpreter()
	out, code, _ := s.Run("nonexistentcmd foo")
	if code != 127 {
		t.Fatalf("expected exit 127, got %d", code)
	}
	if out != "bash: nonexistentcmd: command not found" {
		t.Fatalf("unexpected output: %q", out)
	}
}
