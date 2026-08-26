package shell

import (
	"strings"
	"testing"
)

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

func TestCdTildeExpansion(t *testing.T) {
	s := NewInterpreter()
	if _, code, _ := s.Run("cd /etc"); code != 0 {
		t.Fatalf("cd /etc failed")
	}
	if _, code, _ := s.Run("cd ~"); code != 0 || s.Cwd != homeDir {
		t.Fatalf("cd ~ should return to %s, got cwd=%s code=%d", homeDir, s.Cwd, code)
	}
	if _, code, _ := s.Run("cd ~/.ssh"); code != 0 || s.Cwd != homeDir+"/.ssh" {
		t.Fatalf("cd ~/.ssh should resolve under home, got cwd=%s code=%d", s.Cwd, code)
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

func TestPipeGrep(t *testing.T) {
	s := NewInterpreter()
	out, code, _ := s.Run("cat /etc/passwd | grep root")
	if code != 0 || !strings.Contains(out, "root:x:0:0:root") {
		t.Fatalf("expected passwd's root line, got out=%q code=%d", out, code)
	}

	out, code, _ = s.Run("cat /etc/passwd | grep -v root | grep -c .")
	if code != 0 || out != "3" {
		t.Fatalf("expected 3 non-root lines, got out=%q code=%d", out, code)
	}
}

func TestPipeHeadTailWc(t *testing.T) {
	s := NewInterpreter()
	out, code, _ := s.Run("cat /etc/passwd | head -n 1")
	if code != 0 || out != "root:x:0:0:root:/root:/bin/bash" {
		t.Fatalf("head -n 1 mismatch: out=%q code=%d", out, code)
	}
	out, code, _ = s.Run("wc -l /etc/passwd")
	if code != 0 || !strings.HasPrefix(out, "4 ") {
		t.Fatalf("expected 4 lines counted, got out=%q code=%d", out, code)
	}
}

func TestPipeUnknownCommandDoesNotForwardStdout(t *testing.T) {
	s := NewInterpreter()
	// nonexistentcmd's "command not found" text is this shell's stand-in
	// for stderr and must not leak into the next stage's stdin.
	out, code, _ := s.Run("nonexistentcmd | wc -l")
	if code != 0 || out != "0" {
		t.Fatalf("expected wc to see empty stdin (0 lines), got out=%q code=%d", out, code)
	}
}

func TestRedirectWriteAndReadBack(t *testing.T) {
	s := NewInterpreter()
	if _, code, _ := s.Run("echo hello world > /tmp/note.txt"); code != 0 {
		t.Fatalf("redirect write failed")
	}
	out, code, _ := s.Run("cat /tmp/note.txt")
	// echo's stdout implicitly ends with a newline, same as real bash --
	// the write stores it, so reading it back shows it too.
	if code != 0 || out != "hello world\r\n" {
		t.Fatalf("expected 'hello world\\r\\n' read back, got out=%q code=%d", out, code)
	}
	if _, code, _ := s.Run("ls /tmp"); code != 0 {
		t.Fatalf("ls /tmp failed after write")
	}
	if !strings.Contains(mustLs(t, s, "/tmp"), "note.txt") {
		t.Fatalf("expected note.txt to appear in ls /tmp")
	}
}

func TestRedirectAppendKeepsLinesSeparate(t *testing.T) {
	s := NewInterpreter()
	s.Run("echo first > /tmp/log.txt")
	s.Run("echo second >> /tmp/log.txt")
	out, _, _ := s.Run("cat /tmp/log.txt")
	if out != "first\r\nsecond\r\n" {
		t.Fatalf("expected two separate lines, got %q", out)
	}
}

func TestRedirectWriteIsolatedPerSession(t *testing.T) {
	s1 := NewInterpreter()
	s1.Run("echo secret > /tmp/isolated.txt")

	s2 := NewInterpreter()
	_, code, _ := s2.Run("cat /tmp/isolated.txt")
	if code == 0 {
		t.Fatalf("expected a fresh session not to see another session's write")
	}
}

func TestPipeCharInsideQuotesIsNotAPipe(t *testing.T) {
	s := NewInterpreter()
	out, code, _ := s.Run(`echo "a|b"`)
	if code != 0 || out != "a|b" {
		t.Fatalf("expected literal 'a|b', got out=%q code=%d", out, code)
	}
}

func TestRedirectToMissingDirFails(t *testing.T) {
	s := NewInterpreter()
	_, code, _ := s.Run("echo hi > /no/such/dir/file.txt")
	if code == 0 {
		t.Fatalf("expected redirect into a nonexistent directory to fail")
	}
}

func mustLs(t *testing.T, s *Interpreter, dir string) string {
	t.Helper()
	out, code, _ := s.Run("ls " + dir)
	if code != 0 {
		t.Fatalf("ls %s failed: %s", dir, out)
	}
	return out
}

func TestRunWithDeceptionEmptyActionMatchesRun(t *testing.T) {
	cases := []string{"ls", "cat .env", "cat /etc/os-release", "uname -a", "cd /etc && ls"}
	for _, c := range cases {
		a := NewInterpreter()
		b := NewInterpreter()
		b.Hostname = a.Hostname // isolate this comparison from per-session hostname randomization
		outA, codeA, baitA := a.Run(c)
		outB, codeB, baitB := b.RunWithDeception(c, "")
		if outA != outB || codeA != codeB || len(baitA) != len(baitB) {
			t.Fatalf("Run and RunWithDeception(%q, \"\") diverged: (%q,%d,%d) vs (%q,%d,%d)",
				c, outA, codeA, len(baitA), outB, codeB, len(baitB))
		}
	}
}

func TestEnrichRevealsPythonHistory(t *testing.T) {
	s := NewInterpreter()
	out, code, _ := s.RunWithDeception("ls", "ENRICH")
	if code != 0 {
		t.Fatalf("ls failed: %s", out)
	}
	if !strings.Contains(out, ".python_history") {
		t.Fatalf("expected ENRICH to reveal .python_history, got: %s", out)
	}

	s2 := NewInterpreter()
	out2, _, _ := s2.Run("ls")
	if strings.Contains(out2, ".python_history") {
		t.Fatalf("expected .python_history hidden without ENRICH, got: %s", out2)
	}

	s3 := NewInterpreter()
	out3, code3, _ := s3.Run("cat .python_history")
	if code3 != 0 || out3 == "" {
		t.Fatalf(".python_history should be readable regardless of action: out=%q code=%d", out3, code3)
	}
}

func TestEnrichAddsUbuntuCodename(t *testing.T) {
	s := NewInterpreter()
	out, code, _ := s.RunWithDeception("cat /etc/os-release", "ENRICH")
	if code != 0 || !strings.Contains(out, "UBUNTU_CODENAME=jammy") {
		t.Fatalf("expected ENRICH to add UBUNTU_CODENAME, got: %q", out)
	}

	s2 := NewInterpreter()
	out2, _, _ := s2.Run("cat /etc/os-release")
	if strings.Contains(out2, "UBUNTU_CODENAME") {
		t.Fatalf("expected no UBUNTU_CODENAME without ENRICH, got: %q", out2)
	}
}

func TestSurfaceBaitRevealsAwsCredentials(t *testing.T) {
	s := NewInterpreter()
	out, _, _ := s.RunWithDeception("ls", "SURFACE_BAIT")
	if !strings.Contains(out, ".aws") {
		t.Fatalf("expected SURFACE_BAIT to reveal .aws, got: %s", out)
	}

	s2 := NewInterpreter()
	out2, _, _ := s2.Run("ls")
	if strings.Contains(out2, ".aws") {
		t.Fatalf("expected .aws hidden without SURFACE_BAIT, got: %s", out2)
	}
}

func TestAwsCredentialsCatGatedBySurfaceBait(t *testing.T) {
	s := NewInterpreter()
	out, code, bait := s.Run("cat .aws/credentials")
	if code == 0 {
		t.Fatalf("expected cat .aws/credentials to fail without SURFACE_BAIT, got out=%q code=%d", out, code)
	}
	if out != "cat: .aws/credentials: No such file or directory" {
		t.Fatalf("unexpected output: %q", out)
	}
	if len(bait) != 0 {
		t.Fatalf("expected no bait hit without SURFACE_BAIT, got %v", bait)
	}

	s2 := NewInterpreter()
	out2, code2, bait2 := s2.RunWithDeception("cat .aws/credentials", "SURFACE_BAIT")
	if code2 != 0 {
		t.Fatalf("cat .aws/credentials with SURFACE_BAIT failed: %s", out2)
	}
	if len(bait2) != 1 || bait2[0].BaitID != "home-aws-credentials" {
		t.Fatalf("expected home-aws-credentials bait hit, got %v", bait2)
	}
}

func TestExistingBaitNodesAlwaysVisibleRegardlessOfAction(t *testing.T) {
	for _, action := range []string{"", "ENRICH", "SURFACE_BAIT", "MINIMAL"} {
		s := NewInterpreter()
		out, code, bait := s.RunWithDeception("cat .env", action)
		if code != 0 || len(bait) != 1 || bait[0].BaitID != "home-env-file" {
			t.Fatalf("action=%q: expected .env bait hit unconditionally, got out=%q code=%d bait=%v", action, out, code, bait)
		}

		s2 := NewInterpreter()
		out2, code2, bait2 := s2.RunWithDeception("cat .ssh/id_rsa", action)
		if code2 != 0 || len(bait2) != 1 || bait2[0].BaitID != "home-ssh-private-key" {
			t.Fatalf("action=%q: expected id_rsa bait hit unconditionally, got out=%q code=%d bait=%v", action, out2, code2, bait2)
		}
	}
}
