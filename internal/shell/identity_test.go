package shell

import (
	"strings"
	"testing"
)

func TestRootLoginGetsRootIdentity(t *testing.T) {
	s := NewInterpreter("root")

	if s.HomeDir != "/root" || s.Cwd != "/root" {
		t.Fatalf("root login should start in /root, got HomeDir=%s Cwd=%s", s.HomeDir, s.Cwd)
	}

	prompt := s.Prompt()
	if !strings.HasSuffix(prompt, "# ") {
		t.Errorf("root prompt = %q, want it to end in \"# \"", prompt)
	}

	out, code, _ := s.Run("whoami")
	if code != 0 || out != "root" {
		t.Errorf("whoami = %q (code %d), want \"root\"", out, code)
	}

	out, code, _ = s.Run("id")
	if code != 0 || out != "uid=0(root) gid=0(root) groups=0(root)" {
		t.Errorf("id = %q (code %d), want the root identity", out, code)
	}

	if _, code, _ := s.Run("cd ~"); code != 0 || s.Cwd != "/root" {
		t.Errorf("cd ~ for root should land in /root, got cwd=%s code=%d", s.Cwd, code)
	}
}

func TestNonRootWeakCredentialUsernamesGetUbuntuIdentity(t *testing.T) {
	// config/weak_credentials.txt accepts several usernames besides root and
	// ubuntu (admin, mysql, postgres, ...) -- none of those are meant to get
	// their own identity, since a real box wouldn't hand an interactive
	// shell to a service account. They all still collapse onto the one
	// ordinary "ubuntu" identity.
	for _, username := range []string{"ubuntu", "admin", "mysql", "postgres", "guest"} {
		s := NewInterpreter(username)
		if s.HomeDir != "/home/ubuntu" {
			t.Errorf("username=%q: HomeDir = %q, want /home/ubuntu", username, s.HomeDir)
		}
		out, code, _ := s.Run("whoami")
		if code != 0 || out != "ubuntu" {
			t.Errorf("username=%q: whoami = %q (code %d), want \"ubuntu\"", username, out, code)
		}
		prompt := s.Prompt()
		if !strings.HasSuffix(prompt, "$ ") {
			t.Errorf("username=%q: prompt = %q, want it to end in \"$ \"", username, prompt)
		}
	}
}

func TestWriteFileOwnershipMatchesLoginIdentity(t *testing.T) {
	s := NewInterpreter("root")
	if _, code, _ := s.Run("echo hi > /root/x.txt"); code != 0 {
		t.Fatalf("write failed")
	}
	out, code, _ := s.Run("ls -la /root")
	if code != 0 {
		t.Fatalf("ls -la /root failed: %s", out)
	}
	if !strings.Contains(out, "root   root") {
		t.Errorf("a file root wrote should be owned by root, got: %s", out)
	}
}
