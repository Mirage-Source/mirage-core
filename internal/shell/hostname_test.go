package shell

import (
	"regexp"
	"strings"
	"testing"
)

var hostnamePattern = regexp.MustCompile(`^ip-172-31-\d{1,3}-\d{1,3}$`)

// TestHostnameIsRandomizedAndSelfConsistent locks in the fingerprint fix: a
// single hardcoded "ip-172-31-14-52" everywhere was itself a tell (every
// session, from any attacker, looked identical). Every surface that exposes
// a hostname must agree with the interpreter's own Hostname for the whole
// session, and different sessions should typically get different values.
func TestHostnameIsRandomizedAndSelfConsistent(t *testing.T) {
	s := NewInterpreter()

	if !hostnamePattern.MatchString(s.Hostname) {
		t.Fatalf("Hostname %q does not match the expected ip-172-31-x-y shape", s.Hostname)
	}

	if !strings.Contains(s.Prompt(), s.Hostname) {
		t.Errorf("prompt %q does not contain this session's hostname %q", s.Prompt(), s.Hostname)
	}

	out, code, _ := s.Run("hostname")
	if code != 0 || out != s.Hostname {
		t.Errorf("`hostname` returned %q (code %d), want %q", out, code, s.Hostname)
	}

	out, code, _ = s.Run("uname -n")
	if code != 0 || out != s.Hostname {
		t.Errorf("`uname -n` returned %q (code %d), want %q", out, code, s.Hostname)
	}

	out, code, _ = s.Run("cat /etc/hostname")
	if code != 0 || strings.TrimSpace(out) != s.Hostname {
		t.Errorf("`cat /etc/hostname` returned %q (code %d), want %q", out, code, s.Hostname)
	}

	out, code, _ = s.Run("cat /etc/hosts")
	if code != 0 || !strings.Contains(out, s.Hostname) {
		t.Errorf("`cat /etc/hosts` = %q (code %d) does not contain hostname %q", out, code, s.Hostname)
	}

	out, code, _ = s.Run("cat ~/.ssh/id_rsa.pub")
	if code != 0 || !strings.Contains(out, "ubuntu@"+s.Hostname) {
		t.Errorf("`cat ~/.ssh/id_rsa.pub` = %q (code %d) does not contain ubuntu@%s", out, code, s.Hostname)
	}

	// The static fs.go placeholder must never leak verbatim to the attacker.
	for _, cmd := range []string{"hostname", "uname -a", "cat /etc/hosts", "cat /etc/hostname", "cat ~/.ssh/id_rsa.pub", "cat /var/log/auth.log"} {
		out, _, _ := s.Run(cmd)
		if strings.Contains(out, hostnamePlaceholder) {
			t.Errorf("output of %q leaked the raw placeholder %q: %q", cmd, hostnamePlaceholder, out)
		}
	}
}

func TestHostnameVariesAcrossSessions(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		seen[NewInterpreter().Hostname] = true
	}
	if len(seen) < 2 {
		t.Fatalf("20 fresh interpreters produced only %d distinct hostname(s): %v", len(seen), seen)
	}
}
