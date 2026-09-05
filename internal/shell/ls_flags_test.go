package shell

import (
	"strings"
	"testing"
)

// Regression coverage for the bug where lsBuiltin ignored every flag and
// always rendered the -la (long, all-files) format -- reported by an
// attacker testing the honeypot ("why is ls output ls -la output instead?").

func TestBareLsHidesDotfilesAndUsesShortForm(t *testing.T) {
	s := NewInterpreter("ubuntu")
	out, code, _ := s.Run("ls")
	if code != 0 {
		t.Fatalf("ls failed: %s", out)
	}
	if strings.Contains(out, ".bash_history") || strings.Contains(out, ".bashrc") || strings.Contains(out, ".env") {
		t.Errorf("bare ls should hide dotfiles, got: %q", out)
	}
	if strings.Contains(out, "total ") {
		t.Errorf("bare ls should not print a \"total N\" header, got: %q", out)
	}
	if strings.Contains(out, "drwx") || strings.Contains(out, "-rw-") {
		t.Errorf("bare ls should not print permission bits, got: %q", out)
	}
	if !strings.Contains(out, "django-app") {
		t.Errorf("bare ls should still list ordinary (non-dotfile) entries, got: %q", out)
	}
}

func TestLsDashADotfilesShortForm(t *testing.T) {
	s := NewInterpreter("ubuntu")
	out, code, _ := s.Run("ls -a")
	if code != 0 {
		t.Fatalf("ls -a failed: %s", out)
	}
	if !strings.Contains(out, ".bashrc") {
		t.Errorf("ls -a should include dotfiles, got: %q", out)
	}
	if strings.Contains(out, "total ") || strings.Contains(out, "drwx") {
		t.Errorf("ls -a alone should still be short form, got: %q", out)
	}
}

func TestLsDashLLongFormNoDotfiles(t *testing.T) {
	s := NewInterpreter("ubuntu")
	out, code, _ := s.Run("ls -l")
	if code != 0 {
		t.Fatalf("ls -l failed: %s", out)
	}
	if !strings.Contains(out, "total ") {
		t.Errorf("ls -l should print a total header, got: %q", out)
	}
	if strings.Contains(out, ".bashrc") {
		t.Errorf("ls -l without -a should still hide dotfiles, got: %q", out)
	}
	if strings.Contains(out, " .\n") || strings.HasSuffix(out, " .") {
		t.Errorf("ls -l without -a should not list '.' /'..' entries, got: %q", out)
	}
}

func TestLsDashLADashALLongFormAllFiles(t *testing.T) {
	for _, flags := range []string{"-la", "-al", "-l -a"} {
		s := NewInterpreter("ubuntu")
		out, code, _ := s.Run("ls " + flags)
		if code != 0 {
			t.Fatalf("ls %s failed: %s", flags, out)
		}
		if !strings.Contains(out, "total ") {
			t.Errorf("ls %s should print a total header, got: %q", flags, out)
		}
		if !strings.Contains(out, ".bashrc") {
			t.Errorf("ls %s should include dotfiles, got: %q", flags, out)
		}
		if !strings.Contains(out, "drwxr-xr-x") {
			t.Errorf("ls %s should include permission bits, got: %q", flags, out)
		}
	}
}

func TestLsShortFormIsAlphabeticallySorted(t *testing.T) {
	s := NewInterpreter("ubuntu")
	out, code, _ := s.Run("ls -a")
	if code != 0 {
		t.Fatalf("ls -a failed: %s", out)
	}
	fields := strings.Fields(out)
	sorted := append([]string(nil), fields...)
	for i := 1; i < len(sorted); i++ {
		if sorted[i-1] > sorted[i] {
			t.Fatalf("ls -a output not alphabetically sorted: %v", fields)
		}
	}
}
