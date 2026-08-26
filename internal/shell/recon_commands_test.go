package shell

import (
	"strings"
	"testing"
)

func TestPsAuxListsStoryConsistentProcesses(t *testing.T) {
	s := NewInterpreter()
	out, code, _ := s.Run("ps aux")
	if code != 0 {
		t.Fatalf("ps aux failed: %s", out)
	}
	for _, want := range []string{"sshd", "nginx", "gunicorn", "cron"} {
		if !strings.Contains(out, want) {
			t.Errorf("ps aux output missing expected process %q:\n%s", want, out)
		}
	}
}

func TestNetstatAgreesWithPsAndNginxConfig(t *testing.T) {
	s := NewInterpreter()
	out, code, _ := s.Run("netstat -tulpn")
	if code != 0 {
		t.Fatalf("netstat failed: %s", out)
	}
	// Every listening port must match a process ps aux also claims is running,
	// and gunicorn must be bound to loopback only, matching nginx's
	// proxy_pass http://127.0.0.1:8000 in fs.go.
	for _, want := range []string{":22", "127.0.0.1:8000", ":80", "sshd", "gunicorn", "nginx"} {
		if !strings.Contains(out, want) {
			t.Errorf("netstat output missing expected entry %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "0.0.0.0:8000") || strings.Contains(out, ":::8000") {
		t.Errorf("gunicorn must only be bound to 127.0.0.1:8000 (nginx proxies to it), not externally reachable:\n%s", out)
	}
	if strings.Contains(out, "5432") {
		t.Errorf("the app's Postgres (10.0.4.12:5432, a different host per .env) must not appear in this box's own netstat:\n%s", out)
	}
}

func TestCrontabListEmptyMatchesRealBehavior(t *testing.T) {
	s := NewInterpreter()
	out, code, _ := s.Run("crontab -l")
	if code != 1 || out != "no crontab for ubuntu" {
		t.Fatalf("crontab -l = %q (code %d), want \"no crontab for ubuntu\" (code 1)", out, code)
	}
}

func TestWhichOnlyReportsCommandsTheShellCanActuallyRun(t *testing.T) {
	s := NewInterpreter()

	out, code, _ := s.Run("which ls cat")
	if code != 0 || !strings.Contains(out, "ls") || !strings.Contains(out, "cat") {
		t.Fatalf("which ls cat = %q (code %d), expected both paths", out, code)
	}

	// python3 is referenced in .bash_history but is NOT an execBuiltin case --
	// `which python3` must therefore report "not found", or a follow-up
	// `python3 -V` returning "command not found" would directly contradict it.
	out, code, _ = s.Run("which python3")
	if out != "" || code != 1 {
		t.Fatalf("which python3 = %q (code %d), want empty output and exit 1 (self-consistency with execBuiltin)", out, code)
	}
	pyOut, pyCode, _ := s.Run("python3 -V")
	if pyCode != 127 {
		t.Fatalf("python3 -V should be command-not-found (127) to match `which python3` reporting nothing, got code=%d out=%q", pyCode, pyOut)
	}
}

func TestFindWalksTheSameTreeAsLs(t *testing.T) {
	s := NewInterpreter()
	out, code, _ := s.Run("find /home/ubuntu -type f")
	if code != 0 {
		t.Fatalf("find failed: %s", out)
	}
	for _, want := range []string{"/home/ubuntu/.env", "/home/ubuntu/.bashrc", "/home/ubuntu/django-app/manage.py"} {
		if !strings.Contains(out, want) {
			t.Errorf("find /home/ubuntu -type f missing %q:\n%s", want, out)
		}
	}
	// A directory must never show up under -type f.
	if strings.Contains(out, "/home/ubuntu/.ssh\r\n") || strings.HasSuffix(out, "/home/ubuntu/.ssh") {
		t.Errorf("find -type f should not list the .ssh directory itself:\n%s", out)
	}
}

func TestFindNameFiltersByGlob(t *testing.T) {
	s := NewInterpreter()
	out, code, _ := s.Run("find /etc -name *.conf")
	if code != 0 {
		t.Fatalf("find -name failed: %s", out)
	}
	if !strings.Contains(out, "/etc/nsswitch.conf") {
		t.Errorf("find /etc -name *.conf missing /etc/nsswitch.conf:\n%s", out)
	}
	if strings.Contains(out, "/etc/hosts\r\n") || strings.HasSuffix(out, "/etc/hosts") {
		t.Errorf("find /etc -name *.conf should not match /etc/hosts:\n%s", out)
	}
}

func TestFindRespectsSurfaceBaitGating(t *testing.T) {
	s := NewInterpreter()
	// Without SURFACE_BAIT, the hidden .aws dir must not be discoverable via find.
	out, _, _ := s.Run("find /home/ubuntu")
	if strings.Contains(out, "/home/ubuntu/.aws") {
		t.Errorf("find should not reveal the SURFACE_BAIT-gated .aws dir without that deception action:\n%s", out)
	}
	out, _, _ = s.RunWithDeception("find /home/ubuntu", "SURFACE_BAIT")
	if !strings.Contains(out, "/home/ubuntu/.aws") {
		t.Errorf("find under SURFACE_BAIT should reveal .aws, same as ls does:\n%s", out)
	}
}
