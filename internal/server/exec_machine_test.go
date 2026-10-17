package server

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func execOutput(t *testing.T, client *ssh.Client, cmd string) string {
	t.Helper()
	s, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	out, _ := s.Output(cmd)
	return strings.TrimSpace(string(out))
}

// Bots run one command per exec channel. On a real box those are processes
// on one machine: a file one writes is there for the next, and the hostname
// never changes mid-connection (detection_checks.py's consistency checks).
func TestExecChannelsShareOneMachine(t *testing.T) {
	client, finish := dialRecordingSensor(t)
	defer finish()

	execOutput(t, client, "echo probe_7 > /tmp/.dc_probe; cd /tmp")
	if got := execOutput(t, client, "cat /tmp/.dc_probe"); got != "probe_7" {
		t.Errorf("file from the previous exec: %q", got)
	}
	if got := execOutput(t, client, "pwd"); got != "/root" {
		t.Errorf("cwd carried over between execs: %q", got)
	}
	h := execOutput(t, client, "hostname")
	if got := execOutput(t, client, "cat /etc/hostname"); got != h || h == "" {
		t.Errorf("hostname %q, then /etc/hostname %q", h, got)
	}
}

// Without a pty sshd runs `bash -c`: stdout and stderr apart, \n endings.
// With one, both streams share the terminal and get \r\n. Measured on 8.9p1.
func TestExecStreamsLikeBashC(t *testing.T) {
	client, finish := dialRecordingSensor(t)
	defer finish()

	s, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut strings.Builder
	s.Stdout, s.Stderr = &out, &errOut
	err = s.Run("echo a; qzxv; ls /nope")
	s.Close()
	if out.String() != "a\n" || errOut.String() != "bash: line 1: qzxv: command not found\nls: cannot access '/nope': No such file or directory\n" {
		t.Errorf("no pty: stdout %q stderr %q", out.String(), errOut.String())
	}
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 2 {
		t.Errorf("exit = %v, want 2", err)
	}

	s, _ = client.NewSession()
	if err := s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Output("echo a; qzxv; echo b")
	s.Close()
	if string(got) != "a\r\nbash: line 1: qzxv: command not found\r\nb\r\n" {
		t.Errorf("pty: %q", got)
	}

	if got := execOutput(t, client, "printenv SSH_CLIENT"); !strings.HasPrefix(got, "127.0.0.1 ") || !strings.HasSuffix(got, " 22") {
		t.Errorf("SSH_CLIENT = %q", got)
	}
}
