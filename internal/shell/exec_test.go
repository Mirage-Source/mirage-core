package shell

import (
	"strings"
	"testing"
)

// Expected values measured 2026-10-18 on ubuntu:22.04 openssh-server
// 1:8.9p1-3ubuntu0.18 with `ssh root@host '<cmd>'` (no pty): sshd runs
// `bash -c '<cmd>'`, so stdout and stderr are separate streams with \n line
// ends, and bash's own errors carry "bash: line N:".
func TestRunExecMatchesBashC(t *testing.T) {
	for _, tc := range []struct {
		cmd, stdout, stderr string
		code                int
	}{
		{"echo hi", "hi\n", "", 0},
		{"printf abc", "abc", "", 0},
		{"ls /nonexistent_dir", "", "ls: cannot access '/nonexistent_dir': No such file or directory\n", 2},
		{"qzxv_nope", "", "bash: line 1: qzxv_nope: command not found\n", 127},
		{"echo a; qzxv; echo b", "a\nb\n", "bash: line 1: qzxv: command not found\n", 0},
		{"echo a\nqzxv", "a\n", "bash: line 2: qzxv: command not found\n", 127},
		{"cd /nope", "", "bash: line 1: cd: /nope: No such file or directory\n", 1},
		{"ls /nope 2>&1", "ls: cannot access '/nope': No such file or directory\n", "", 2},
		{"echo $0 $SHELL", "bash /bin/bash\n", "", 0},
		{`echo "0=$0 ?=$? #=$# -=$-"; false; echo "after false $?"`, "0=bash ?=0 #=0 -=hBc\nafter false 1\n", "", 0},
		{"echo $HOME $USER $LOGNAME $PWD $SHLVL", "/root root root /root 1\n", "", 0},
		// bash lowers SHLVL just before exec'ing its last command or a
		// pipeline stage in place, so only those see 0.
		{"printenv SHLVL", "0\n", "", 0},
		{"printenv SHLVL; true", "1\n", "", 0},
		{"true; printenv SHLVL", "0\n", "", 0},
		{"env | grep SHLVL; true", "SHLVL=0\n", "", 0},
		{"X=1; export Y=2; env | grep -c '^[XY]='", "1\n", "", 0},
		{`printf "%s-%d|%5s|%-3s|%x|%o|%c|%%|%b\n" a 42 r l 255 8 xyz "q\tz"`, "a-42|    r|l  |ff|10|x|%|q\tz\n", "", 0},
		{`printf "%s\n" one two`, "one\ntwo\n", "", 0},
		{`printf "\x41\102\n"`, "AB\n", "", 0},
		{`printf "%d\n" abc`, "0\n", "bash: line 1: printf: abc: invalid number\n", 1},
		{"printf", "", "printf: usage: printf [-v var] format [arguments]\n", 2},
		{"cd /tmp; echo $PWD", "/tmp\n", "", 0},
		{"echo $PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin\n", "", 0},
	} {
		p := NewMachine(Ubuntu).NewInterpreter("root")
		stdout, stderr, code, _ := p.RunExec(tc.cmd)
		if stdout != tc.stdout || stderr != tc.stderr || code != tc.code {
			t.Errorf("%q:\n got  out=%q err=%q code=%d\n want out=%q err=%q code=%d",
				tc.cmd, stdout, stderr, code, tc.stdout, tc.stderr, tc.code)
		}
	}
}

func TestEnvListsTheLoginEnvironment(t *testing.T) {
	p := NewMachine(Ubuntu).NewInterpreter("root")
	p.Env["SSH_CLIENT"] = "203.0.113.9 51515 22"
	out, _, code, _ := p.RunExec("env")
	want := []string{"HOME=/root", "LOGNAME=root", "PATH=/usr/local/sbin:", "PWD=/root", "SHELL=/bin/bash", "SHLVL=0", "_=/usr/bin/env", "SSH_CLIENT=203.0.113.9 51515 22", "USER=root"}
	for _, w := range want {
		if !strings.Contains(out, "\n"+w) && !strings.HasPrefix(out, w) {
			t.Errorf("env missing %q:\n%s", w, out)
		}
	}
	if code != 0 {
		t.Errorf("env exit %d", code)
	}
	if got, _, _, _ := p.RunExec("printenv HOME"); got != "/root\n" {
		t.Errorf("printenv HOME = %q", got)
	}
	if _, _, code, _ := p.RunExec("printenv NOPE_X"); code != 1 {
		t.Errorf("printenv of unset var exit %d, want 1", code)
	}
}

// The interactive shell keeps its terminal formatting and merged output.
// (Its error wording is a separate question: a login shell says "-bash:",
// and an EC2 image's command-not-found handler words it differently again.)
func TestInteractiveRunUnchanged(t *testing.T) {
	p := NewInterpreter("root")
	if out, _, _ := p.Run("echo a; qzxv; echo b"); !strings.HasPrefix(out, "a\r\n") || !strings.HasSuffix(out, "qzxv: command not found\r\nb") || strings.Contains(out, "line 1") {
		t.Errorf("interactive output %q", out)
	}
	if out, _, _ := p.Run("echo $SHLVL $0"); out != "1 -bash" {
		t.Errorf("interactive $SHLVL $0 = %q", out)
	}
}

// SANS ISC 31064: bots read 22 bytes of their own shell binary to learn
// the architecture from the ELF header.
func TestDDSelfExeOneLiner(t *testing.T) {
	const line = "busybox dd if=$SHELL bs=22 count=1||dd if=/proc/self/exe bs=22 count=1||" +
		"while read i;do busybox echo -n $i;done</proc/self/exe||cat /proc/self/exe"
	out, _, code, _ := NewMachine(Ubuntu).NewInterpreter("root").RunExec(line)
	if len(out) != 22 || !strings.HasPrefix(out, "\x7fELF") || code != 0 {
		t.Errorf("got %d bytes %q, exit %d; want 22 bytes of ELF header", len(out), out, code)
	}
	for _, c := range []string{"while read i;do echo $i;done</etc/hostname", "dd if=$SHELL bs=22 count=1", "ls /bin/bash /bin/sh /dev/shm"} {
		if _, errOut, code, _ := NewMachine(Ubuntu).NewInterpreter("root").RunExec(c); code != 0 {
			t.Errorf("%q: exit %d, %q", c, code, errOut)
		}
	}
}

// Measured on 8.9p1 / coreutils 8.32 with no tty: one name per line, files
// before directories, errors on stderr first, columns sized to the widest
// entry, symlinks shown as links.
func TestLsLikeCoreutilsWithoutATerminal(t *testing.T) {
	p := NewMachine(Ubuntu).NewInterpreter("root")
	p.RunExec("mkdir -p /tmp/lt/d1 /tmp/lt/d2; touch /tmp/lt/d1/a /tmp/lt/d1/b /tmp/lt/f")
	for _, tc := range []struct {
		cmd, stdout, stderr string
		code                int
	}{
		{"cd /tmp/lt; ls d1", "a\nb\n", "", 0},
		{"cd /tmp/lt; ls f nope d1 d2", "f\n\nd1:\na\nb\n\nd2:\n", "ls: cannot access 'nope': No such file or directory\n", 2},
		{"ls -l /bin/sh", "lrwxrwxrwx 1 root root 4 Mar 23  2022 /bin/sh -> dash\n", "", 0},
		{"dd if=/bin/sh bs=4 count=1 2>/dev/null", "\x7fELF", "", 0},
	} {
		p := p.Machine.NewInterpreter("root")
		stdout, stderr, code, _ := p.RunExec(tc.cmd)
		if stdout != tc.stdout || stderr != tc.stderr || code != tc.code {
			t.Errorf("%q:\n got  out=%q err=%q code=%d\n want out=%q err=%q code=%d",
				tc.cmd, stdout, stderr, code, tc.stdout, tc.stderr, tc.code)
		}
	}
}

// Single quotes and backslashes stop expansion. They used to be removed
// before expansion ran, so `echo '$(id)'` ran id and awk '{print $1}' got
// an empty program.
func TestQuotingStopsExpansion(t *testing.T) {
	for _, tc := range []struct{ cmd, want string }{
		{`echo '$HOME'`, "$HOME\n"},
		{`echo "$HOME"`, "/root\n"},
		{`echo '$(id)'`, "$(id)\n"},
		{`echo a'$HOME'b`, "a$HOMEb\n"},
		{`echo "a'$HOME'b"`, "a'/root'b\n"},
		{`echo \$HOME`, "$HOME\n"},
		{`echo "\$HOME is $HOME"`, "$HOME is /root\n"},
		{`echo '$1' "$1"`, "$1 \n"},
	} {
		got, _, _, _ := NewMachine(Ubuntu).NewInterpreter("root").RunExec(tc.cmd)
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.cmd, got, tc.want)
		}
	}
	inv := ParseCommands(`awk '{print $1}' /etc/passwd`)
	if len(inv) != 1 || inv[0].Args[0] != "{print $1}" {
		t.Errorf("logged args %q", inv)
	}
}
