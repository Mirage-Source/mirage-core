package shell

import (
	"strings"
	"testing"
)

// The telnet sensor is a HiSilicon Hi3520DV400 DVR (Cortex-A7, BusyBox ash).
// 579 of ~630 logged-in telnet IPs open with device-console words
// (enable/system/shell), and loaders pick a payload from uname and ELF
// headers, so every surface must agree on one embedded ARM device.

func newDVR() *Interpreter { return NewInterpreterFor("admin", DVR) }

func TestDVRIdentity(t *testing.T) {
	s := newDVR()
	for line, want := range map[string]string{
		"uname -a": "Linux LocalHost 3.10.0 #1 SMP Thu Mar 8 15:40:28 CST 2018 armv7l GNU/Linux",
		"uname -m": "armv7l",
		"hostname": "LocalHost",
		"whoami":   "root",
		"pwd":      "/",
		"id":       "uid=0(root) gid=0(root) groups=0(root)",
	} {
		if out, _, _ := s.Run(line); out != want {
			t.Errorf("%s = %q, want %q", line, out, want)
		}
	}
	if p := s.Prompt(); p != "# " {
		t.Errorf("prompt = %q, want \"# \"", p)
	}
}

func TestDVRShellErrorsAreAsh(t *testing.T) {
	s := newDVR()
	for line, want := range map[string]string{
		"enable":           "-sh: enable: not found",
		"linuxshell":       "-sh: linuxshell: not found",
		"do":               `-sh: syntax error: unexpected "do"`,
		"echo x > /nope/f": "-sh: can't create /nope/f: nonexistent directory",
		"./missing":        "-sh: ./missing: not found",
	} {
		if out, _, _ := s.Run(line); out != want {
			t.Errorf("%q -> %q, want %q", line, out, want)
		}
	}
}

func TestDVRConsoleWordsLikeBusybox(t *testing.T) {
	s := newDVR()
	if out, code, _ := s.Run("su"); out != "" || code != 0 {
		t.Errorf("su (already root) -> (%q, %d), want silent success", out, code)
	}
	out, code, _ := s.Run("ping")
	if code != 1 || !strings.HasPrefix(out, "BusyBox v1.20.2") || !strings.Contains(out, "Usage: ping") {
		t.Errorf("ping -> (%q, %d), want BusyBox usage, exit 1", out, code)
	}
	if out, _, _ := s.Run("/bin/busybox"); !strings.HasPrefix(out, "BusyBox v1.20.2 (2018-03-08 15:32:11 CST) multi-call binary.") {
		t.Errorf("busybox banner = %q", firstLine(out))
	}
}

func TestDVRHostnameCanBeSet(t *testing.T) {
	s := newDVR()
	if out, code, _ := s.Run("/bin/busybox hostname PBOC"); out != "" || code != 0 {
		t.Errorf("hostname PBOC -> (%q, %d), want silent success", out, code)
	}
	if out, _, _ := s.Run("hostname"); out != "PBOC" {
		t.Errorf("hostname after set = %q, want PBOC", out)
	}
}

func TestDVRProcFilesDescribeTheSameARMDevice(t *testing.T) {
	s := newDVR()
	checks := map[string][]string{
		"cat /proc/cpuinfo": {"ARMv7 Processor rev 5 (v7l)", "CPU part\t: 0xc07", "hi3520dv400"},
		"cat /proc/version": {"Linux version 3.10.0", "Thu Mar 8 15:40:28 CST 2018"},
		"cat /proc/mounts":  {"rootfs / squashfs ro", "tmpfs /var tmpfs rw", "tmpfs /dev/shm tmpfs rw"},
		"ps":                {"  PID USER       VSZ STAT COMMAND", "Sofia", "telnetd"},
	}
	for line, wants := range checks {
		out, _, _ := s.Run(line)
		for _, w := range wants {
			if !strings.Contains(out, w) {
				t.Errorf("%s missing %q:\n%s", line, w, out)
			}
		}
	}
}

func TestDVRELFHeaderIsARM32(t *testing.T) {
	s := newDVR()
	out, code, _ := s.Run("dd bs=52 count=1 if=/bin/ls")
	if code != 0 || out[:52] != elf32ARMHeader {
		t.Fatalf("dd header = %q (exit %d)", out, code)
	}
	// EI_CLASS=1 (32-bit), EI_DATA=1 (LE), e_machine=0x28 (ARM), EABI5.
	h := elf32ARMHeader
	if h[4] != 1 || h[5] != 1 || h[18] != 0x28 || h[39] != 0x05 || len(h) != 52 {
		t.Errorf("header fields wrong: % x", h)
	}
}

func TestDVRShadowIsStillBait(t *testing.T) {
	s := newDVR()
	_, _, bait := s.Run("cat /etc/shadow")
	if len(bait) != 1 || bait[0].BaitID != "etc-shadow" {
		t.Errorf("bait = %+v, want one etc-shadow hit", bait)
	}
}

func TestDVRShowsNoUbuntuTraces(t *testing.T) {
	s := newDVR()
	for _, line := range []string{
		"uname -a", "cat /proc/version", "cat /proc/cpuinfo", "ls /", "ls /home",
		"ps", "id", "hostname", "/bin/busybox", "cat /etc/passwd", "ping", "ls /bin",
	} {
		out, _, _ := s.Run(line)
		low := strings.ToLower(out)
		for _, tell := range []string{"ubuntu", "aws", "x86", "intel", "bash", "nginx", "gunicorn"} {
			if strings.Contains(low, tell) {
				t.Errorf("%q leaks %q: %q", line, tell, firstLine(out))
			}
		}
	}
	if _, code, _ := s.Run("cat /etc/os-release"); code == 0 {
		t.Error("/etc/os-release exists on the DVR")
	}
}

func TestUbuntuProfileHasNoBusybox(t *testing.T) {
	s := NewInterpreter("root")
	if out, code, _ := s.Run("cat /bin/busybox"); code != 1 || !strings.Contains(out, "No such file") {
		t.Errorf("SSH: cat /bin/busybox -> (%q, %d), want not found", out, code)
	}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\r\n")
	return line
}
