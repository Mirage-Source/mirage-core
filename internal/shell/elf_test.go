package shell

import (
	"strings"
	"testing"
)

// Mirai-family loaders read an ELF header to pick which binary to fetch; a
// missing file ends the session before any download. These are the exact
// probes seen on the telnet sensor, by distinct source IPs.
var elfProbes = []string{
	"/bin/busybox cat /proc/self/exe || cat /proc/self/exe", // 242 IPs
	// 53 IPs each; exact lines, including the while-read fallbacks.
	"dd bs=52 count=1 if=/bin/ls || cat /bin/ls || while read i; do echo $i; done < /bin/ls || while read i; do echo $i; done < /bin/busybox",
	"/bin/busybox dd bs=52 count=1 if=/bin/ls || /bin/busybox cat /bin/ls || while read i; do printf $i; done < /bin/ls || while read i; do printf $i; done < /bin/busybox",
	"/bin/busybox cat /bin/ls|head -n 1",
	"/bin/busybox cat /bin/ls|more",
	"/bin/busybox cat /bin/echo", // 8
	// 3 IPs, 449 sessions.
	"/bin/busybox cat /bin/busybox || while read i; do echo $i; done < /bin/busybox",
}

// wantELF maps `uname -m` to the ELF (class, e_machine) a loader expects.
var wantELF = map[string][2]byte{"x86_64": {2, 0x3e}, "armv7l": {1, 0x28}}

func TestELFProbesSeeAHeaderMatchingUname(t *testing.T) {
	s := newBusyboxInterpreter()
	m, _, _ := s.Run("uname -m")
	want, ok := wantELF[m]
	if !ok {
		t.Fatalf("no expected ELF for uname -m %q", m)
	}
	for _, line := range elfProbes {
		out, code, _ := s.Run(line)
		if code != 0 {
			t.Errorf("%q exit %d, want 0 (out %q)", line, code, out)
			continue
		}
		if len(out) < 20 || !strings.HasPrefix(out, "\x7fELF") {
			t.Errorf("%q -> %q, want an ELF header", line, out)
			continue
		}
		if out[4] != want[0] || out[5] != 1 || out[18] != want[1] || out[19] != 0 {
			t.Errorf("%q header class=%d data=%d machine=%#x, want class %d LE machine %#x for %s",
				line, out[4], out[5], out[18], want[0], want[1], m)
		}
	}
}

// SSH's Ubuntu box answers the same probes with an x86-64 header.
func TestUbuntuELFMatchesUname(t *testing.T) {
	s := NewInterpreter("root")
	for _, line := range []string{"cat /proc/self/exe", "dd bs=52 count=1 if=/bin/ls"} {
		out, _, _ := s.Run(line)
		if len(out) < 20 || out[4] != 2 || out[18] != 0x3e {
			t.Errorf("%q -> %q, want an x86-64 ELF64 header", line, firstLine(out))
		}
	}
}

func TestDDCopiesExactlyBsTimesCountThenReportsRecords(t *testing.T) {
	s := NewInterpreter("root")
	out, code, _ := s.Run("dd bs=52 count=1 if=/bin/ls")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, out)
	}
	if out[:52] != elfHeader[:52] {
		t.Errorf("first 52 bytes = %q, want the first 52 header bytes", out[:52])
	}
	if !strings.HasPrefix(out[52:], "1+0 records in\r\n1+0 records out\r\n52 bytes copied") {
		t.Errorf("after data = %q, want GNU dd record summary", out[52:])
	}
}

func TestDDMissingInputFileFailsLikeGNU(t *testing.T) {
	s := NewInterpreter("root")
	out, code, _ := s.Run("dd if=/nope bs=1 count=1")
	if code != 1 || out != "dd: failed to open '/nope': No such file or directory" {
		t.Errorf("-> (%q, %d)", out, code)
	}
}

func TestMorePassesPipedInputThrough(t *testing.T) {
	s := NewInterpreter("root")
	if out, code, _ := s.Run("echo hi | more"); out != "hi" || code != 0 {
		t.Errorf("echo hi | more -> (%q, %d), want (\"hi\", 0)", out, code)
	}
}

func TestBinariesAreListedWhereTheyExist(t *testing.T) {
	s := NewInterpreter("root")
	for dir, want := range map[string]string{"/bin": "ls", "/proc": "self", "/proc/self": "exe"} {
		out, _, _ := s.Run("ls " + dir)
		if !strings.Contains(out, want) {
			t.Errorf("ls %s = %q, want it to list %s", dir, out, want)
		}
	}
}

func TestBusyboxBinaryExistsOnTheDVR(t *testing.T) {
	if out, _, _ := newBusyboxInterpreter().Run("ls /bin"); !strings.Contains(out, "busybox") {
		t.Errorf("DVR: ls /bin = %q, want busybox listed", out)
	}
}
