package shell

import (
	"strings"
	"testing"
)

// Mirai-family loaders read an ELF header to pick which binary to fetch; a
// missing file ends the session before any download. These are the exact
// probes seen on the telnet sensor, by distinct source IPs. /bin/busybox is
// left out of the shared fs so SSH, which has no busybox, stays unchanged.
var elfProbes = []string{
	"/bin/busybox cat /proc/self/exe || cat /proc/self/exe", // 242 IPs
	"dd bs=52 count=1 if=/bin/ls || cat /bin/ls",            // 53
	"/bin/busybox dd bs=52 count=1 if=/bin/ls || /bin/busybox cat /bin/ls",
	"/bin/busybox cat /bin/ls|head -n 1",
	"/bin/busybox cat /bin/ls|more",
	"/bin/busybox cat /bin/echo", // 8
}

func TestELFProbesSeeAHeaderMatchingUname(t *testing.T) {
	s := newBusyboxInterpreter()
	if m, _, _ := s.Run("uname -m"); m != "x86_64" {
		t.Fatalf("uname -m = %q; this test assumes x86_64", m)
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
		// EI_CLASS=2 (64-bit), EI_DATA=1 (little-endian), e_machine=0x3e (x86-64).
		if out[4] != 2 || out[5] != 1 || out[18] != 0x3e || out[19] != 0 {
			t.Errorf("%q header class=%d data=%d machine=%#x%02x, want 64-bit LE x86-64",
				line, out[4], out[5], out[19], out[18])
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
