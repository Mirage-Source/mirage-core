package shell

import (
	"errors"
	iofs "io/fs"
	"strings"
	"testing"
	"time"
)

func TestModeStringRoundTrip(t *testing.T) {
	for _, m := range []string{"-rw-r--r--", "drwxr-xr-x", "drwxrwxrwt", "-rwsr-xr-x", "-rwSr--r--", "drwxr-sr-T", "----------"} {
		bits := ModeBits(m)
		if got := ModeString(m[0] == 'd', bits&0o7777); got != m {
			t.Errorf("%s -> %o -> %s", m, bits, got)
		}
	}
	if ModeBits("drwxr-xr-x") != 0o40755 || ModeBits("-rw-r--r--") != 0o100644 {
		t.Error("type bits wrong")
	}
}

func TestMTimeUnix(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	if got := MTimeUnix("Feb  7  2022", now); got != uint32(time.Date(2022, 2, 7, 0, 0, 0, 0, time.UTC).Unix()) {
		t.Errorf("year form: %d", got)
	}
	if got := MTimeUnix("Jan 12 09:11", now); got != uint32(time.Date(2026, 1, 12, 9, 11, 0, 0, time.UTC).Unix()) {
		t.Errorf("this year: %d", got)
	}
	// A yearless date after "now" is last year's, as ls means it.
	if got := MTimeUnix("Dec 24 10:00", now); got != uint32(time.Date(2025, 12, 24, 10, 0, 0, 0, time.UTC).Unix()) {
		t.Errorf("last year: %d", got)
	}
}

func TestUploadShowsUpInLs(t *testing.T) {
	s := NewInterpreter("root")
	if err := s.CreateFile("/tmp/x86", true); err != nil {
		t.Fatal(err)
	}
	s.SetSize("/tmp/x86", 1234)
	if err := s.Chmod("/tmp/x86", 0o755); err != nil {
		t.Fatal(err)
	}
	out, _, _ := s.Run("ls -la /tmp")
	if !strings.Contains(out, "-rwxr-xr-x") || !strings.Contains(out, "1234") || !strings.Contains(out, "x86") {
		t.Errorf("ls -la /tmp:\n%s", out)
	}
	fi, err := s.Stat("/tmp/x86")
	if err != nil || fi.Size != 1234 || fi.Owner != "root" {
		t.Errorf("stat = %+v, %v", fi, err)
	}
}

func TestCreateNeedsParent(t *testing.T) {
	s := NewInterpreter("root")
	if err := s.CreateFile("/nope/x", false); !errors.Is(err, iofs.ErrNotExist) {
		t.Errorf("got %v", err)
	}
	if err := s.CreateFile("/tmp", false); !errors.Is(err, iofs.ErrInvalid) {
		t.Errorf("dir: got %v", err)
	}
}

func TestReadDirMatchesLs(t *testing.T) {
	s := NewInterpreter("root")
	s.Mkdir("/tmp/kit")
	entries, err := s.ReadDir("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name)
	}
	if strings.Join(names, ",") != ".,..,kit" {
		t.Errorf("names = %v", names)
	}
	if _, err := s.ReadDir("/etc/passwd"); err == nil {
		t.Error("ReadDir on a file succeeded")
	}
}

func TestRenameMovesDirectoryTree(t *testing.T) {
	s := NewInterpreter("root")
	s.Mkdir("/tmp/a")
	s.CreateFile("/tmp/a/f", false)
	if err := s.Rename("/tmp/a", "/tmp/b"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stat("/tmp/a/f"); err == nil {
		t.Error("old path still there")
	}
	if _, err := s.Stat("/tmp/b/f"); err != nil {
		t.Error("child not moved")
	}
	if err := s.Rename("/tmp/b", "/tmp/b/c"); err == nil {
		t.Error("moved a directory into itself")
	}
}

func TestRemoveDirMustBeEmpty(t *testing.T) {
	s := NewInterpreter("root")
	s.Mkdir("/tmp/d")
	s.CreateFile("/tmp/d/f", false)
	if err := s.Remove("/tmp/d", true); err == nil {
		t.Error("removed a non-empty dir")
	}
	if err := s.Remove("/tmp/d/f", true); err == nil {
		t.Error("rmdir on a file succeeded")
	}
	s.Remove("/tmp/d/f", false)
	if err := s.Remove("/tmp/d", true); err != nil {
		t.Error(err)
	}
}

func TestHiddenBaitIsInvisible(t *testing.T) {
	s := NewInterpreter("ubuntu")
	if _, err := s.Stat("/home/ubuntu/.aws/credentials"); err == nil {
		t.Error("hidden bait visible to stat")
	}
	if _, err := s.ReadFile("/home/ubuntu/.aws/credentials"); err == nil {
		t.Error("hidden bait readable")
	}
}

func TestReadFilePadsToListedSize(t *testing.T) {
	s := NewInterpreter("root")
	c, err := s.ReadFile("/bin/ls")
	if err != nil || len(c) != 138216 || !strings.HasPrefix(c, "\x7fELF") {
		t.Errorf("len %d, err %v", len(c), err)
	}
}

func TestReadFileDoesNotPadText(t *testing.T) {
	s := NewInterpreter("root")
	c, err := s.ReadFile("/etc/hostname")
	if err != nil || strings.Contains(c, "\x00") || c != s.Hostname+"\n" {
		t.Errorf("got %q, %v", c, err)
	}
}
