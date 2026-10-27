package shell

import (
	"strings"
	"testing"
)

// A case added without running `python3 scripts/ubuntu_diff.py regen` has no expected output. Read as
// zero values it would mean "prints nothing, exit 0", which a broken shell can satisfy by accident.
func TestUbuntuFileRejectsCasesThatWereNeverRegenerated(t *testing.T) {
	_, err := parseUbuntuFile([]byte(`{"cases":[{"cmd":"echo hi"}],"known_gaps":[]}`))
	if err == nil || !strings.Contains(err.Error(), "regen") {
		t.Fatalf("want an error telling the author to run regen, got %v", err)
	}
}

func TestUbuntuFileAcceptsACompleteCase(t *testing.T) {
	f, err := parseUbuntuFile([]byte(`{"cases":[{"cmd":"true","stdout":"","stderr":"","code":0}],"known_gaps":[]}`))
	if err != nil || len(f.Cases) != 1 || f.Cases[0].cmd != "true" {
		t.Fatalf("got %+v, %v", f, err)
	}
}

func TestUbuntuFileRejectsDuplicates(t *testing.T) {
	c := `{"cmd":"true","stdout":"","stderr":"","code":0}`
	if _, err := parseUbuntuFile([]byte(`{"cases":[` + c + `,` + c + `],"known_gaps":[]}`)); err == nil {
		t.Fatal("a command listed twice is counted twice in any pass rate")
	}
}
