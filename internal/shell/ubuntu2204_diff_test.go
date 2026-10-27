package shell

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// Differential tests against a real Ubuntu 22.04 host.
//
// testdata/ubuntu2204.json lists commands with the stdout, stderr and exit status that
// `bash -c <cmd>` produced in a fresh ubuntu:22.04 container (bash 5.1.16, GNU coreutils 8.32,
// grep 3.7, sed 4.8, mawk 1.3.4, root, cwd /root, no network). RunExec must reproduce all three
// byte for byte, which is how sshd runs an exec request.
//
// The expected values are produced by the container, never typed:
//
//	python3 scripts/ubuntu_diff.py check   # compare the file with the container (needs Docker)
//	python3 scripts/ubuntu_diff.py regen   # rewrite every expectation from the container
//
// To add a case, append {"cmd": "..."} to "cases" and run regen. Never edit an expected value to
// make a test pass; fix the shell instead.

type ubuntuCase struct {
	cmd, stdout, stderr string
	code                int
}

type ubuntuFile struct {
	Cases, KnownGaps []ubuntuCase
}

// parseUbuntuFile reads the data file and rejects what would make the pass rate meaningless: a case
// with no recorded expectation (never regenerated) and a command listed twice.
func parseUbuntuFile(data []byte) (ubuntuFile, error) {
	type raw struct {
		Cmd    string  `json:"cmd"`
		Stdout *string `json:"stdout"`
		Stderr *string `json:"stderr"`
		Code   *int    `json:"code"`
	}
	var in struct {
		Cases     []raw `json:"cases"`
		KnownGaps []raw `json:"known_gaps"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return ubuntuFile{}, err
	}
	seen := map[string]bool{}
	conv := func(rs []raw) ([]ubuntuCase, error) {
		var out []ubuntuCase
		for _, r := range rs {
			if r.Stdout == nil || r.Stderr == nil || r.Code == nil {
				return nil, fmt.Errorf("%q has no recorded expectation: run `python3 scripts/ubuntu_diff.py regen`", r.Cmd)
			}
			if seen[r.Cmd] {
				return nil, fmt.Errorf("%q is listed twice", r.Cmd)
			}
			seen[r.Cmd] = true
			out = append(out, ubuntuCase{r.Cmd, *r.Stdout, *r.Stderr, *r.Code})
		}
		return out, nil
	}
	var f ubuntuFile
	var err error
	if f.Cases, err = conv(in.Cases); err != nil {
		return f, err
	}
	f.KnownGaps, err = conv(in.KnownGaps)
	return f, err
}

func loadUbuntuCases(t *testing.T) ubuntuFile {
	t.Helper()
	data, err := os.ReadFile("testdata/ubuntu2204.json")
	if err != nil {
		t.Fatal(err)
	}
	f, err := parseUbuntuFile(data)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestMatchesUbuntu2204(t *testing.T) {
	f := loadUbuntuCases(t)
	if len(f.Cases) == 0 {
		t.Fatal("no cases loaded")
	}
	for _, tc := range f.Cases {
		stdout, stderr, code, _ := NewMachine(Ubuntu).NewInterpreter("root").RunExec(tc.cmd)
		if stdout != tc.stdout || stderr != tc.stderr || code != tc.code {
			t.Errorf("%q\n got  stdout=%q stderr=%q code=%d\n want stdout=%q stderr=%q code=%d", tc.cmd, stdout, stderr, code, tc.stdout, tc.stderr, tc.code)
		}
	}
	t.Logf("%d cases match Ubuntu 22.04, %d known gap(s) tracked", len(f.Cases), len(f.KnownGaps))
}

// Known gaps: measured on the same container, not yet matched. When one starts matching, move it to
// "cases" in the data file.
func TestKnownUbuntu2204Gaps(t *testing.T) {
	for _, tc := range loadUbuntuCases(t).KnownGaps {
		stdout, stderr, code, _ := NewMachine(Ubuntu).NewInterpreter("root").RunExec(tc.cmd)
		if stdout == tc.stdout && stderr == tc.stderr && code == tc.code {
			t.Errorf("%q now matches Ubuntu: move it to \"cases\" in testdata/ubuntu2204.json", tc.cmd)
		}
	}
}
