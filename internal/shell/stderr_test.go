package shell

import (
	"strings"
	"testing"
)

// These lock in the fix for the "unknown commands always write to stdout"
// tell (SECURITY.md correctness notes): a real recon script commonly probes
// exactly this distinction via `2>`, `2>&1`, or `2>/dev/null`.

func TestUnknownCommandStderrRedirectsToFile(t *testing.T) {
	s := NewInterpreter()
	out, code, _ := s.Run("wget http://example.com/a 2>/tmp/err")
	if out != "" {
		t.Fatalf("stderr should have been redirected away from the terminal, got %q", out)
	}
	if code != 127 {
		t.Fatalf("exit code should still be 127, got %d", code)
	}

	catOut, catCode, _ := s.Run("cat /tmp/err")
	if catCode != 0 {
		t.Fatalf("cat /tmp/err failed: %s", catOut)
	}
	if strings.TrimSpace(catOut) != "bash: wget: command not found" {
		t.Fatalf("/tmp/err = %q, want the command-not-found message", catOut)
	}
}

func TestUnknownCommandStderrToDevNullIsSilentAndCreatesNoFile(t *testing.T) {
	s := NewInterpreter()
	out, code, _ := s.Run("wget http://example.com/a 2>/dev/null")
	if out != "" || code != 127 {
		t.Fatalf("wget ... 2>/dev/null = %q (code %d), want empty output, code 127", out, code)
	}
	// /dev/null must not become a real (empty) file node in the sim fs.
	_, lsCode, _ := s.Run("cat /dev/null")
	if lsCode == 0 {
		t.Fatalf("/dev/null should not have been materialized as a real file")
	}
}

func TestUnknownCommandStdoutRedirectDoesNotSwallowStderr(t *testing.T) {
	// `> file` only touches stdout -- an unknown command's error text is
	// stderr and must still reach the terminal, matching real bash.
	s := NewInterpreter()
	out, code, _ := s.Run("wget http://example.com/a > out.txt")
	if code != 127 {
		t.Fatalf("expected code 127, got %d", code)
	}
	if out != "bash: wget: command not found" {
		t.Fatalf("stdout-only redirect should not have hidden the error text, got %q", out)
	}
}

func TestTwoGreaterAmpOneMergesStderrIntoStdout(t *testing.T) {
	s := NewInterpreter()
	out, code, _ := s.Run("wget http://example.com/a 2>&1")
	if code != 127 {
		t.Fatalf("expected code 127, got %d", code)
	}
	if out != "bash: wget: command not found" {
		t.Fatalf("2>&1 should still show the message on the terminal (nothing to merge away from), got %q", out)
	}
}

func TestStderrMergedIntoPipeIsVisibleToNextStage(t *testing.T) {
	s := NewInterpreter()
	out, code, _ := s.Run("wget http://example.com/a 2>&1 | grep -i found")
	if code != 0 {
		t.Fatalf("grep should have matched the merged stderr text, got code=%d out=%q", code, out)
	}
	if out != "bash: wget: command not found" {
		t.Fatalf("expected grep to forward the merged error line, got %q", out)
	}
}

func TestErrorTextIsNotPipedByDefault(t *testing.T) {
	// Without 2>&1, an error message must NOT flow into the next pipeline
	// stage -- this generalizes the old code==127-only rule to every
	// nonzero-exit builtin (e.g. cat's "No such file or directory", code 1).
	s := NewInterpreter()
	out, code, _ := s.Run("cat missingfile | wc -l")
	if code != 0 {
		t.Fatalf("wc -l failed: %s", out)
	}
	if out != "0" {
		t.Fatalf("cat's error text must not be piped into wc -l, want a 0-line count, got %q", out)
	}
}

func TestAmpGreaterCombinesBothStreamsIntoOneFile(t *testing.T) {
	s := NewInterpreter()
	out, code, _ := s.Run("wget http://example.com/a &>/tmp/both")
	if out != "" || code != 127 {
		t.Fatalf("&>/tmp/both = %q (code %d), want empty terminal output, code 127", out, code)
	}
	catOut, catCode, _ := s.Run("cat /tmp/both")
	if catCode != 0 || strings.TrimSpace(catOut) != "bash: wget: command not found" {
		t.Fatalf("/tmp/both = %q (code %d), want the command-not-found message", catOut, catCode)
	}
}

func TestWhichStdoutContentIsNeverTreatedAsStderr(t *testing.T) {
	// which can legitimately exit 1 (some args weren't found) while its
	// printed matches are still real stdout content, not error text.
	s := NewInterpreter()
	out, code, _ := s.Run("which ls python3 2>/tmp/which_err")
	if code != 1 {
		t.Fatalf("expected exit 1 (python3 not found), got %d", code)
	}
	if out == "" {
		t.Fatalf("which's real stdout match for `ls` must still display, got empty output")
	}
	_, catCode, _ := s.Run("cat /tmp/which_err")
	if catCode == 0 {
		t.Fatalf("which never writes error text, so 2>/tmp/which_err should never have created that file")
	}
}
