package buildinfo

import (
	"os/exec"
	"strings"
	"testing"
)

// An unstamped build must say so, loudly, instead of looking like a real revision.
func TestUnstampedBuildReportsUnknown(t *testing.T) {
	if Commit != "unknown" {
		t.Skipf("this test binary was linked with -X, Commit=%q", Commit)
	}
}

// The -X symbol path is the part that fails silently: a typo leaves "unknown" in
// every stored session. This links a real program with the exact flag the
// Dockerfiles use and reads the value back.
func TestLinkerFlagStampsCommit(t *testing.T) {
	if testing.Short() {
		t.Skip("invokes the go toolchain")
	}
	const sym = "github.com/mirage-source/mirage-core/internal/buildinfo.Commit"
	out, err := exec.Command("go", "run", "-ldflags", "-X "+sym+"=abc1234-dirty", "./printcommit").CombinedOutput()
	if err != nil {
		t.Fatalf("go run: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "abc1234-dirty" {
		t.Fatalf("stamped commit = %q, want abc1234-dirty", got)
	}
}
