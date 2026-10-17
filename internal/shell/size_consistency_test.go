package shell

import (
	"sort"
	"strings"
	"testing"
)

// ls -l and wc -c must agree on every file; detection_checks.py compares
// them for /etc/passwd, and any file works the same way.
func TestLsSizeMatchesContent(t *testing.T) {
	var paths []string
	for p, n := range fs {
		if n.Type == NodeFile && n.Link == "" && !strings.HasPrefix(n.Content, elfHeader[:4]) && (n.Bait == nil || !n.Bait.Hidden) {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	p := NewMachine(Ubuntu).NewInterpreter("root")
	for _, f := range paths {
		ls, _, _, _ := p.RunExec("ls -l " + f)
		wc, _, _, _ := p.RunExec("wc -c < " + f)
		fields := strings.Fields(ls)
		if len(fields) < 5 || fields[4] != strings.TrimSpace(wc) {
			t.Errorf("%s: ls -l %q, wc -c %q", f, strings.TrimSpace(ls), strings.TrimSpace(wc))
		}
	}
}
