package shell

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// The replay measures how often real attacker commands make the shell give itself away. It does not
// compare output with Ubuntu (ubuntu2204_diff_test.go does that for commands we have ground truth
// for). A "tell" here is what no Ubuntu host would print for a command it has:
//   - "syntax error": bash accepts these commands, so the parser failed;
//   - "X: command not found" for any X other than the probe below.
//
// Honest limit: some attackers run binaries Ubuntu really lacks (their own dropper, ssh in a minimal
// image), where "command not found" is the right answer, so the tell rate is an upper bound on
// those; and "ok" only means none of the tells appeared, not that the output was right.

func TestClassifyReplay(t *testing.T) {
	for _, tc := range []struct {
		name, out, class, detail string
	}{
		{"plain output", "Linux\n", "ok", ""},
		{"empty output", "", "ok", ""},
		{"syntax error", "bash: line 1: syntax error near unexpected token `;;'\n", "syntax_error", ""},
		{"missing command", "bash: line 1: lockr: command not found\n", "command_not_found", "lockr"},
		// The botnet self-test runs `xxxxxx` on purpose and expects exactly this answer from a real host.
		{"the self-test probe is the correct answer", "bash: line 1: xxxxxx: command not found\n", "ok", ""},
		{"the probe's file form is also correct", "bash: line 1: ./xxxxxx: No such file or directory\n", "ok", ""},
		{"a real miss next to the probe still counts", "bash: line 1: xxxxxx: command not found\nbash: line 2: busybox: command not found\n", "command_not_found", "busybox"},
		{"syntax error wins over a miss", "bash: line 1: foo: command not found\nbash: line 2: syntax error near unexpected token `esac'\n", "syntax_error", ""},
		{"a command merely mentioning the words is ok", "echo command not found\n", "ok", ""},
	} {
		class, detail := classifyReplay(tc.out)
		if class != tc.class || detail != tc.detail {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", tc.name, class, detail, tc.class, tc.detail)
		}
	}
}

func TestSummarizeReplayWeightsBySessions(t *testing.T) {
	items := []replayItem{{Sessions: 90, Cmd: "echo hi"}, {Sessions: 10, Cmd: "nosuchcmdxyz"}}
	s := summarizeReplay(items, runReplay(items))
	if s.Commands != 2 || s.Sessions != 100 {
		t.Fatalf("totals: %+v", s)
	}
	if s.BySessions["ok"] != 90 || s.BySessions["command_not_found"] != 10 {
		t.Errorf("weights: %+v", s.BySessions)
	}
	if got := s.OKPercent(); got != 90.0 {
		t.Errorf("ok%% = %v, want 90", got)
	}
}

// One command, the botnet self-test, can dominate the weighted total (12.6% of Nuremberg's replay,
// 14.1% of Frankfurt's), and it flips from a syntax error to correct all at once. The summary must be
// able to leave it out so the headline never rests on that one command.
func TestSummaryCanLeaveOutTheSelfTest(t *testing.T) {
	items := []replayItem{{Sessions: 50, Cmd: "echo a; " + selfTestMarker}, {Sessions: 40, Cmd: "echo hi"}, {Sessions: 10, Cmd: "nosuchcmdxyz"}}
	results := []replayResult{{"ok", ""}, {"ok", ""}, {"command_not_found", "nosuchcmdxyz"}}
	all := summarizeReplay(items, results)
	rest := summarizeReplayWhere(items, results, func(it replayItem) bool { return !isSelfTest(it) })
	if all.OKPercent() != 90 {
		t.Errorf("all = %v, want 90", all.OKPercent())
	}
	if rest.Sessions != 50 || rest.OKPercent() != 80 {
		t.Errorf("without the self-test: %+v ok=%v, want 50 sessions at 80%%", rest, rest.OKPercent())
	}
}

func TestReplayContainsAPanicInsteadOfCrashingTheRun(t *testing.T) {
	class, _ := runReplayItem("echo hi", 0, func(string) (string, string) { panic("boom") })
	if class != "crash" {
		t.Errorf("class = %q, want crash", class)
	}
}

func TestReplayReportsATimeoutInsteadOfHanging(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	class, _ := runReplayItem("sleep forever", 50*1e6, func(string) (string, string) { <-block; return "", "" })
	if class != "timeout" {
		t.Errorf("class = %q, want timeout", class)
	}
}

// ---- the harness -------------------------------------------------------------------------------

// replayProbe is the name the botnet self-test runs on purpose. A real Ubuntu answers it with
// "command not found", so that answer is correct and never counts as a tell.
const replayProbe = "xxxxxx"

var commandNotFound = regexp.MustCompile(`(?:^|: )([^\s:]+): command not found`)

type replayItem struct {
	Sessions int    `json:"sessions"`
	Cmd      string `json:"cmd"`
}

type replayResult struct{ Class, Detail string }

func classifyReplay(out string) (class, detail string) {
	if strings.Contains(out, "syntax error") {
		return "syntax_error", ""
	}
	for _, line := range strings.Split(out, "\n") {
		if m := commandNotFound.FindStringSubmatch(line); m != nil && m[1] != replayProbe {
			return "command_not_found", m[1]
		}
	}
	return "ok", ""
}

// runReplayItem runs one command through run. A panic or a command that does not finish becomes a
// result of its own, so one bad command cannot end the whole replay. timeout 0 means no limit.
func runReplayItem(cmd string, timeout time.Duration, run func(string) (stdout, stderr string)) (class, detail string) {
	type outcome struct {
		out      string
		panicked bool
	}
	done := make(chan outcome, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- outcome{panicked: true}
			}
		}()
		stdout, stderr := run(cmd)
		done <- outcome{out: stdout + "\n" + stderr}
	}()
	var limit <-chan time.Time
	if timeout > 0 {
		limit = time.After(timeout)
	}
	select {
	case o := <-done:
		if o.panicked {
			return "crash", ""
		}
		return classifyReplay(o.out)
	case <-limit:
		return "timeout", ""
	}
}

func runReplay(items []replayItem) []replayResult {
	out := make([]replayResult, len(items))
	for i, it := range items {
		class, detail := runReplayItem(it.Cmd, 10*time.Second, func(c string) (string, string) {
			stdout, stderr, _, _ := NewMachine(Ubuntu).NewInterpreter("root").RunExec(c)
			return stdout, stderr
		})
		out[i] = replayResult{class, detail}
	}
	return out
}

type replaySummary struct {
	Commands, Sessions int
	BySessions         map[string]int
}

// selfTestMarker identifies the botnet's honeypot self-test payload, in every variant seen.
const selfTestMarker = "===SHELL_BEHAVIOR==="

func isSelfTest(it replayItem) bool { return strings.Contains(it.Cmd, selfTestMarker) }

func summarizeReplay(items []replayItem, results []replayResult) replaySummary {
	return summarizeReplayWhere(items, results, func(replayItem) bool { return true })
}

func summarizeReplayWhere(items []replayItem, results []replayResult, keep func(replayItem) bool) replaySummary {
	s := replaySummary{BySessions: map[string]int{}}
	for i, it := range items {
		if !keep(it) {
			continue
		}
		s.Commands++
		s.Sessions += it.Sessions
		s.BySessions[results[i].Class] += it.Sessions
	}
	return s
}

func (s replaySummary) OKPercent() float64 {
	if s.Sessions == 0 {
		return 0
	}
	return 100 * float64(s.BySessions["ok"]) / float64(s.Sessions)
}

// TestReplayCorpus replays a JSONL corpus of {"sessions": N, "cmd": "..."} through the simulated
// shell, which has no os/exec, network or real-filesystem access. Skipped unless MIRAGE_REPLAY_FILE
// is set; see `make replay`. MIRAGE_REPLAY_OUT, if set, receives one TSV row per command.
func TestReplayCorpus(t *testing.T) {
	path := os.Getenv("MIRAGE_REPLAY_FILE")
	if path == "" {
		t.Skip("set MIRAGE_REPLAY_FILE to a JSONL corpus (scripts/export_replay_commands.py) to run the replay")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var items []replayItem
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		if len(strings.TrimSpace(sc.Text())) == 0 {
			continue
		}
		var it replayItem
		if err := json.Unmarshal(sc.Bytes(), &it); err != nil {
			t.Fatalf("bad corpus line: %v", err)
		}
		items = append(items, it)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	results := runReplay(items)
	s := summarizeReplay(items, results)

	if outPath := os.Getenv("MIRAGE_REPLAY_OUT"); outPath != "" {
		var b strings.Builder
		for i, it := range items {
			fmt.Fprintf(&b, "%d\t%s\t%s\t%s\n", it.Sessions, results[i].Class, results[i].Detail, strings.ReplaceAll(it.Cmd, "\n", "⏎"))
		}
		if err := os.WriteFile(outPath, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Println(replayLine("REPLAY             ", s))
	fmt.Println(replayLine("REPLAY no-self-test", summarizeReplayWhere(items, results, func(it replayItem) bool { return !isSelfTest(it) })))
}

func replayLine(label string, s replaySummary) string {
	classes := make([]string, 0, len(s.BySessions))
	for c := range s.BySessions {
		classes = append(classes, c)
	}
	sort.Slice(classes, func(i, j int) bool { return s.BySessions[classes[i]] > s.BySessions[classes[j]] })
	var parts []string
	for _, c := range classes {
		parts = append(parts, fmt.Sprintf("%s=%d", c, s.BySessions[c]))
	}
	return fmt.Sprintf("%s commands=%d sessions=%d ok=%.1f%% (%s)", label, s.Commands, s.Sessions, s.OKPercent(), strings.Join(parts, " "))
}
