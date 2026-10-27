package shell

import (
	"regexp"
	"strings"
	"testing"
)

func exec(t *testing.T, cmd string) (string, string, int) {
	t.Helper()
	out, errOut, code, _ := NewMachine(Ubuntu).NewInterpreter("root").RunExec(cmd)
	return out, errOut, code
}

// uptime: procps-ng 3.3.17 format. The values depend on the clock, so the
// shape is what is pinned (the shape was checked against ubuntu:22.04).
func TestUptimeShape(t *testing.T) {
	out, _, code := exec(t, "uptime")
	re := regexp.MustCompile(`^ \d\d:\d\d:\d\d up (\d+ days?, +\d+:\d\d|\d+:\d\d|\d+ min),  \d+ users?,  load average: \d+\.\d\d, \d+\.\d\d, \d+\.\d\d\n$`)
	if code != 0 || !re.MatchString(out) {
		t.Errorf("uptime = %q (code %d)", out, code)
	}
	if out, _, _ := exec(t, "uptime -p"); !regexp.MustCompile(`^up (\d+ (week|day|hour|minute)s?(, )?)+\n$`).MatchString(out) {
		t.Errorf("uptime -p = %q", out)
	}
	if out, _, _ := exec(t, "uptime -s"); !regexp.MustCompile(`^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\n$`).MatchString(out) {
		t.Errorf("uptime -s = %q", out)
	}
}

// sudo as a user with passwordless sudo runs the command.
func TestSudoRunsTheCommand(t *testing.T) {
	for cmd, want := range map[string]string{
		"sudo echo hi":               "hi\n",
		"sudo -n echo hi":            "hi\n",
		"sudo -u root whoami":        "root\n",
		"sudo sh -c 'echo $((1+1))'": "2\n",
		"echo x | sudo tr x y":       "y\n",
		"sudo -- echo a b":           "a b\n",
	} {
		out, _, _ := exec(t, cmd)
		if want != "" && out != want {
			t.Errorf("%q = %q, want %q", cmd, out, want)
		}
	}
	if out, _, _ := exec(t, "sudo -l"); !strings.Contains(out, "(ALL : ALL) ALL") {
		t.Errorf("sudo -l = %q", out)
	}
}

// The self-test payload that botnets run against honeypots writes a script
// with printf, makes it executable and runs it. Each probe has to give bash's
// own answer; the three expected lines were measured on ubuntu:22.04.
func TestHoneypotSelfTestProbes(t *testing.T) {
	cmd := `printf 'path_err='; ( ./xxxxxx 2>&1 || true ) | ( head -c 250 2>/dev/null || cat ) | ( tr -d '\n' 2>/dev/null || cat ); printf '\n'; ` +
		`printf 'cmd_err='; ( xxxxxx 2>&1 || true ) | ( head -c 250 2>/dev/null || cat ) | ( tr -d '\n' 2>/dev/null || cat ); printf '\n'; ` +
		`printf 'execute_err='; out=$(bash -c 'printf "#!/bin/bash\necho \"xxxxxx\"\n" > filter && chmod +x filter && ./filter && rm -rf filter' 2>&1); ` +
		`printf '%s' "$out" | ( head -c 250 2>/dev/null || cat ) | ( tr -d '\n' 2>/dev/null || cat ); printf '\n'; echo '===DONE==='`
	want := "path_err=bash: line 1: ./xxxxxx: No such file or directory\n" +
		"cmd_err=bash: line 1: xxxxxx: command not found\n" +
		"execute_err=xxxxxx\n===DONE===\n"
	if out, errOut, _ := exec(t, cmd); out != want || errOut != "" {
		t.Errorf("self-test probes\n got  %q (stderr %q)\n want %q", out, errOut, want)
	}
}

func TestBreakAndContinueOutsideALoopDoNothing(t *testing.T) {
	if out, _, code := exec(t, "break; echo after"); out != "after\n" || code != 0 {
		t.Errorf("break outside a loop = %q (code %d)", out, code)
	}
}

func TestCommentsAreIgnored(t *testing.T) {
	for cmd, want := range map[string]string{
		"echo a # not this":                 "a\n",
		"# only a comment\necho b":          "b\n",
		"echo a#b":                          "a#b\n",
		"x=hello; echo ${#x}":               "5\n",
		"printf '#!/bin/sh\\n' | head -c 2": "#!",
	} {
		if out, _, _ := exec(t, cmd); out != want {
			t.Errorf("%q = %q, want %q", cmd, out, want)
		}
	}
}
