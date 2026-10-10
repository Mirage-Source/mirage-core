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
