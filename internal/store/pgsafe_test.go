package store

import (
	"encoding/json"
	"testing"
	"unicode/utf8"
)

func TestPGTextDropsNULAndInvalidUTF8(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"A\x00B", "A�B"},
		{"\x7fELF\x01\x01\x01\x00\xb7", "\x7fELF\x01\x01\x01��"},
		{"héllo", "héllo"},
	}
	for _, c := range cases {
		got := pgText(c.in)
		if got != c.want {
			t.Errorf("pgText(%q) = %q, want %q", c.in, got, c.want)
		}
		if !utf8.ValidString(got) {
			t.Errorf("pgText(%q) is not valid UTF-8", c.in)
		}
	}
}

func TestPGJSONReplacesOnlyRealNULEscapes(t *testing.T) {
	// A literal backslash followed by "u0000" marshals to `\\u0000`; that is
	// text, not a NUL, and must survive untouched.
	in, _ := json.Marshal([]string{"A\x00B", `lit\u0000eral`})
	got := string(pgJSON(in))
	want := `["A�B","lit\\u0000eral"]`
	if got != want {
		t.Errorf("pgJSON = %s, want %s", got, want)
	}
	var back []string
	if err := json.Unmarshal([]byte(got), &back); err != nil {
		t.Fatalf("pgJSON output is not valid JSON: %v", err)
	}
	if back[1] != `lit\u0000eral` {
		t.Errorf("literal backslash text changed: %q", back[1])
	}
}

func TestPGArgsSanitizesStringsPointersAndJSON(t *testing.T) {
	s := "x\x00"
	var nilStr *string
	args := pgArgs([]any{"a\x00", &s, nilStr, []byte(`"\u0000"`), 42, nil})
	if args[0] != "a�" {
		t.Errorf("string arg = %q", args[0])
	}
	if p := args[1].(*string); *p != "x�" || s != "x\x00" {
		t.Errorf("*string arg = %q (original %q must be untouched)", *p, s)
	}
	if args[2].(*string) != nil {
		t.Errorf("nil *string should stay nil")
	}
	if string(args[3].([]byte)) != `"�"` {
		t.Errorf("[]byte arg = %s", args[3])
	}
	if args[4] != 42 || args[5] != nil {
		t.Errorf("non-text args changed: %v %v", args[4], args[5])
	}
}
