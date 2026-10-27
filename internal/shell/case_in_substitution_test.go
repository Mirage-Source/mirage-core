package shell

import (
	"strings"
	"testing"
)

// A case pattern's closing `)` is not the end of a surrounding `$(` or `( )`.
// Before this was fixed, splitStatements counted that `)` as closing the
// substitution, so the `;;` that follows was split off as a top-level
// separator and the line failed with "syntax error near unexpected token
// `;;'". Botnet host fingerprinting payloads nest case inside $( ), so the
// sensor answered them with a syntax error that bash would never print.
//
// Expected values measured with GNU bash 5.3.20 (`bash -c '<cmd>'`).
func TestCaseNestedInSubstitutionAndSubshell(t *testing.T) {
	for _, tc := range []struct{ name, cmd, want string }{
		{"assignment", `x=$(case a in a) echo sub;; esac); echo $x`, "sub"},
		{"second branch", `echo $(case b in a) echo A;; b) echo B;; esac)`, "B"},
		{"alternation", `echo $(case b in a|b) echo AB;; *) echo no;; esac)`, "AB"},
		{"nested substitutions", `echo $(echo $(case a in a) echo deep;; esac))`, "deep"},
		{"subshell", `(case a in a) echo sh;; esac)`, "sh"},
		{"quoted paren in substitution", `echo $(echo ")")`, ")"},
		{"empty branch then fallthrough", `r=$( ( out=abc; case "$out" in *abc*) ;; *) out=2;; esac; echo "[$out]" ) 2>&1 ); echo "$r"`, "[abc]"},
		{"case inside case inside substitution", `r=$( ( case x in x) case y in y) echo inner;; esac;; esac ) ); echo "$r"`, "inner"},
		{"command after the substitution", `echo $(case z in a) echo A;; *) echo star;; esac) done`, "star done"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, _, _ := NewInterpreter("root").Run(tc.cmd)
			got := strings.TrimRight(strings.ReplaceAll(out, "\r", ""), "\n")
			if got != tc.want {
				t.Errorf("%s\n got  %q\n want %q", tc.cmd, got, tc.want)
			}
		})
	}
}

// Plain top-level case and unbalanced input must keep behaving as before.
func TestCaseFixKeepsExistingBehaviour(t *testing.T) {
	for _, tc := range []struct{ cmd, want string }{
		{`case a in a) echo one;; esac`, "one"},
		{`x=a; case "$x" in a) echo matched;; *) echo no;; esac`, "matched"},
		{"case a in\n a) echo multi;;\n esac", "multi"},
		{`if true; then echo ok; fi`, "ok"},
		{`echo $(echo plain)`, "plain"},
	} {
		out, _, _ := NewInterpreter("root").Run(tc.cmd)
		if got := strings.TrimRight(strings.ReplaceAll(out, "\r", ""), "\n"); got != tc.want {
			t.Errorf("%q\n got  %q\n want %q", tc.cmd, got, tc.want)
		}
	}
}
