package shell

import (
	"regexp"
	"strings"
)

const perlVersion = `
This is perl 5, version 34, subversion 0 (v5.34.0) built for x86_64-linux-gnu-thread-multi
(with 60 registered patches, see perl -V for more detail)

Copyright 1987-2021, Larry Wall

Perl may be copied only under the terms of either the Artistic License or the
GNU General Public License, which may be found in the Perl 5 source kit.

Complete documentation for Perl, including FAQ lists, should be found on
this system using "man perl" or "perldoc perl".  If you have access to the
Internet, point your browser at http://www.perl.org/, the Perl Home Page.`

var perlPrint = regexp.MustCompile(`^\s*print\s*\(?\s*(?:"([^"$@\\]*(?:\\n[^"$@\\]*)*)"|'([^']*)'|(\d+))\s*\)?\s*;?\s*$`)

// perlBuiltin never runs Perl. It answers -v, missing scripts and a lone
// print of a literal; any other code exits 0 with no output.
func (s *Interpreter) perlBuiltin(args []string) (string, int) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-v" || a == "--version":
			return strings.ReplaceAll(perlVersion, "\n", "\r\n"), 0
		case a == "-e" || a == "-E":
			if i+1 >= len(args) {
				return "No code specified for " + a + ".", 25
			}
			return perlEval(args[i+1]), 0
		case strings.HasPrefix(a, "-"):
		default:
			if _, n := s.lookup(a); n == nil || n.Type != NodeFile {
				return `Can't open perl script "` + a + `": No such file or directory`, 2
			}
			return "", 0
		}
	}
	return "", 0
}

func perlEval(code string) string {
	m := perlPrint.FindStringSubmatch(code)
	if m == nil {
		return ""
	}
	out := m[1] + m[2] + m[3]
	if m[1] != "" {
		out = strings.ReplaceAll(out, `\n`, "\n")
	}
	return strings.ReplaceAll(strings.TrimRight(out, "\n"), "\n", "\r\n")
}
