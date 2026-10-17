package shell

import "testing"

// Expected outputs from mawk 1.3.4 20200120 (Ubuntu 22.04's awk) on the
// same input.
func TestAwkMatchesMawk(t *testing.T) {
	const in = "a b c\n1 2 3\n  x   y  \nlast line here\n"
	for _, tc := range []struct{ prog, want string }{
		{"{print $1}", "a\n1\nx\nlast\n"},
		{"{print $2,$1}", "b a\n2 1\ny x\nline last\n"},
		{"{print $NF}", "c\n3\ny\nhere\n"},
		{"NR==2", "1 2 3\n"},
		{"FNR == 2 {print $2;}", "2\n"},
		{`/x/{print NR": "$0}`, "3:   x   y  \n"},
		{"{s+=$1} END {print s}", "1\n"},
		{"{print NF}", "3\n3\n2\n3\n"},
		{"END{print NR}", "4\n"},
		{"{print $4,$5,$6,$7,$8,$9;}", "     \n     \n     \n     \n"},
		{"{print $1 $2}", "ab\n12\nxy\nlastline\n"},
		{"NR>2{print}", "  x   y  \nlast line here\n"},
		{"!/a/", "1 2 3\n  x   y  \n"},
		{"{print length($0)}", "5\n5\n9\n14\n"},
		{`BEGIN{print "hi"}`, "hi\n"},
		{"{print toupper($1)}", "A\n1\nX\nLAST\n"},
		{`$1 == "1" {print $3 * 2, $2 + 0.5}`, "6 2.5\n"},
		{`{printf "%s-%d\n", $1, NR}`, "a-1\n1-2\nx-3\nlast-4\n"},
		{"NR==1 || NR==4 {print substr($0, 2, 3)}", " b \nast\n"},
	} {
		p := NewMachine(Ubuntu).NewInterpreter("root")
		p.RunExec("printf '" + in + "' > /tmp/in")
		got, errOut, code, _ := p.RunExec("awk '" + tc.prog + "' /tmp/in")
		if got != tc.want || code != 0 {
			t.Errorf("awk %s:\n got  %q (err %q, exit %d)\n want %q", tc.prog, got, errOut, code, tc.want)
		}
	}
}

func TestAwkFieldSeparatorAndErrors(t *testing.T) {
	p := NewMachine(Ubuntu).NewInterpreter("root")
	for _, tc := range []struct {
		cmd, stdout, stderr string
		code                int
	}{
		{"awk -F: '$3>=1000{print $1}' /etc/passwd", "nobody\nubuntu\n", "", 0},
		{`awk -F":" '/^root/{print $7}' /etc/passwd`, "/bin/bash\n", "", 0},
		{"awk -F: '{print $1}' /etc/passwd | head -2", "root\ndaemon\n", "", 0},
		{"awk '/^MemTotal:/{print $2}' /proc/meminfo", "980300\n", "", 0},
		{"awk '{print}' /nope", "", "awk: cannot open /nope (No such file or directory)\n", 2},
		{"awk '{print $1' /etc/hostname", "", "awk: line 2: missing } near end of file\n", 2},
		{"echo 5 7 | awk '{print $1+$2}'", "12\n", "", 0},
	} {
		out, errOut, code, _ := p.Machine.NewInterpreter("root").RunExec(tc.cmd)
		if out != tc.stdout || errOut != tc.stderr || code != tc.code {
			t.Errorf("%s:\n got  out=%q err=%q code=%d\n want out=%q err=%q code=%d", tc.cmd, out, errOut, code, tc.stdout, tc.stderr, tc.code)
		}
	}
}
