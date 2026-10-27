package shell

import (
	"testing"
)

// Differential tests against a real Ubuntu 22.04 host.
//
// Each case is a command run as `bash -c <cmd>` in a fresh ubuntu:22.04
// container (bash 5.1.16, GNU coreutils 8.32, grep 3.7, sed 4.8, mawk 1.3.4,
// root, cwd /root, no network), with stdout, stderr and exit status recorded.
// RunExec must reproduce all three byte for byte, which is how sshd runs an
// exec request. The expected values were copied from those runs, not typed.
// Regenerate with the container image, never by editing a value to fit.

type ubuntuCase struct {
	cmd, stdout, stderr string
	code                int
}

var ubuntu2204Cases = []ubuntuCase{
	{"printf 'a\\n'", "a\n", "", 0},
	{"x=$(printf 'a\\n'); echo \"[$x]\"", "[a]\n", "", 0},
	{"printf '%s' abc | head -c 2", "ab", "", 0},
	{"./xxxxxx", "", "bash: line 1: ./xxxxxx: No such file or directory\n", 127},
	{"xxxxxx", "", "bash: line 1: xxxxxx: command not found\n", 127},
	{"./xxxxxx 2>&1", "bash: line 1: ./xxxxxx: No such file or directory\n", "", 127},
	{"( ./xxxxxx 2>&1 || true ) | ( head -c 250 2>/dev/null || cat ) | ( tr -d '\\n' 2>/dev/null || cat )", "bash: line 1: ./xxxxxx: No such file or directory", "", 0},
	{"r=$( ( ./xxxxxx 2>&1 || true ) | tr -d '\\n' ); echo \"[$r]\"", "[bash: line 1: ./xxxxxx: No such file or directory]\n", "", 0},
	{"r=$( ( xxxxxx 2>&1 || true ) | tr -d '\\n' ); echo \"[$r]\"", "[bash: line 1: xxxxxx: command not found]\n", "", 0},
	{"out=$(bash -c 'printf \"#!/bin/bash\\necho \\\"xxxxxx\\\"\\n\" > filter && chmod +x filter && ./filter && rm -rf filter' 2>&1); echo \"[$out]\"", "[xxxxxx]\n", "", 0},
	{"printf '#!/bin/bash\\necho hi\\n' > f1 && chmod +x f1 && ./f1; rm -f f1", "hi\n", "", 0},
	{"echo abc:def:ghi | cut -d: -f1", "abc\n", "", 0},
	{"echo abc:def:ghi | cut -d: -f2,3", "def:ghi\n", "", 0},
	{"echo abcdef | cut -c2-4", "bcd\n", "", 0},
	{"echo hello | tr a-z A-Z", "HELLO\n", "", 0},
	{"echo 'a b c' | tr -d ' '", "abc\n", "", 0},
	{"printf 'a\\nb\\n' | tr -d '\\n'", "ab", "", 0},
	{"printf 'aab\\n' | tr -s a", "ab\n", "", 0},
	{"printf 'b\\na\\nc\\n' | sort", "a\nb\nc\n", "", 0},
	{"printf 'b\\na\\nc\\n' | sort -r", "c\nb\na\n", "", 0},
	{"printf '10\\n9\\n100\\n' | sort -n", "9\n10\n100\n", "", 0},
	{"printf 'a\\nb\\na\\n' | sort -u", "a\nb\n", "", 0},
	{"echo 'a,b,c' | sed 's/,//g'", "abc\n", "", 0},
	{"echo hello | sed 's/l/L/'", "heLlo\n", "", 0},
	{"echo hello | sed 's/l/L/g'", "heLLo\n", "", 0},
	{"printf 'a\\n\\nb\\n' | sed '/^$/d'", "a\nb\n", "", 0},
	{"printf 'a\\nb\\nc\\n' | sed -n '2p'", "b\n", "", 0},
	{"echo '  lead' | sed 's/^[[:space:]]*//'", "lead\n", "", 0},
	{"echo 'trail  ' | sed 's/[[:space:]]*$//'", "trail\n", "", 0},
	{"echo 'x AArch64 Processor' | sed 's/ AArch64 Processor$//'", "x\n", "", 0},
	{"echo abc | egrep 'a|z'", "abc\n", "", 0},
	{"echo abc | grep -m1 -E 'b|z'", "abc\n", "", 0},
	{"echo abc | grep -q b && echo yes", "yes\n", "", 0},
	{"printf 'a\\nb\\n' | head -n 1", "a\n", "", 0},
	{"printf 'a\\nb\\n' | tail -n 1", "b\n", "", 0},
	{"printf 'x\\n' | wc -l", "1\n", "", 0},
	{"echo \"a b\" | awk '{print $2}'", "b\n", "", 0},
	{"echo \"Model name:  Foo CPU\" | awk -F: '/Model name/ {print $2}'", "  Foo CPU\n", "", 0},
	{"echo \"  v  \" | awk '{gsub(/^[ \\t]+/,\"\",$0); print}'", "v  \n", "", 0},
	{"true && echo t || echo f", "t\n", "", 0},
	{"false || echo f2", "f2\n", "", 0},
	{"[ -f /nonexistent ] && echo yes || echo no", "no\n", "", 0},
	{"cat /nonexistent", "", "cat: /nonexistent: No such file or directory\n", 1},
	{"ls /nonexistent", "", "ls: cannot access '/nonexistent': No such file or directory\n", 2},
	{"echo \"up 3 days, 2 hours\" | grep -ohe 'up .*' | sed 's/,//g' | awk '{ print $2\" \"$3 }'", "3 days\n", "", 0},
	{"echo x86_64 | tr -d '\\n'", "x86_64", "", 0},
	{"printf 'a b\\n' | cut -d' ' -f2", "b\n", "", 0},
	{"echo 'Intel(R) Xeon(R) CPU' | sed 's/ CPU$//'", "Intel(R) Xeon(R)\n", "", 0},
	{"echo abc | grep -c b", "1\n", "", 0},
	{"echo abc | grep -o 'b.'", "bc\n", "", 0},
	{"echo ABC | grep -i abc", "ABC\n", "", 0},
	{"printf 'a\\nb\\n' | grep -v a", "b\n", "", 0},
	{"echo abc | grep -w abc", "abc\n", "", 0},
	{"echo 'abc def' | grep -w abc", "abc def\n", "", 0},
	{"echo abc | grep -x abc", "abc\n", "", 0},
	{"printf '3\\n1\\n2\\n' | sort -n | head -n1", "1\n", "", 0},
	{"echo \"a=1;b=2\" | tr ';' '\\n' | cut -d= -f2", "1\n2\n", "", 0},
	{"echo ' x ' | sed -e 's/^ *//' -e 's/ *$//'", "x\n", "", 0},
	{"echo hello | sed 's/\\(h\\)\\(e\\)/\\2\\1/'", "ehllo\n", "", 0},
	{"echo aaa | sed 's/a/b/2'", "aba\n", "", 0},
	{"printf 'one\\ntwo\\nthree\\n' | sed -n '2,3p'", "two\nthree\n", "", 0},
	{"printf 'one\\ntwo\\nthree\\n' | sed '$d'", "one\ntwo\n", "", 0},
	{"printf 'one\\ntwo\\nthree\\n' | sed '1d'", "two\nthree\n", "", 0},
	{"printf 'k=v\\n' | sed 's/=/ -> /'", "k -> v\n", "", 0},
	{"echo path/to/file | sed 's#/#:#g'", "path:to:file\n", "", 0},
	{"echo hi # a comment", "hi\n", "", 0},
	{"# only a comment", "", "", 0},
	{"echo a#b", "a#b\n", "", 0},
	{"x=5; echo ${#x}", "1\n", "", 0},
	{"echo \"$(echo \"nested $(echo deep)\")\"", "nested deep\n", "", 0},
	{"[ -z \"\" ] && echo empty", "empty\n", "", 0},
	{"[ 1 -lt 2 ] && echo lt", "lt\n", "", 0},
	{"for i in 1 2 3; do printf \"$i,\"; done; echo", "1,2,3,\n", "", 0},
	{"x=$(echo a; echo b); echo \"$x\"", "a\nb\n", "", 0},
	{"command -v nosuchcmd || echo missing", "missing\n", "", 0},
	{"nosuchcmd; echo $?", "127\n", "bash: line 1: nosuchcmd: command not found\n", 0},
	{"ls /nonexistent 2>/dev/null; echo $?", "2\n", "", 0},
	{"cd /tmp && pwd", "/tmp\n", "", 0},
	{"mkdir -p /tmp/x1 && ls /tmp/x1; echo $?", "0\n", "", 0},
	{"touch f2 && ls f2", "f2\n", "", 0},
	{"echo hi > f3 && cat f3", "hi\n", "", 0},
	{"echo hi >> f4; echo yo >> f4; cat f4", "hi\nyo\n", "", 0},
	{"echo a | head -c 1", "a", "", 0},
	{"printf 'abcdef' | head -c 3", "abc", "", 0},
	{"printf 'abcdef' | tail -c 2", "ef", "", 0},
	{"echo abcdef | head -c 3; echo", "abc\n", "", 0},
	{"echo one two | awk '{print $2}'", "two\n", "", 0},
	{"echo one two | awk '{print NF}'", "2\n", "", 0},
	{"echo \"a:b\" | awk -F: '{print $2}'", "b\n", "", 0},
	{"echo 5 | awk '{print $1*2}'", "10\n", "", 0},
	{"uname -s", "Linux\n", "", 0},
	{"uname -m", "x86_64\n", "", 0},
	{"id -u", "0\n", "", 0},
	{"whoami", "root\n", "", 0},
	{"pwd", "/root\n", "", 0},
	{"echo $((1+2))", "3\n", "", 0},
	{"echo hello | wc -c", "6\n", "", 0},
	{"printf 'a\\nb\\nc\\n' | wc -l", "3\n", "", 0},
	{"printf 'a\\nb\\n' | tail -n 1", "b\n", "", 0},
	{"printf 'x y z\\n' | awk '{print $NF}'", "z\n", "", 0},
	{"true; echo $?", "0\n", "", 0},
	{"false; echo $?", "1\n", "", 0},
	{"echo \"$(printf 'a\\n')b\"", "ab\n", "", 0},
	{"echo 'single $HOME' \"double $HOME\"", "single $HOME double /root\n", "", 0},
	{"printf '%s\\n' a b c", "a\nb\nc\n", "", 0},
	{"printf '%d %s\\n' 5 x", "5 x\n", "", 0},
	{"printf 'a\\tb\\n'", "a\tb\n", "", 0},
	{"echo -e 'a\\tb'", "a\tb\n", "", 0},
	{"echo -n hi; echo", "hi\n", "", 0},
	{"cat /nonexistent 2>&1", "cat: /nonexistent: No such file or directory\n", "", 1},
	{"cat /nonexistent 2>/dev/null; echo \"rc=$?\"", "rc=1\n", "", 0},
	{"ls /nope 2>&1 | head -n1", "ls: cannot access '/nope': No such file or directory\n", "", 0},
	{"for i in 1 2 3; do [ $i = 2 ] && break; echo $i; done", "1\n", "", 0},
	{"for i in 1 2 3; do [ $i = 2 ] && continue; echo $i; done", "1\n3\n", "", 0},
	{"i=0; while true; do i=$((i+1)); [ $i -ge 3 ] && break; done; echo $i", "3\n", "", 0},
	{"for a in x y; do for b in 1 2; do [ $b = 2 ] && break; echo $a$b; done; done", "x1\ny1\n", "", 0},
	{"sh -c 'for d in /nonexistent /tmp; do cd \"$d\" 2>/dev/null && break; done; pwd'", "/tmp\n", "", 0},
	{"readlink -f /bin/sh", "/usr/bin/dash\n", "", 0},
	{"readlink -f /bin", "/usr/bin\n", "", 0},
	{"readlink /bin", "usr/bin\n", "", 0},
	{"readlink /etc/passwd; echo $?", "1\n", "", 0},
	{"chattr +i /nonexistent_file; echo $?", "1\n", "chattr: No such file or directory while trying to stat /nonexistent_file\n", 0},
	{"chattr -ia /root; echo $?", "0\n", "", 0},
	{"uptime | grep -c 'load average'", "1\n", "", 0},
	{"uptime -p | grep -c '^up '", "1\n", "", 0},
	{"echo; echo a; echo", "\na\n\n", "", 0},
	{"echo $((2*3+1))", "7\n", "", 0},
	{"echo $(( (1+2)*3 ))", "9\n", "", 0},
	{"echo $((10/3))", "3\n", "", 0},
	{"echo $((10%3))", "1\n", "", 0},
	{"echo $((-5+2))", "-3\n", "", 0},
	{"x=4; echo $((x*2))", "8\n", "", 0},
	{"echo $((1<2))", "1\n", "", 0},
	{"command -v echo >/dev/null && echo has", "has\n", "", 0},
	{"command -v nosuchcmd; echo $?", "1\n", "", 0},
	{"echo \"a  b   c\" | awk '{gsub(/ +/,\" \"); print}'", "a b c\n", "", 0},
	{"echo \"foo bar\" | awk '{sub(/o+/,\"0\"); print}'", "f0 bar\n", "", 0},
	{"echo \"foo\" | awk '{n=gsub(/o/,\"0\"); print n, $0}'", "2 f00\n", "", 0},
	{"echo \"x y\" | awk '{gsub(/x/,\"[&]\",$1); print}'", "[x] y\n", "", 0},
	{"uname -m | awk '{printf $1}'", "x86_64", "", 0},
	{"echo abc | tr a-c A-C | cat", "ABC\n", "", 0},
	{"printf 'a\\nb\\n' | cat | wc -l", "2\n", "", 0},
	{"echo hi | more", "hi\n", "", 0},
	{"x=$(echo); echo \"[$x]\"", "[]\n", "", 0},
	{"x=$(echo hi; echo); echo \"[$x]\"", "[hi]\n", "", 0},
}

func TestMatchesUbuntu2204(t *testing.T) {
	for _, tc := range ubuntu2204Cases {
		stdout, stderr, code, _ := NewMachine(Ubuntu).NewInterpreter("root").RunExec(tc.cmd)
		if stdout != tc.stdout || stderr != tc.stderr || code != tc.code {
			t.Errorf("%q\n got  stdout=%q stderr=%q code=%d\n want stdout=%q stderr=%q code=%d", tc.cmd, stdout, stderr, code, tc.stdout, tc.stderr, tc.code)
		}
	}
}

// Known gaps: measured on the same container, not yet matched.
var ubuntu2204KnownGaps = []ubuntuCase{
	{"echo \"a b\" | while read x y; do echo \"$y $x\"; done", "b a\n", "", 0},
}

func TestKnownUbuntu2204Gaps(t *testing.T) {
	for _, tc := range ubuntu2204KnownGaps {
		stdout, stderr, code, _ := NewMachine(Ubuntu).NewInterpreter("root").RunExec(tc.cmd)
		if stdout == tc.stdout && stderr == tc.stderr && code == tc.code {
			t.Errorf("%q now matches Ubuntu: move it to ubuntu2204Cases", tc.cmd)
		}
	}
}
