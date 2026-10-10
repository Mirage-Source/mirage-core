package shell

import (
	"strings"
	"testing"
)

func run(t *testing.T, s *Interpreter, line string) (string, int) {
	t.Helper()
	out, code, _ := s.Run(line)
	return out, code
}

func TestAbsoluteAndPrefixedCommandsResolve(t *testing.T) {
	s := NewInterpreter("root")
	for _, line := range []string{"/bin/uname -s", "/usr/bin/uname -s", "/bin/./uname -s", "LC_ALL=C uname -s", "FOO=1 BAR=2 /bin/uname -s"} {
		if out, code := run(t, s, line); out != "Linux" || code != 0 {
			t.Errorf("%q = %q %d, want Linux 0", line, out, code)
		}
	}
	if out, code := run(t, s, "/usr/bin/nosuchtool"); out != "bash: /usr/bin/nosuchtool: No such file or directory" || code != 127 {
		t.Errorf("missing bin path = %q %d", out, code)
	}
}

func TestExecutingAFileByPath(t *testing.T) {
	s := NewInterpreter("root")
	run(t, s, "cd /tmp")
	if out, code := run(t, s, "./x"); out != "bash: ./x: No such file or directory" || code != 127 {
		t.Errorf("missing = %q %d", out, code)
	}
	run(t, s, "touch x")
	if out, code := run(t, s, "./x"); out != "bash: ./x: Permission denied" || code != 126 {
		t.Errorf("not executable = %q %d", out, code)
	}
	run(t, s, "chmod +x x")
	if out, code := run(t, s, "./x"); out != "" || code != 0 {
		t.Errorf("executable empty file = %q %d", out, code)
	}
	run(t, s, "echo 'echo from-script' > y; chmod 755 y")
	if out, code := run(t, s, "/tmp/y"); out != "from-script" || code != 0 {
		t.Errorf("script = %q %d", out, code)
	}
	if out, code := run(t, s, "/tmp"); out != "bash: /tmp: Is a directory" || code != 126 {
		t.Errorf("dir = %q %d", out, code)
	}
}

func TestSelfExecutingScriptTerminates(t *testing.T) {
	s := NewInterpreter("root")
	run(t, s, "echo /tmp/loop > /tmp/loop; chmod 777 /tmp/loop")
	if _, code := run(t, s, "/tmp/loop"); code != 0 {
		t.Errorf("code = %d", code)
	}
}

func TestChmod(t *testing.T) {
	s := NewInterpreter("root")
	run(t, s, "touch /tmp/a")
	run(t, s, "chmod 777 /tmp/a")
	if out, _ := run(t, s, "ls -l /tmp"); !strings.Contains(out, "-rwxrwxrwx") {
		t.Errorf("ls after chmod 777 = %q", out)
	}
	run(t, s, "chmod 644 /tmp/a; chmod +x /tmp/a")
	if out, _ := run(t, s, "ls -l /tmp"); !strings.Contains(out, "-rwxr-xr-x") {
		t.Errorf("ls after +x = %q", out)
	}
	if out, code := run(t, s, "chmod 777 /tmp/nope"); out != "chmod: cannot access '/tmp/nope': No such file or directory" || code != 1 {
		t.Errorf("missing = %q %d", out, code)
	}
	if out, code := run(t, s, "chmod 777"); out != "chmod: missing operand after '777'" || code != 1 {
		t.Errorf("no operand = %q %d", out, code)
	}
}

func TestRm(t *testing.T) {
	s := NewInterpreter("root")
	run(t, s, "touch /tmp/a")
	if out, code := run(t, s, "rm /tmp/a"); out != "" || code != 0 {
		t.Errorf("rm = %q %d", out, code)
	}
	if out, _ := run(t, s, "ls /tmp"); strings.Contains(out, "a") {
		t.Errorf("file still listed: %q", out)
	}
	if out, code := run(t, s, "rm /tmp/a"); out != "rm: cannot remove '/tmp/a': No such file or directory" || code != 1 {
		t.Errorf("rm missing = %q %d", out, code)
	}
	if out, code := run(t, s, "rm -rf /tmp/a /tmp/b"); out != "" || code != 0 {
		t.Errorf("rm -rf missing = %q %d", out, code)
	}
	if out, code := run(t, s, "rm /tmp"); out != "rm: cannot remove '/tmp': Is a directory" || code != 1 {
		t.Errorf("rm dir = %q %d", out, code)
	}
	run(t, s, "rm -f /etc/hostname")
	if _, code := run(t, s, "cat /etc/hostname"); code == 0 {
		t.Error("base file still readable after rm")
	}
	run(t, s, "touch /etc/hostname")
	if out, _ := run(t, s, "ls /etc"); strings.Count(out, "hostname") != 1 {
		t.Errorf("recreated file listed %d times", strings.Count(out, "hostname"))
	}
}

func TestMkdirTouchCpMv(t *testing.T) {
	s := NewInterpreter("root")
	if out, code := run(t, s, "mkdir /tmp/a/b"); out != "mkdir: cannot create directory '/tmp/a/b': No such file or directory" || code != 1 {
		t.Errorf("mkdir no parent = %q %d", out, code)
	}
	run(t, s, "mkdir -p /tmp/a/b")
	if _, code := run(t, s, "cd /tmp/a/b"); code != 0 {
		t.Fatal("cd into mkdir -p dir failed")
	}
	if out, code := run(t, s, "mkdir /tmp/a"); out != "mkdir: cannot create directory '/tmp/a': File exists" || code != 1 {
		t.Errorf("mkdir exists = %q %d", out, code)
	}
	run(t, s, "echo hi > f; cp f g; mv g h")
	if out, _ := run(t, s, "cat h"); strings.TrimSpace(out) != "hi" {
		t.Errorf("cat after cp+mv = %q", out)
	}
	if _, code := run(t, s, "cat g"); code == 0 {
		t.Error("mv left source behind")
	}
	if out, _ := run(t, s, "ls"); out != "f  h" {
		t.Errorf("ls = %q", out)
	}
	if out, code := run(t, s, "cp nope x"); out != "cp: cannot stat 'nope': No such file or directory" || code != 1 {
		t.Errorf("cp missing = %q %d", out, code)
	}
	if out, code := run(t, s, "chown root:root h"); out != "" || code != 0 {
		t.Errorf("chown = %q %d", out, code)
	}
}
