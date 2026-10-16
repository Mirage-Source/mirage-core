package shell

import (
	"fmt"
	"strings"
)

// Profile is the machine a session claims to be. Everything that would
// contradict another sensor's identity -- the filesystem tree, kernel and
// architecture, hostname, prompt and the shell's own error wording -- lives
// here, so SSH (an Ubuntu cloud server) and telnet (an embedded DVR) each
// stay self-consistent without per-command special cases.
type Profile struct {
	fs       map[string]*Node
	hostname func() string

	sysname, release, version, machine string
	// BusyBox uname -a prints no processor or hardware-platform fields.
	busyboxUname bool

	msgs shellMsgs

	// allRoot: every login is uid 0 with home /, as on embedded devices.
	allRoot bool
	busybox bool
	prompt  func(s *Interpreter) string
}

// Ubuntu is the SSH sensor's identity: an Ubuntu 22.04 EC2 instance.
var Ubuntu = &Profile{
	fs:       fs,
	hostname: randomHostname,
	sysname:  "Linux",
	release:  "5.15.0-1031-aws",
	version:  "#35-Ubuntu SMP Fri Feb 10 02:07:19 UTC 2023",
	machine:  "x86_64",
	msgs: shellMsgs{
		notFound:    "bash: %s: command not found",
		execMissing: "bash: %s: No such file or directory",
		execIsDir:   "bash: %s: Is a directory",
		execPerm:    "bash: %s: Permission denied",
		createNoDir: "bash: %s: No such file or directory",
		createIsDir: "bash: %s: Is a directory",
		openMissing: "bash: %s: No such file or directory",
		syntaxEOF:   "bash: syntax error: unexpected end of file",
		syntaxToken: "bash: syntax error near unexpected token `%s'",
	},
	prompt: func(s *Interpreter) string {
		promptChar := "$"
		if s.Username == "root" {
			promptChar = "#"
		}
		return fmt.Sprintf("%s@%s:%s%s ", s.Username, s.Hostname, displayPath(s.Cwd, s.HomeDir), promptChar)
	},
}

// shellMsgs are the printf formats for errors the shell itself (not a
// command) reports; bash and BusyBox ash word every one of them differently.
type shellMsgs struct {
	notFound, execMissing, execIsDir, execPerm string
	createNoDir, createIsDir, openMissing      string
	syntaxEOF, syntaxToken                     string
}

func (s *Interpreter) shellMsg(format, arg string) string {
	if !strings.Contains(format, "%s") {
		return format
	}
	return fmt.Sprintf(format, arg)
}

func (s *Interpreter) syntaxMsg(e syntaxError) string {
	if e == "" {
		return s.profile.msgs.syntaxEOF
	}
	return s.shellMsg(s.profile.msgs.syntaxToken, string(e))
}
