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

	// allRoot: every login is uid 0 with home dir home, as on embedded devices.
	allRoot bool
	home    string
	busybox bool
	// busyboxBanner replaces the first line of `busybox` usage output.
	busyboxBanner string
	prompt        func(s *Interpreter) string
	ps            func(s *Interpreter) string // nil: the Ubuntu ps table
	// writable lists the mount points that accept writes; nil means the
	// whole tree is writable. Everything else is a read-only rootfs.
	writable []string

	// loginEnv is the environment a new process starts with (nil: none).
	loginEnv func(user, home string) map[string]string
}

// ubuntuPath is Ubuntu 22.04's /etc/environment PATH, as sshd hands it out.
const ubuntuPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"

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
		cdMissing:   "bash: cd: %s: No such file or directory",
	},
	// Measured on 8.9p1 for an exec session; the server adds SSH_CLIENT and
	// SSH_CONNECTION, and RunExec sets SHLVL to 0.
	loginEnv: func(user, home string) map[string]string {
		return map[string]string{
			"HOME": home, "LOGNAME": user, "USER": user, "PWD": home,
			"PATH": ubuntuPath, "SHELL": "/bin/bash", "SHLVL": "1",
			"LANG": "C.UTF-8", "MOTD_SHOWN": "pam",
		}
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
	createRO                                   string
	cdMissing                                  string
}

// readOnly reports whether clean lies on the profile's read-only rootfs.
func (s *Interpreter) readOnly(clean string) bool {
	if s.profile.writable == nil {
		return false
	}
	for _, w := range s.profile.writable {
		if clean == w || strings.HasPrefix(clean, w+"/") {
			return false
		}
	}
	return true
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
