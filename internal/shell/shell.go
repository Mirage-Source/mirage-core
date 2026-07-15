// Package shell simulates just enough of an interactive Ubuntu bash session
// to survive real-world attacker recon: a single filesystem tree (fs.go)
// shared by every command, and a small tokenizer (tokenizer.go) that
// understands `;`/`&&`/`||` chaining, quoting, and one level of `$(...)`
// command substitution. It deliberately does not implement pipes, redirects,
// or real subshell execution — see the project's honeypot-hardening plan for
// why that line was drawn where it was.
package shell

import (
	"fmt"
	"log"
	"strings"

	"github.com/mirage-source/mirage-core/internal/session"
)

const homeDir = "/home/ubuntu"

// ExitRequested is the sentinel exit code returned when the attacker types
// `exit` — the caller (server.go) uses this to end the session.
const ExitRequested = 257

const maxSubstitutionDepth = 3

// Deception action names this package acts on. Duplicated from
// internal/deception's constants (not imported) because internal/deception
// already imports internal/shell for shell.ExitRequested -- importing the
// other way would cycle. Both sides are pinned to the same wire contract
// documented in internal/deception/client.go.
const (
	deceptionActionEnrich      = "ENRICH"
	deceptionActionSurfaceBait = "SURFACE_BAIT"
)

// BaitHit is reported when a command touches a planted lure so the caller
// can record it against the session.
type BaitHit struct {
	BaitID     string
	BaitType   session.BaitType
	AccessType session.AccessType
}

// Interpreter holds the state of one interactive session: its current
// working directory and any exported environment variables. Create one per
// SSH session and reuse it across commands so `cd` and `export` persist the
// way they would in a real shell.
type Interpreter struct {
	Cwd string
	Env map[string]string
}

func NewInterpreter() *Interpreter {
	return &Interpreter{Cwd: homeDir, Env: map[string]string{}}
}

// Prompt renders the current PS1-style prompt for this interpreter's cwd.
func (s *Interpreter) Prompt() string {
	return fmt.Sprintf("ubuntu@ip-172-31-14-52:%s$ ", displayPath(s.Cwd))
}

// Run executes one line of input (which may contain `;`/`&&`/`||`-chained
// statements) and returns the combined output, the exit code of the last
// statement that ran, and any bait interactions triggered along the way.
// Equivalent to RunWithDeception(line, "") -- no deception action applied.
func (s *Interpreter) Run(line string) (output string, code int, bait []BaitHit) {
	return s.RunWithDeception(line, "")
}

// RunWithDeception is Run, but threads a deception action ("ENRICH",
// "SURFACE_BAIT", or "" for none) into the parts of the filesystem (cat/ls)
// that can render richer or gated content for that action. Passing ""
// reproduces Run's exact output -- callers should only pass a real action
// when the deception policy is actually allowed to change output (see
// server.go's applyDeception).
func (s *Interpreter) RunWithDeception(line, action string) (output string, code int, bait []BaitHit) {
	out, code := s.evalLine(line, 0, &bait, action)
	return out, code, bait
}

func (s *Interpreter) evalLine(line string, depth int, bait *[]BaitHit, action string) (string, int) {
	stmts := splitStatements(line)

	var outputs []string
	lastExit := 0

	for i, st := range stmts {
		if i > 0 {
			switch st.Sep {
			case "&&":
				if lastExit != 0 {
					continue
				}
			case "||":
				if lastExit == 0 {
					continue
				}
			}
		}

		words := tokenizeWords(st.Text)
		resolved := make([]string, 0, len(words))
		for _, w := range words {
			resolved = append(resolved, s.substitute(w, depth, bait, action))
		}
		if len(resolved) == 0 {
			continue
		}

		// A statement made up entirely of NAME=value words (e.g. the very
		// common `uname=$(uname -a)` local-variable-assignment pattern) is
		// an assignment, not a command invocation.
		if isAssignmentOnly(resolved) {
			for _, w := range resolved {
				k, v, _ := strings.Cut(w, "=")
				s.Env[k] = v
			}
			lastExit = 0
			continue
		}

		out, code := s.execBuiltin(resolved[0], resolved[1:], bait, action)
		lastExit = code
		if out != "" {
			outputs = append(outputs, out)
		}
	}

	return strings.Join(outputs, "\r\n"), lastExit
}

// substitute resolves `$(...)` command substitutions and `$NAME`/`${NAME}`
// variable interpolation inside a single word. Command substitutions nested
// deeper than maxSubstitutionDepth collapse to an empty string rather than
// erroring, same as a real shell running out of patience would look like
// from the outside. Unset variables interpolate to "", matching bash.
func (s *Interpreter) substitute(word string, depth int, bait *[]BaitHit, action string) string {
	var out strings.Builder
	i := 0
	for i < len(word) {
		c := word[i]

		if c == '$' && i+1 < len(word) && word[i+1] == '(' {
			end := matchingParen(word, i+2)
			if end == -1 {
				out.WriteString(word[i:])
				break
			}
			inner := word[i+2 : end]
			var resolved string
			if depth+1 <= maxSubstitutionDepth {
				o, _ := s.evalLine(inner, depth+1, bait, action)
				resolved = strings.TrimRight(o, "\r\n")
			}
			out.WriteString(resolved)
			i = end + 1
			continue
		}

		if c == '$' && i+1 < len(word) && word[i+1] == '{' {
			closeIdx := strings.IndexByte(word[i+2:], '}')
			if closeIdx == -1 {
				out.WriteByte(c)
				i++
				continue
			}
			name := word[i+2 : i+2+closeIdx]
			out.WriteString(s.Env[name])
			i = i + 2 + closeIdx + 1
			continue
		}

		if c == '$' && i+1 < len(word) && isIdentStart(word[i+1]) {
			j := i + 1
			for j < len(word) && isIdentPart(word[j]) {
				j++
			}
			out.WriteString(s.Env[word[i+1:j]])
			i = j
			continue
		}

		out.WriteByte(c)
		i++
	}
	return out.String()
}

func isAssignmentOnly(words []string) bool {
	for _, w := range words {
		eq := strings.IndexByte(w, '=')
		if eq <= 0 || !isIdentStart(w[0]) {
			return false
		}
		for i := 1; i < eq; i++ {
			if !isIdentPart(w[i]) {
				return false
			}
		}
	}
	return true
}

func isIdentStart(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isIdentPart(b byte) bool {
	return isIdentStart(b) || (b >= '0' && b <= '9')
}

// matchingParen returns the index of the `)` matching the `(` implicitly
// opened just before pos (pos is the index right after "$("), or -1.
func matchingParen(s string, pos int) int {
	depth := 1
	for i := pos; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func (s *Interpreter) execBuiltin(cmd string, args []string, bait *[]BaitHit, action string) (string, int) {
	switch cmd {
	case "":
		return "", 0

	case "echo":
		return strings.Join(args, " "), 0

	case "whoami":
		return "ubuntu", 0

	case "pwd":
		return s.Cwd, 0

	case "hostname":
		return "ip-172-31-14-52", 0

	case "id":
		return "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),27(sudo)", 0

	case "uname":
		return unameOutput(args), 0

	case "export":
		for _, a := range args {
			if k, v, ok := strings.Cut(a, "="); ok {
				s.Env[k] = v
			}
		}
		return "", 0

	case "test", "[":
		return "", testBuiltin(s.Cwd, cmd, args)

	case "cat":
		return s.catBuiltin(args, bait, action)

	case "ls":
		return s.lsBuiltin(args, action)

	case "cd":
		return s.cdBuiltin(args)

	case "exit":
		return "", ExitRequested

	default:
		log.Printf("Unknown command: %s", cmd)
		return "bash: " + cmd + ": command not found", 127
	}
}

func unameOutput(args []string) string {
	const (
		sysname  = "Linux"
		nodename = "ip-172-31-14-52"
		release  = "5.15.0-1031-aws"
		version  = "#35-Ubuntu SMP Fri Feb 10 02:07:19 UTC 2023"
		machine  = "x86_64"
	)

	all := len(args) == 0
	want := map[string]bool{}
	for _, a := range args {
		switch a {
		case "-a", "--all":
			all = true
		case "-s", "--kernel-name":
			want["s"] = true
		case "-n", "--nodename":
			want["n"] = true
		case "-r", "--kernel-release":
			want["r"] = true
		case "-v", "--kernel-version":
			want["v"] = true
		case "-m", "--machine":
			want["m"] = true
		}
	}

	var fields []string
	if all {
		fields = []string{sysname, nodename, release, version, machine, machine, machine, "GNU/Linux"}
	} else {
		if want["s"] {
			fields = append(fields, sysname)
		}
		if want["n"] {
			fields = append(fields, nodename)
		}
		if want["r"] {
			fields = append(fields, release)
		}
		if want["v"] {
			fields = append(fields, version)
		}
		if want["m"] {
			fields = append(fields, machine)
		}
		if len(fields) == 0 {
			fields = []string{sysname}
		}
	}
	return strings.Join(fields, " ")
}

// testBuiltin implements the handful of `test`/`[` checks attacker recon
// scripts actually use: -f (regular file), -d (directory), -e (exists).
func testBuiltin(cwd, cmd string, args []string) int {
	if cmd == "[" && len(args) > 0 && args[len(args)-1] == "]" {
		args = args[:len(args)-1]
	}
	if len(args) != 2 {
		return 2
	}
	flag, target := args[0], args[1]
	_, n := lookup(cwd, target)
	switch flag {
	case "-f":
		if n != nil && n.Type == NodeFile {
			return 0
		}
	case "-d":
		if n != nil && n.Type == NodeDir {
			return 0
		}
	case "-e":
		if n != nil {
			return 0
		}
	}
	return 1
}

func (s *Interpreter) catBuiltin(args []string, bait *[]BaitHit, action string) (string, int) {
	if len(args) < 1 {
		return "cat: missing operand", 1
	}
	_, n := lookup(s.Cwd, args[0])
	if n == nil || n.Type != NodeFile {
		return "cat: " + args[0] + ": No such file or directory", 1
	}
	// A Hidden bait node pretends not to exist unless this turn's decision
	// is SURFACE_BAIT -- no BaitHit is recorded either, since the attacker
	// never actually discovered it.
	if n.Bait != nil && n.Bait.Hidden && action != deceptionActionSurfaceBait {
		return "cat: " + args[0] + ": No such file or directory", 1
	}
	if n.Bait != nil {
		*bait = append(*bait, BaitHit{BaitID: n.Bait.BaitID, BaitType: n.Bait.BaitType, AccessType: session.AccessTypeRead})
	}
	content := n.Content
	if action == deceptionActionEnrich && n.EnrichedContent != "" {
		content = n.EnrichedContent
	}
	return strings.ReplaceAll(content, "\n", "\r\n"), 0
}

func (s *Interpreter) lsBuiltin(args []string, action string) (string, int) {
	target := s.Cwd
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			target = a
		}
	}
	_, n := lookup(s.Cwd, target)
	if n == nil || n.Type != NodeDir {
		return "ls: cannot access '" + target + "': No such file or directory", 2
	}
	return lsListing(n, action), 0
}

func (s *Interpreter) cdBuiltin(args []string) (string, int) {
	target := homeDir
	if len(args) >= 1 {
		target = args[0]
	}
	clean, n := lookup(s.Cwd, target)
	if n == nil || n.Type != NodeDir {
		return "cd: " + target + ": No such file or directory", 1
	}
	s.Cwd = clean
	return "", 0
}
