// Package shell simulates just enough of an interactive Ubuntu bash session
// to survive real-world attacker recon: a single filesystem tree (fs.go)
// shared by every command, and a small tokenizer (tokenizer.go) that
// understands `;`/`&&`/`||` chaining, quoting, `$(...)` command
// substitution, `|` pipelines, and `>`/`>>`/`<` redirects.
package shell

import (
	"fmt"
	"log"
	"math/rand"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/mirage-source/mirage-core/internal/session"
)

const ubuntuHomeDir = "/home/ubuntu"
const rootHomeDir = "/root"

// hostnamePlaceholder marks the spot in a static fs.go Content/EnrichedContent
// string where this session's randomized hostname belongs (see
// Interpreter.expandHostname). The base filesystem tree in fs.go is a single
// package-level map shared by every session, so per-session values can't be
// baked into it directly -- they're substituted in at read time instead.
const hostnamePlaceholder = "{{hostname}}"

// randomHostname picks one EC2-style "ip-<private-ip-with-dashes>" hostname
// per session (Ubuntu cloud images derive their default hostname this way),
// varying the last two octets within the same 172.31.0.0/16 default-VPC range
// the fixed hostname used to hardcode. A single hardcoded hostname across
// every session was itself a fingerprint -- a returning attacker (or two
// operators comparing notes) would see the identical "ip-172-31-14-52" no
// matter which session they landed in.
func randomHostname() string {
	return fmt.Sprintf("ip-172-31-%d-%d", 1+rand.Intn(254), 1+rand.Intn(254))
}

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
// way they would in a real shell. overlay/overlayChildren hold this
// session's own `>`/`>>` writes (fs.go's writeFile/lookup) so they never
// leak into another session or mutate the shared fs map.
//
// Username/HomeDir are fixed for the life of the session, derived once in
// NewInterpreter from the credential the attacker actually authenticated
// with -- whoami, id, the prompt's user@host and #/$ character, and cd/~
// resolution all read from these two fields rather than a hardcoded
// "ubuntu", so a root login looks like root throughout, not a root login
// into what whoami then claims is an ubuntu box.
type Interpreter struct {
	Cwd      string
	Env      map[string]string
	Hostname string
	Username string
	HomeDir  string

	overlay         map[string]*Node
	overlayChildren map[string][]string
}

// NewInterpreter derives the emulated identity from the username the
// attacker authenticated as. Only "root" gets its own identity (prompt #,
// uid 0, /root) -- every other accepted username in
// config/weak_credentials.txt (admin, mysql, postgres, ...) is a service
// account a real box would never hand an interactive shell to, so those all
// still land on the one ordinary "ubuntu" identity, same as before this
// distinction existed.
func NewInterpreter(username string) *Interpreter {
	homeDir := ubuntuHomeDir
	identity := "ubuntu"
	if username == "root" {
		homeDir = rootHomeDir
		identity = "root"
	}
	return &Interpreter{
		Cwd:      homeDir,
		Env:      map[string]string{},
		Hostname: randomHostname(),
		Username: identity,
		HomeDir:  homeDir,
	}
}

// expandHostname substitutes this session's Hostname into a static fs.go
// Content/EnrichedContent string wherever hostnamePlaceholder appears. Every
// site that returns file content to the attacker (readStdinFile,
// builtinInput, catBuiltin) must route through this so the shared base
// filesystem's placeholder never leaks verbatim.
func (s *Interpreter) expandHostname(content string) string {
	return strings.ReplaceAll(content, hostnamePlaceholder, s.Hostname)
}

// Prompt renders the current PS1-style prompt for this interpreter's cwd.
// The trailing character follows the real convention of tracking UID, not
// login method: root gets #, everyone else gets $.
func (s *Interpreter) Prompt() string {
	promptChar := "$"
	if s.Username == "root" {
		promptChar = "#"
	}
	return fmt.Sprintf("%s@%s:%s%s ", s.Username, s.Hostname, displayPath(s.Cwd, s.HomeDir), promptChar)
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

		stages := splitPipeline(st.Text)

		// NAME=value assignment only applies to a lone, non-piped statement --
		// real bash treats `FOO=bar | baz` as a pipeline, not an assignment.
		if len(stages) == 1 {
			words := tokenizeWords(stages[0])
			resolved := make([]string, 0, len(words))
			for _, w := range words {
				resolved = append(resolved, s.substitute(w, depth, bait, action))
			}
			if len(resolved) == 0 {
				continue
			}
			if isAssignmentOnly(resolved) {
				for _, w := range resolved {
					k, v, _ := strings.Cut(w, "=")
					s.Env[k] = v
				}
				lastExit = 0
				continue
			}

			cmdWords, red := extractRedirects(resolved)
			if len(cmdWords) == 0 {
				continue
			}
			var stdin *string
			if red.stdinFile != "" {
				in, ok := s.readStdinFile(red.stdinFile)
				if !ok {
					outputs = append(outputs, red.stdinFile+": No such file or directory")
					lastExit = 1
					continue
				}
				stdin = &in
			}
			out, code := s.execBuiltin(cmdWords[0], cmdWords[1:], bait, action, stdin)
			errChan := isErrorChannel(cmdWords[0], code) && !red.mergeStderrToStdout
			out, ok := s.routeStageOutput(out, errChan, red, true)
			lastExit = code
			if !ok {
				outputs = append(outputs, out)
				lastExit = 1
				continue
			}
			if out != "" {
				outputs = append(outputs, out)
			}
			continue
		}

		// A real pipeline: each stage after the first gets the previous
		// stage's stdout as its own stdin; only the last stage's output
		// reaches the attacker's terminal.
		var stageOut string
		var stageCode int
		var pipedIn *string
		for i, stageText := range stages {
			words := tokenizeWords(stageText)
			resolved := make([]string, 0, len(words))
			for _, w := range words {
				resolved = append(resolved, s.substitute(w, depth, bait, action))
			}
			cmdWords, red := extractRedirects(resolved)
			if len(cmdWords) == 0 {
				stageOut, stageCode, pipedIn = "", 0, nil
				continue
			}

			stdin := pipedIn
			if red.stdinFile != "" {
				in, ok := s.readStdinFile(red.stdinFile)
				if !ok {
					stageOut, stageCode = red.stdinFile+": No such file or directory", 1
					break
				}
				stdin = &in
			}

			stageOut, stageCode = s.execBuiltin(cmdWords[0], cmdWords[1:], bait, action, stdin)
			// Error-channel content (e.g. "command not found") is this
			// shell's stand-in for stderr, which a plain `|` never captures
			// -- unless this stage explicitly merged it with 2>&1.
			errChan := isErrorChannel(cmdWords[0], stageCode) && !red.mergeStderrToStdout
			if errChan {
				pipedIn = nil
			} else {
				// Builtins format output as \r\n for terminal display; a
				// pipe needs raw \n content.
				forwarded := strings.ReplaceAll(stageOut, "\r\n", "\n")
				pipedIn = &forwarded
			}

			var ok bool
			stageOut, ok = s.routeStageOutput(stageOut, errChan, red, i == len(stages)-1)
			if !ok {
				stageCode = 1
			}
		}
		lastExit = stageCode
		if stageOut != "" {
			outputs = append(outputs, stageOut)
		}
	}

	return strings.Join(outputs, "\r\n"), lastExit
}

// isErrorChannel reports whether cmd's output at this exit code is this
// shell's model of "went to stderr, not stdout". A real recon script commonly
// checks this distinction directly (`cmd 2>/tmp/err; cat /tmp/err`, or
// `cmd 2>&1 | grep -i denied`) -- see SECURITY.md's correctness notes on
// emulation tells. code != 0 is a reliable proxy for "this text is an error
// message" across this interpreter's small builtin set, with one deliberate
// exception: `which` can legitimately exit 1 (some requested commands
// weren't found) while its printed output is still real matches on stdout,
// never error text -- see whichBuiltin.
func isErrorChannel(cmd string, code int) bool {
	if cmd == "which" {
		return false
	}
	return code != 0
}

// routeStageOutput sends one pipeline stage's output to wherever this
// stage's active redirects say it belongs (a stderr file, both streams
// combined into one file, a stdout file, or nowhere), and returns what (if
// anything) should still be visible on the terminal for this stage. errChan
// classifies whether out is this command's error-channel content (see
// isErrorChannel) -- a `>` redirect must never intercept it, and a `2>`/`&>`
// redirect must never intercept real stdout content.
func (s *Interpreter) routeStageOutput(out string, errChan bool, red redirects, isFinal bool) (string, bool) {
	switch {
	case red.combinedFile != "":
		s.writeRedirectTarget(red.combinedFile, out, false)
		return "", true
	case errChan:
		if red.stderrFile != "" {
			s.writeRedirectTarget(red.stderrFile, out, red.stderrAppendMode)
			return "", true
		}
		return out, true // un-redirected stderr content is always visible
	case isFinal:
		return s.applyStdoutRedirect(out, red)
	case red.stdoutFile != "":
		s.writeFile(red.stdoutFile, out, red.appendMode)
		return out, true
	default:
		return out, true
	}
}

// writeRedirectTarget writes content to a `2>`/`&>` redirect target,
// discarding it silently for the common `/dev/null` sink (the overwhelming
// majority of real "hide my errors" recon usage) rather than creating a real
// file node named literally "dev/null" in the simulated filesystem.
func (s *Interpreter) writeRedirectTarget(target, content string, appendMode bool) {
	if target == "/dev/null" {
		return
	}
	content = strings.ReplaceAll(content, "\r\n", "\n")
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	s.writeFile(target, content, appendMode)
}

// applyStdoutRedirect writes out to red.stdoutFile if one was specified.
// Returns ("", true) on a successful write, out unchanged with ok=true when
// there was no redirect, or an error message with ok=false on failure.
func (s *Interpreter) applyStdoutRedirect(out string, red redirects) (string, bool) {
	if red.stdoutFile == "" {
		return out, true
	}
	content := strings.ReplaceAll(out, "\r\n", "\n")
	// Builtins return output without a trailing newline (the terminal
	// display path adds it); a file needs it explicit so a later append
	// doesn't run two writes together on one line.
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if msg, code := s.writeFile(red.stdoutFile, content, red.appendMode); code != 0 {
		return msg, false
	}
	return "", true
}

// readStdinFile resolves a `<` redirect's target to file content, or
// (_, false) if it doesn't exist or isn't a regular file.
func (s *Interpreter) readStdinFile(target string) (string, bool) {
	_, n := s.lookup(target)
	if n == nil || n.Type != NodeFile {
		return "", false
	}
	return s.expandHostname(n.Content), true
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

// execBuiltin dispatches one command. stdin is non-nil only when this
// invocation is piped-into or `<`-redirected; most builtins ignore it, only
// cat/grep/head/tail/wc read it.
func (s *Interpreter) execBuiltin(cmd string, args []string, bait *[]BaitHit, action string, stdin *string) (string, int) {
	switch cmd {
	case "":
		return "", 0

	case "echo":
		return strings.Join(args, " "), 0

	case "whoami":
		return s.Username, 0

	case "pwd":
		return s.Cwd, 0

	case "hostname":
		return s.Hostname, 0

	case "id":
		if s.Username == "root" {
			return "uid=0(root) gid=0(root) groups=0(root)", 0
		}
		return "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),27(sudo)", 0

	case "uname":
		return unameOutput(args, s.Hostname), 0

	case "export":
		for _, a := range args {
			if k, v, ok := strings.Cut(a, "="); ok {
				s.Env[k] = v
			}
		}
		return "", 0

	case "test", "[":
		return "", s.testBuiltin(cmd, args)

	case "cat":
		return s.catBuiltin(args, bait, action, stdin)

	case "ls":
		return s.lsBuiltin(args, action)

	case "cd":
		return s.cdBuiltin(args)

	case "grep":
		return s.grepBuiltin(args, stdin)

	case "head":
		return s.headTailBuiltin(args, stdin, true)

	case "tail":
		return s.headTailBuiltin(args, stdin, false)

	case "wc":
		return s.wcBuiltin(args, stdin)

	case "which":
		return s.whichBuiltin(args)

	case "find":
		return s.findBuiltin(args, action)

	case "ps":
		return psOutput(args), 0

	case "netstat":
		return netstatOutput(), 0

	case "crontab":
		return crontabBuiltin(args)

	case "exit":
		return "", ExitRequested

	default:
		log.Printf("Unknown command: %s", cmd)
		return "bash: " + cmd + ": command not found", 127
	}
}

// builtinInput resolves a stdin-reading builtin's input: a named file
// argument if given, otherwise piped stdin. ok is false only when a file
// argument was given but isn't a readable file.
func (s *Interpreter) builtinInput(fileArg string, stdin *string) (text string, ok bool) {
	if fileArg != "" {
		_, n := s.lookup(fileArg)
		if n == nil || n.Type != NodeFile {
			return "", false
		}
		return s.expandHostname(n.Content), true
	}
	if stdin != nil {
		return *stdin, true
	}
	return "", true
}

func unameOutput(args []string, hostname string) string {
	const (
		sysname = "Linux"
		release = "5.15.0-1031-aws"
		version = "#35-Ubuntu SMP Fri Feb 10 02:07:19 UTC 2023"
		machine = "x86_64"
	)
	nodename := hostname

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
func (s *Interpreter) testBuiltin(cmd string, args []string) int {
	if cmd == "[" && len(args) > 0 && args[len(args)-1] == "]" {
		args = args[:len(args)-1]
	}
	if len(args) != 2 {
		return 2
	}
	flag, target := args[0], args[1]
	_, n := s.lookup(target)
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

func (s *Interpreter) catBuiltin(args []string, bait *[]BaitHit, action string, stdin *string) (string, int) {
	if len(args) < 1 {
		// A standalone `cat` (no pipe/redirect in) keeps the original
		// "missing operand" error; only a piped/redirected cat reads stdin.
		if stdin != nil {
			return strings.ReplaceAll(*stdin, "\n", "\r\n"), 0
		}
		return "cat: missing operand", 1
	}
	_, n := s.lookup(args[0])
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
	return strings.ReplaceAll(s.expandHostname(content), "\n", "\r\n"), 0
}

func (s *Interpreter) lsBuiltin(args []string, action string) (string, int) {
	target := s.Cwd
	var longFormat, showAll bool
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			target = a
			continue
		}
		if strings.Contains(a, "l") {
			longFormat = true
		}
		if strings.Contains(a, "a") {
			showAll = true
		}
	}
	_, n := s.lookup(target)
	if n == nil || n.Type != NodeDir {
		return "ls: cannot access '" + target + "': No such file or directory", 2
	}
	return s.lsListing(n, action, longFormat, showAll), 0
}

func (s *Interpreter) cdBuiltin(args []string) (string, int) {
	target := s.HomeDir
	if len(args) >= 1 {
		target = args[0]
	}
	clean, n := s.lookup(target)
	if n == nil || n.Type != NodeDir {
		return "cd: " + target + ": No such file or directory", 1
	}
	s.Cwd = clean
	return "", 0
}

// grepBuiltin implements a simplified grep: -i/-v/-n/-c, pattern as a RE2
// regex, falling back to a literal substring match on an invalid pattern.
func (s *Interpreter) grepBuiltin(args []string, stdin *string) (string, int) {
	var invert, ignoreCase, lineNumbers, countOnly bool
	var pattern, fileArg string
	for _, a := range args {
		switch {
		case a == "-v":
			invert = true
		case a == "-i":
			ignoreCase = true
		case a == "-n":
			lineNumbers = true
		case a == "-c":
			countOnly = true
		case strings.HasPrefix(a, "-"):
			// unrecognized flag, ignored
		case pattern == "":
			pattern = a
		default:
			fileArg = a
		}
	}
	if pattern == "" {
		return "usage: grep [-ivnc] pattern [file]", 2
	}

	text, ok := s.builtinInput(fileArg, stdin)
	if !ok {
		return "grep: " + fileArg + ": No such file or directory", 2
	}

	reSrc := pattern
	if ignoreCase {
		reSrc = "(?i)" + reSrc
	}
	re, err := regexp.Compile(reSrc)
	match := func(line string) bool {
		if err != nil {
			if ignoreCase {
				return strings.Contains(strings.ToLower(line), strings.ToLower(pattern))
			}
			return strings.Contains(line, pattern)
		}
		return re.MatchString(line)
	}

	lines := splitLines(text)
	var matched []string
	count := 0
	for i, line := range lines {
		if match(line) == !invert {
			count++
			if lineNumbers {
				line = strconv.Itoa(i+1) + ":" + line
			}
			matched = append(matched, line)
		}
	}

	if countOnly {
		return strconv.Itoa(count), boolToExit(count > 0)
	}
	return strings.Join(matched, "\r\n"), boolToExit(len(matched) > 0)
}

// headTailBuiltin implements `head`/`tail -n N` (default 10), reading a
// file argument if given, otherwise stdin.
func (s *Interpreter) headTailBuiltin(args []string, stdin *string, head bool) (string, int) {
	n := 10
	var fileArg string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-n" && i+1 < len(args):
			i++
			if v, err := strconv.Atoi(args[i]); err == nil {
				n = v
			}
		case strings.HasPrefix(a, "-n") && len(a) > 2:
			if v, err := strconv.Atoi(a[2:]); err == nil {
				n = v
			}
		case strings.HasPrefix(a, "-") && len(a) > 1 && isAllDigits(a[1:]):
			if v, err := strconv.Atoi(a[1:]); err == nil {
				n = v
			}
		case !strings.HasPrefix(a, "-"):
			fileArg = a
		}
	}

	text, ok := s.builtinInput(fileArg, stdin)
	if !ok {
		cmd := "tail"
		if head {
			cmd = "head"
		}
		return cmd + ": " + fileArg + ": No such file or directory", 1
	}

	lines := splitLines(text)
	if n < 0 {
		n = 0
	}
	var picked []string
	if head {
		if n > len(lines) {
			n = len(lines)
		}
		picked = lines[:n]
	} else {
		start := len(lines) - n
		if start < 0 {
			start = 0
		}
		picked = lines[start:]
	}
	return strings.Join(picked, "\r\n"), 0
}

// wcBuiltin implements `wc -l/-w/-c` (default: all three, in that order,
// matching real wc's column order).
func (s *Interpreter) wcBuiltin(args []string, stdin *string) (string, int) {
	var lines, words, bytesFlag bool
	var fileArg string
	for _, a := range args {
		switch {
		case a == "-l":
			lines = true
		case a == "-w":
			words = true
		case a == "-c":
			bytesFlag = true
		case strings.HasPrefix(a, "-"):
		default:
			fileArg = a
		}
	}
	if !lines && !words && !bytesFlag {
		lines, words, bytesFlag = true, true, true
	}

	text, ok := s.builtinInput(fileArg, stdin)
	if !ok {
		return "wc: " + fileArg + ": No such file or directory", 1
	}

	lineCount := len(splitLines(text))
	if text == "" {
		lineCount = 0
	}
	wordCount := len(strings.Fields(text))
	byteCount := len(text)

	var fields []string
	if lines {
		fields = append(fields, strconv.Itoa(lineCount))
	}
	if words {
		fields = append(fields, strconv.Itoa(wordCount))
	}
	if bytesFlag {
		fields = append(fields, strconv.Itoa(byteCount))
	}
	out := strings.Join(fields, " ")
	if fileArg != "" {
		out += " " + fileArg
	}
	return out, 0
}

// whichBuiltinNames maps every command this interpreter can actually run to
// the path a real Ubuntu 22.04 (usr-merge) install would report for it.
// Deliberately scoped to *exactly* the commands execBuiltin's switch above
// recognizes -- reporting a hit for something the shell can't actually run
// (e.g. "python3", which only appears as history in .bash_history, not as a
// runnable builtin) would be a worse tell than admitting it's missing: an
// attacker who runs `which python3` and gets nothing, then never tries to
// run python3, learns nothing either way; one who runs `which python3`,
// gets a path back, then runs it and gets "command not found" has caught a
// direct self-contradiction.
var whichBuiltinNames = map[string]string{
	"echo":     "/usr/bin/echo",
	"whoami":   "/usr/bin/whoami",
	"pwd":      "/usr/bin/pwd",
	"hostname": "/usr/bin/hostname",
	"id":       "/usr/bin/id",
	"uname":    "/usr/bin/uname",
	"cat":      "/usr/bin/cat",
	"ls":       "/usr/bin/ls",
	"grep":     "/usr/bin/grep",
	"head":     "/usr/bin/head",
	"tail":     "/usr/bin/tail",
	"wc":       "/usr/bin/wc",
	"which":    "/usr/bin/which",
	"find":     "/usr/bin/find",
	"ps":       "/usr/bin/ps",
	"netstat":  "/bin/netstat",
	"crontab":  "/usr/bin/crontab",
	"bash":     "/usr/bin/bash",
	"sh":       "/usr/bin/sh",
}

// whichBuiltin implements `which cmd...`: prints the path for every
// recognized command, silently skips unrecognized ones (matching real
// `which`'s behavior of only erroring via its exit code), and exits 1 if any
// argument was not found or none were given.
func (s *Interpreter) whichBuiltin(args []string) (string, int) {
	var found []string
	anyMissing := len(args) == 0
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if p, ok := whichBuiltinNames[a]; ok {
			found = append(found, p)
		} else {
			anyMissing = true
		}
	}
	code := 0
	if anyMissing {
		code = 1
	}
	return strings.Join(found, "\r\n"), code
}

// findBuiltin implements a bounded `find [path] [-name PATTERN] [-type f|d]`,
// walking the exact same tree (including this session's own `>`/`>>`
// overlay writes) that ls/cat already use, so its results can never
// contradict them. Paths are always printed absolute, even when the start
// argument is relative (e.g. "." resolves to cwd but prints as cwd's full
// path) -- a deliberate simplification; real find's "./"-relative-path
// rendering isn't worth the extra bookkeeping for what recon actually reads
// out of this command (which files exist / match a name).
func (s *Interpreter) findBuiltin(args []string, action string) (string, int) {
	start := "."
	namePattern := ""
	var typeFilter byte // 'f', 'd', or 0 for "no filter"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-name":
			if i+1 < len(args) {
				i++
				namePattern = args[i]
			}
		case "-type":
			if i+1 < len(args) {
				i++
				if args[i] == "f" || args[i] == "d" {
					typeFilter = args[i][0]
				}
			}
		default:
			if !strings.HasPrefix(args[i], "-") {
				start = args[i]
			}
		}
	}

	startClean, n := s.lookup(start)
	if n == nil {
		return "find: '" + start + "': No such file or directory", 1
	}

	var out []string
	s.findWalk(startClean, n, action, namePattern, typeFilter, &out)
	return strings.Join(out, "\r\n"), 0
}

func (s *Interpreter) findWalk(p string, n *Node, action, namePattern string, typeFilter byte, out *[]string) {
	if findMatches(p, n, namePattern, typeFilter) {
		*out = append(*out, p)
	}
	if n.Type != NodeDir {
		return
	}
	names := append([]string{}, n.Children...)
	for _, cc := range n.ConditionalChildren {
		if cc.Action != "" && cc.Action == action {
			names = append(names, cc.Name)
		}
	}
	names = append(names, s.overlayChildren[n.Path]...)
	for _, name := range names {
		childPath, child := s.lookup(path.Join(p, name))
		if child == nil {
			continue
		}
		s.findWalk(childPath, child, action, namePattern, typeFilter, out)
	}
}

func findMatches(p string, n *Node, namePattern string, typeFilter byte) bool {
	if typeFilter == 'f' && n.Type != NodeFile {
		return false
	}
	if typeFilter == 'd' && n.Type != NodeDir {
		return false
	}
	if namePattern != "" {
		matched, err := path.Match(namePattern, path.Base(p))
		if err != nil || !matched {
			return false
		}
	}
	return true
}

// psOutput returns a static "ps aux"-style process table consistent with
// this box's story (nginx reverse-proxying to gunicorn per
// /etc/nginx/sites-enabled/default, sshd, cron -- see fs.go). Not
// per-session-randomized like Hostname: unlike a hostname, near-identical
// PID/uptime numbers across sessions are at least as consistent with "a
// small, recently-booted VM" as varying them would be, so it isn't worth a
// second randomization axis. args is accepted (matching every other
// flag-tolerant builtin here) but unused -- every flag combination this
// interpreter is likely to see (aux, -ef, -aux) wants the same table.
func psOutput(args []string) string {
	rows := []string{
		"USER         PID  %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND",
		"root           1   0.0  0.1 168456 11024 ?        Ss   Jul11   0:03 /sbin/init",
		"root         482   0.0  0.1  16812  8760 ?        Ss   Jul11   0:00 /usr/sbin/sshd -D",
		"root         611   0.0  0.2  55880 18220 ?        Ss   Jul11   0:00 /usr/sbin/cron -f",
		"syslog       618   0.0  0.1 222968  9040 ?        Ssl  Jul11   0:01 /usr/sbin/rsyslogd -n",
		"root         881   0.0  0.1  55164 10552 ?        Ss   Jul11   0:00 nginx: master process /usr/sbin/nginx",
		"www-data     882   0.0  0.1  55592  7280 ?        S    Jul11   0:00 nginx: worker process",
		"ubuntu      1147   0.2  1.4 178452 57316 ?        Sl   09:12   0:14 /home/ubuntu/.local/bin/gunicorn app.wsgi:application --bind 127.0.0.1:8000",
		"ubuntu      1148   0.1  1.3 178452 55908 ?        S    09:12   0:09 /home/ubuntu/.local/bin/gunicorn app.wsgi:application --bind 127.0.0.1:8000",
		"ubuntu      2031   0.0  0.0  10404  5192 pts/0    Ss   14:02   0:00 -bash",
		"ubuntu      2114   0.0  0.0  10744  3364 pts/0    R+   14:03   0:00 ps aux",
	}
	return strings.Join(rows, "\r\n")
}

// netstatOutput returns a static "netstat -tulpn"-style listening-socket
// table. Every entry has to agree with a service the rest of the filesystem
// story implies is running (see psOutput above): nginx on :80, gunicorn on
// 127.0.0.1:8000 (not externally reachable, matching nginx's proxy_pass
// target in fs.go), sshd on :22. The Postgres the app's DATABASE_URL points
// at (10.0.4.12:5432, see .env) is deliberately absent -- it's a different
// host, so it would never appear in this box's own netstat.
func netstatOutput() string {
	rows := []string{
		"Active Internet connections (only servers)",
		"Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name",
		"tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      482/sshd",
		"tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      1147/gunicorn",
		"tcp6       0      0 :::80                   :::*                    LISTEN      881/nginx",
	}
	return strings.Join(rows, "\r\n")
}

// crontabBuiltin implements just enough of `crontab` to answer honestly:
// this box's ubuntu user has never installed a personal crontab. -l/-e/-r
// (list/edit/remove) all resolve to real crontab's actual message for that
// case; anything else falls back to its usage line.
func crontabBuiltin(args []string) (string, int) {
	for _, a := range args {
		switch a {
		case "-l", "-e", "-r":
			return "no crontab for ubuntu", 1
		}
	}
	return "usage: crontab [-u user] file\ncrontab [ -u user ] [ -i ] { -e | -l | -r }", 1
}

func splitLines(text string) []string {
	text = strings.TrimRight(text, "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func boolToExit(b bool) int {
	if b {
		return 0
	}
	return 1
}
