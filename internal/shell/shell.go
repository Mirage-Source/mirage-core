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
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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

// randomBootTime picks a plausible boot time for this session's box: 1 hour
// to 60 days of uptime, matching a long-running EC2 instance rather than one
// freshly rebooted for every attacker. Backs ps's daemon START column and
// /proc/uptime.
func randomBootTime() time.Time {
	uptime := time.Duration(60+rand.Intn(60*24*60)) * time.Minute
	return time.Now().Add(-uptime)
}

// randomPIDs assigns each named process in the psOutput/netstatOutput story
// a per-session PID, jittered within the same band the original hardcoded
// values occupied (so the story -- sshd started early, gunicorn/nginx later,
// bash/ps most recent -- stays intact) rather than a single hardcoded set
// every session shares. init is deliberately NOT randomized: PID 1 is always
// init on a real Linux box, session or no session.
func randomPIDs() map[string]int {
	nginxMaster := 850 + rand.Intn(150)
	gunicorn1 := 1100 + rand.Intn(200)
	bash := 2000 + rand.Intn(200)
	return map[string]int{
		"sshd":         400 + rand.Intn(150),
		"cron":         580 + rand.Intn(150),
		"rsyslogd":     600 + rand.Intn(150),
		"nginx_master": nginxMaster,
		"nginx_worker": nginxMaster + 1,
		"gunicorn1":    gunicorn1,
		"gunicorn2":    gunicorn1 + 1,
		"bash":         bash,
		"ps":           bash + 50 + rand.Intn(100),
	}
}

// formatPsStart renders a process's start time the way real `ps` does: HH:MM
// if it started on the same calendar day as now, otherwise "Mon02" (e.g.
// "Jul11").
func formatPsStart(start, now time.Time) string {
	if start.Year() == now.Year() && start.YearDay() == now.YearDay() {
		return start.Format("15:04")
	}
	return start.Format("Jan02")
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
	*Machine

	Cwd      string
	Env      map[string]string
	Username string
	HomeDir  string

	nesting   int
	loopInput *[]string // lines left for `read` in a `done < file` loop

	exec     bool // running as sshd's `bash -c <command>` (RunExec), not a login shell
	tty      bool // stdout is a terminal (interactive shell, or exec with a pty)
	line     int  // line of the statement running, for exec's "bash: line N:"
	lineBase int  // lines before the text being run, so $( ) and ( ) report script lines

	pipeStdin *string // stdin a ( ) group inherits from the pipe feeding it
	blankEcho bool    // the statement was a bare `echo`: it prints an empty line

	loopDepth int    // for/while/until loops being run
	loopCtl   string // "break" or "continue" waiting for the innermost loop to take it
	lastCode  int    // $?

	exported   map[string]bool // names `export`ed beyond the login environment
	direct     bool            // statement is one bash would exec in place (see exportedEnv)
	pendingErr []string        // stderr a builtin wrote alongside its stdout
	lastTop    *item           // last statement of the top-level list

	noTrailingNewline bool
}

// Machine is the box an SSH connection logged in to: what stays the same
// across every exec, shell and sftp channel on it (a file uploaded or
// written by one is there for the next; hostname, boot time and PIDs do not
// change). Each channel gets its own Interpreter, a process with its own
// cwd and variables, from NewInterpreter. Channels run concurrently, so mu
// serializes every entry point that touches the overlay.
type Machine struct {
	mu sync.Mutex

	Hostname string

	// BootTime, SessionStart, and pids back ps/netstat/`/proc/uptime` --
	// fixed once per session, like Hostname, so a patient attacker
	// reconnecting can't fingerprint the honeypot by noticing every
	// low-level system fact is byte-identical across sessions. Kernel
	// version (uname -r/-v) is deliberately NOT varied here -- see
	// unameOutput -- real hosts booted from the same image legitimately
	// share it; only host-specific facts (uptime, PIDs, process start
	// times) should differ.
	BootTime     time.Time
	SessionStart time.Time
	pids         map[string]int

	Busybox bool
	profile *Profile

	mem       memBase // see memSnapshot
	idleRatio float64 // /proc/uptime's idle seconds per second of uptime

	aptNotUpgraded int // pending updates apt reports; a stale box has dozens

	overlay         map[string]*Node
	overlayChildren map[string][]string
}

// NewMachine creates the box for one connection.
func NewMachine(p *Profile) *Machine {
	m := &Machine{
		Hostname:     p.hostname(),
		BootTime:     randomBootTime(),
		SessionStart: time.Now(),
		pids:         randomPIDs(),
		Busybox:      p.busybox,
		profile:      p,
	}
	m.overlay = map[string]*Node{}
	m.mem = newMemBase()
	m.idleRatio = 0.7 + rand.Float64()*0.25
	m.aptNotUpgraded = 20 + rand.Intn(60)
	return m
}

// NewInterpreter derives the emulated identity from the username the
// attacker authenticated as. Only "root" gets its own identity (prompt #,
// uid 0, /root) -- every other accepted username in
// config/weak_credentials.txt (admin, mysql, postgres, ...) is a service
// account a real box would never hand an interactive shell to, so those all
// still land on the one ordinary "ubuntu" identity, same as before this
// distinction existed.
func NewInterpreter(username string) *Interpreter {
	return NewInterpreterFor(username, Ubuntu)
}

// NewInterpreterFor is NewInterpreter for a machine other than the default
// Ubuntu server.
func NewInterpreterFor(username string, p *Profile) *Interpreter {
	return NewMachine(p).NewInterpreter(username)
}

// NewInterpreter starts a process on m as username, in its home directory
// with no shell variables set, like a fresh login shell or `bash -c`.
func (m *Machine) NewInterpreter(username string) *Interpreter {
	homeDir := ubuntuHomeDir
	identity := "ubuntu"
	if username == "root" {
		homeDir = rootHomeDir
		identity = "root"
	}
	if m.profile.allRoot {
		homeDir = m.profile.home
		identity = "root"
	}
	env := map[string]string{}
	if m.profile.loginEnv != nil {
		env = m.profile.loginEnv(identity, homeDir)
	}
	return &Interpreter{
		Machine:  m,
		Cwd:      homeDir,
		Env:      env,
		Username: identity,
		HomeDir:  homeDir,
	}
}

// specialParam expands bash's one-character parameters. ok is false for a
// character that is not one.
func (s *Interpreter) specialParam(c byte) (string, bool) {
	switch c {
	case '?':
		return strconv.Itoa(s.lastCode), true
	case '$':
		return strconv.Itoa(s.pids["bash"]), true
	case '#':
		return "0", true
	case '0':
		if s.Busybox {
			return "-sh", true
		}
		if s.exec {
			return "bash", true
		}
		return "-bash", true
	case '-':
		if s.exec {
			return "hBc", true
		}
		return "himBHs", true
	case '!', '1', '2', '3', '4', '5', '6', '7', '8', '9', '@', '*':
		return "", true
	}
	return "", false
}

// param is the value of NAME in $NAME or ${NAME}.
func (s *Interpreter) param(name string) string {
	if len(name) == 1 {
		if v, ok := s.specialParam(name[0]); ok {
			return v
		}
	}
	if len(name) > 1 && name[0] == '#' {
		return strconv.Itoa(len([]rune(s.param(name[1:]))))
	}
	return s.Env[name]
}

// expandHostname substitutes this session's Hostname into a static fs.go
// Content/EnrichedContent string wherever hostnamePlaceholder appears. Every
// site that returns file content to the attacker (readStdinFile,
// builtinInput, catBuiltin) must route through this so the shared base
// filesystem's placeholder never leaks verbatim.
// content is what reading n returns: generated now for /proc files, else
// the stored text with this machine's hostname filled in.
func (s *Interpreter) content(n *Node) string {
	if n.gen != nil {
		return n.gen(s)
	}
	return s.expandHostname(n.Content)
}

func (s *Interpreter) expandHostname(content string) string {
	return strings.ReplaceAll(content, hostnamePlaceholder, s.Hostname)
}

// Prompt renders the current PS1-style prompt for this interpreter's cwd.
// The trailing character follows the real convention of tracking UID, not
// login method: root gets #, everyone else gets $.
func (s *Interpreter) Prompt() string {
	return s.profile.prompt(s)
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
	s.mu.Lock()
	defer s.mu.Unlock()
	out, code := s.evalLine(line, 0, &bait, action)
	return out, code, bait
}

// RunExec runs command the way sshd runs an exec request without a pty:
// as `bash -c command`, a non-interactive shell with stdout and stderr kept
// apart, \n line ends, and "bash: line N:" on bash's own errors. Each call
// is a new process: create a fresh Interpreter per exec on the Machine.
func (s *Interpreter) RunExec(command string) (stdout, stderr string, code int, bait []BaitHit) {
	return s.RunExecWithDeception(command, "", false)
}

// RunExecWithDeception is RunExec with a deception action, as
// RunWithDeception is to Run. With pty, the exec has a terminal: both
// streams go to it (all in stdout here) with \r\n line ends.
func (s *Interpreter) RunExecWithDeception(command, action string, pty bool) (stdout, stderr string, code int, bait []BaitHit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exec, s.tty = true, pty
	chunks, code := s.evalChunks(command, 0, &bait, action)
	var out, errOut strings.Builder
	for _, c := range chunks {
		text := strings.ReplaceAll(c.text, "\r\n", "\n")
		// Builtins leave off their final newline unless they mean it.
		if !strings.HasSuffix(text, "\n") && !c.noNewline {
			text += "\n"
		}
		switch {
		case pty:
			out.WriteString(strings.ReplaceAll(text, "\n", "\r\n"))
		case c.stderr:
			errOut.WriteString(text)
		default:
			out.WriteString(text)
		}
	}
	return out.String(), errOut.String(), code, bait
}

// PrivateIP is the address the hostname implies ("ip-172-31-9-171" is
// 172.31.9.171, as on EC2), or "" for any other hostname.
func (m *Machine) PrivateIP() string {
	rest, ok := strings.CutPrefix(m.Hostname, "ip-")
	if !ok {
		return ""
	}
	ip := strings.ReplaceAll(rest, "-", ".")
	if _, err := netip.ParseAddr(ip); err != nil {
		return "" // netip, not net: this package must not be able to dial
	}
	return ip
}

// outChunk is one statement's visible output and the stream it went to.
type outChunk struct {
	text      string
	stderr    bool
	noNewline bool // printed without a final newline (echo -n, printf, dd)
}

func joinChunks(chunks []outChunk, sep string) string {
	var b strings.Builder
	for i, c := range chunks {
		b.WriteString(c.text)
		if i < len(chunks)-1 && !c.noNewline {
			b.WriteString(sep)
		}
	}
	return b.String()
}

// chunk tags output with its stream. Under bash -c, the shell's own errors
// name the script line: "bash: line 2: x: command not found".
func (s *Interpreter) chunk(text string, stderr bool) outChunk {
	if stderr {
		text = s.addLine(text)
	}
	return outChunk{text: text, stderr: stderr}
}

// addLine puts "line N:" on bash's own error lines when running as bash -c.
// It is idempotent, and is also applied where 2>&1 sends such an error to
// stdout, which bash prefixes the same way.
func (s *Interpreter) addLine(text string) string {
	if !s.exec || s.line <= 0 || !strings.Contains(text, "bash: ") {
		return text
	}
	lines := strings.Split(text, "\r\n")
	for i, l := range lines {
		if rest, ok := strings.CutPrefix(l, "bash: "); ok && !strings.HasPrefix(rest, "line ") {
			lines[i] = fmt.Sprintf("bash: line %d: %s", s.line, rest)
		}
	}
	return strings.Join(lines, "\r\n")
}

func (s *Interpreter) evalLine(line string, depth int, bait *[]BaitHit, action string) (string, int) {
	chunks, code := s.evalChunks(line, depth, bait, action)
	return joinChunks(chunks, "\r\n"), code
}

func (s *Interpreter) evalChunks(line string, depth int, bait *[]BaitHit, action string) ([]outChunk, int) {
	items, err := parseStatements(splitStatements(line))
	if err != nil {
		if se, ok := err.(syntaxError); ok {
			return []outChunk{{text: s.syntaxMsg(se), stderr: true}}, 2
		}
		return []outChunk{{text: err.Error(), stderr: true}}, 2
	}
	if depth == 0 && len(items) > 0 {
		s.lastTop = &items[len(items)-1]
	}
	var outputs []outChunk
	code := s.runItems(items, depth, bait, action, &outputs)
	return outputs, code
}

// execStatement runs one statement (possibly a pipeline). ran is false when
// the statement had no words, which leaves the previous exit status alone.
// isErr reports that out is stderr content (see isErrorChannel).
func (s *Interpreter) execStatement(text string, depth int, bait *[]BaitHit, action string) (out string, code int, ran, isErr bool) {
	stages := splitPipeline(text)

	// NAME=value assignment only applies to a lone, non-piped statement --
	// real bash treats `FOO=bar | baz` as a pipeline, not an assignment.
	if len(stages) == 1 {
		words := tokenizeWords(stages[0])
		resolved := make([]string, 0, len(words))
		for _, w := range words {
			resolved = append(resolved, s.substitute(w, depth, bait, action))
		}
		if len(resolved) == 0 {
			return "", 0, false, false
		}
		if isAssignmentOnly(resolved) {
			for _, w := range resolved {
				k, v, _ := strings.Cut(w, "=")
				s.Env[k] = v
			}
			return "", 0, true, false
		}

		cmdWords, red := extractRedirects(resolved)
		cmdWords = stripAssignments(cmdWords)
		if len(cmdWords) == 0 {
			// `> FILE` alone creates or truncates FILE.
			if red.stdoutFile == "" {
				return "", 0, false, false
			}
			if msg, code := s.writeFile(red.stdoutFile, "", red.appendMode); code != 0 {
				return msg, 1, true, true
			}
			return "", 0, true, false
		}
		var stdin *string
		if red.stdinFile != "" {
			in, ok := s.readStdinFile(red.stdinFile)
			if !ok {
				return red.stdinFile + ": No such file or directory", 1, true, true
			}
			stdin = &in
		} else if s.pipeStdin != nil {
			stdin = s.pipeStdin
		}
		out, code := s.execBuiltin(cmdWords[0], cmdWords[1:], bait, action, stdin)
		if red.mergeStderrToStdout && isErrorChannel(cmdWords[0], code) {
			out = s.addLine(out)
		}
		if red.stdoutFile != "" || red.combinedFile != "" {
			s.blankEcho = false
		}
		// A builtin that wrote its errors to pendingErr printed stdout.
		errChan := isErrorChannel(cmdWords[0], code) && !red.mergeStderrToStdout && len(s.pendingErr) == 0
		out = s.routePendingErr(out, red)
		out, ok := s.routeStageOutput(out, errChan, red, true)
		if !ok {
			return out, 1, true, true
		}
		return out, code, true, errChan
	}

	// A real pipeline: each stage after the first gets the previous
	// stage's stdout as its own stdin; only the last stage's output
	// reaches the attacker's terminal.
	var stageOut string
	var stageCode int
	var stageErr bool
	var pipedIn *string
	for i, stageText := range stages {
		// A ( ) group as a pipeline stage reads the previous stage's output.
		if inner, ok := groupStageBody(stageText); ok {
			saved := s.pipeStdin
			if i > 0 {
				s.pipeStdin = pipedIn
			}
			chunks, c := s.evalChunks(inner, depth, bait, action)
			s.pipeStdin = saved
			var outs []outChunk
			for _, ch := range chunks {
				if ch.stderr {
					s.pendingErr = append(s.pendingErr, ch.text)
				} else {
					outs = append(outs, ch)
				}
			}
			stageOut, stageCode, stageErr = joinChunks(outs, "\r\n"), c, false
			noNL := len(outs) > 0 && outs[len(outs)-1].noNewline
			s.noTrailingNewline = noNL
			fwd := strings.ReplaceAll(stageOut, "\r\n", "\n")
			if fwd != "" && !noNL {
				fwd += "\n"
			}
			pipedIn = &fwd
			continue
		}
		words := tokenizeWords(stageText)
		resolved := make([]string, 0, len(words))
		for _, w := range words {
			resolved = append(resolved, s.substitute(w, depth, bait, action))
		}
		cmdWords, red := extractRedirects(resolved)
		cmdWords = stripAssignments(cmdWords)
		if len(cmdWords) == 0 {
			stageOut, stageCode, pipedIn = "", 0, nil
			continue
		}

		stdin := pipedIn
		if stdin == nil && i == 0 {
			stdin = s.pipeStdin
		}
		if red.stdinFile != "" {
			in, ok := s.readStdinFile(red.stdinFile)
			if !ok {
				stageOut, stageCode, stageErr = red.stdinFile+": No such file or directory", 1, true
				break
			}
			stdin = &in
		}

		s.direct = true // each stage is a forked subshell that execs in place
		stageOut, stageCode = s.execBuiltin(cmdWords[0], cmdWords[1:], bait, action, stdin)
		if red.mergeStderrToStdout && isErrorChannel(cmdWords[0], stageCode) {
			stageOut = s.addLine(stageOut)
		}
		// Error-channel content (e.g. "command not found") is this
		// shell's stand-in for stderr, which a plain `|` never captures
		// -- unless this stage explicitly merged it with 2>&1.
		errChan := isErrorChannel(cmdWords[0], stageCode) && !red.mergeStderrToStdout && len(s.pendingErr) == 0
		stageOut = s.routePendingErr(stageOut, red)
		if errChan {
			pipedIn = nil
		} else {
			// Builtins format output as \r\n for terminal display; a
			// pipe needs raw \n content.
			forwarded := strings.ReplaceAll(stageOut, "\r\n", "\n")
			if forwarded != "" && !s.noTrailingNewline {
				forwarded += "\n" // the display form drops it; a pipe carries it
			}
			pipedIn = &forwarded
		}

		var ok bool
		stageOut, ok = s.routeStageOutput(stageOut, errChan, red, i == len(stages)-1)
		stageErr = errChan || !ok
		if !ok {
			stageCode = 1
		}
	}
	return stageOut, stageCode, true, stageErr
}

// routePendingErr applies a statement's stderr redirects to what its
// builtin wrote to pendingErr: 2>&1 and &> join it to stdout, 2> sends it
// to the file. Unredirected, it stays pending and is shown after stdout.
func (s *Interpreter) routePendingErr(out string, red redirects) string {
	if len(s.pendingErr) == 0 {
		return out
	}
	text := strings.Join(s.pendingErr, "\r\n")
	switch {
	case red.mergeStderrToStdout || red.combinedFile != "":
		text = s.addLine(text)
		s.pendingErr = nil
		if out == "" {
			return text
		}
		return out + "\r\n" + text
	case red.stderrFile != "":
		s.pendingErr = nil
		s.writeRedirectTarget(red.stderrFile, text, red.stderrAppendMode)
	}
	return out
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
	// printf reports bad numbers on stderr itself (pendingErr) and still
	// prints its output.
	// apt writes its errors to pendingErr; its usage text is stdout.
	if cmd == "which" || (cmd == "ping" && code == 1) || (cmd == "printf" && code == 1) || cmd == "apt" || cmd == "apt-get" {
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
	if content != "" && !strings.HasSuffix(content, "\n") && !s.noTrailingNewline {
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
	if content != "" && !strings.HasSuffix(content, "\n") && !s.noTrailingNewline {
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
	return s.content(n), true
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

		if c == '$' && i+2 < len(word) && word[i+1] == '(' && word[i+2] == '(' {
			if end := matchingParen(word, i+2); end > i+3 && word[end-1] == ')' {
				if v, ok := s.evalArith(word[i+3 : end-1]); ok {
					out.WriteString(strconv.FormatInt(v, 10))
					i = end + 1
					continue
				}
			}
		}

		if c == '$' && i+1 < len(word) && word[i+1] == '(' {
			end := matchingParen(word, i+2)
			if end == -1 {
				out.WriteString(word[i:])
				break
			}
			inner := word[i+2 : end]
			var resolved string
			if depth+1 <= maxSubstitutionDepth {
				savedBase, savedLine, savedBlank := s.lineBase, s.line, s.blankEcho
				s.lineBase = s.line - 1 // bash numbers lines inside $( ) by the script
				o, _ := s.evalLine(inner, depth+1, bait, action)
				s.lineBase, s.line, s.blankEcho = savedBase, savedLine, savedBlank
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
			out.WriteString(s.param(name))
			i = i + 2 + closeIdx + 1
			continue
		}

		if c == '$' && i+1 < len(word) {
			if v, ok := s.specialParam(word[i+1]); ok {
				out.WriteString(v)
				i += 2
				continue
			}
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
	return strings.ReplaceAll(out.String(), litDollar, "$")
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
	var cs caseScope
	var quote byte
	for i := pos; i < len(s); i++ {
		if quote != 0 {
			if s[i] == '\\' && quote == '"' && i+1 < len(s) {
				i++
			} else if s[i] == quote {
				quote = 0
			}
			continue
		}
		if s[i] == '\'' || s[i] == '"' {
			quote = s[i]
			continue
		}
		skip := cs.step(s, i)
		switch s[i] {
		case '(':
			if !skip {
				depth++
			}
		case ')':
			if skip {
				break
			}
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
	s.noTrailingNewline = false
	s.blankEcho = false
	if s.Busybox {
		if out, code, ok := s.busyboxBuiltin(cmd, args, bait, action, stdin); ok {
			return out, code
		}
	}
	switch cmd {
	case "":
		return "", 0

	case "echo":
		out, noNewline := echoBuiltin(args)
		s.noTrailingNewline = noNewline
		s.blankEcho = out == "" && !noNewline
		return out, 0

	case "command":
		return s.commandBuiltin(args, bait, action, stdin)

	case "sudo":
		return s.sudoBuiltin(args, bait, action, stdin)

	case "uptime":
		return s.uptimeBuiltin(args)

	case "readlink":
		return s.readlinkBuiltin(args)

	case "chattr":
		return s.chattrBuiltin(args)

	case "break", "continue":
		if s.loopDepth > 0 {
			s.loopCtl = cmd
		}
		return "", 0

	case "whoami":
		return s.Username, 0

	case "pwd":
		return s.Cwd, 0

	case "hostname":
		return s.Hostname, 0

	case "id":
		if out, ok := s.idFlags(args); ok {
			return out, 0
		}
		if s.Username == "root" {
			return "uid=0(root) gid=0(root) groups=0(root)", 0
		}
		return "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),27(sudo)", 0

	case "uname":
		return s.unameOutput(args), 0

	case "export":
		for _, a := range args {
			k, v, ok := strings.Cut(a, "=")
			if ok {
				s.Env[k] = v
			}
			s.markExported(k)
		}
		return "", 0

	case "env":
		return s.envBuiltin(args, bait, action, stdin)

	case "printenv":
		return s.printenvBuiltin(args)

	case "printf":
		return s.printfBuiltin(args)

	case "free":
		return s.freeBuiltin(args)

	case "nproc":
		return s.nprocBuiltin()

	case "awk", "mawk":
		return s.awkBuiltin(args, stdin)

	case "apt-get", "apt":
		return s.aptBuiltin(cmd, args)

	case "test", "[":
		return "", s.testBuiltin(cmd, args)

	case "cat":
		return s.catBuiltin(args, bait, action, stdin)

	case "ls":
		return s.lsBuiltin(args, action)

	case "cd":
		return s.cdBuiltin(args)

	case "grep":
		return s.grepBuiltin(args, stdin, "")

	case "egrep":
		return s.grepBuiltin(args, stdin, "E")

	case "fgrep":
		return s.grepBuiltin(args, stdin, "F")

	case "tr":
		return s.trBuiltin(args, stdin)

	case "cut":
		return s.cutBuiltin(args, stdin)

	case "sort":
		return s.sortBuiltin(args, stdin)

	case "sed":
		return s.sedBuiltin(args, stdin)

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
		if s.profile.ps != nil {
			return s.profile.ps(s), 0
		}
		return s.psOutput(args), 0

	case "netstat":
		return s.netstatOutput(), 0

	case "crontab":
		return crontabBuiltin(args)

	case "exit":
		return "", ExitRequested

	case "chmod":
		return s.chmodBuiltin(args)

	case "chown", "chgrp":
		return s.chownBuiltin(cmd, args)

	case "rm":
		return s.rmBuiltin(args)

	case "mkdir":
		return s.mkdirBuiltin(args)

	case "touch":
		return s.touchBuiltin(args)

	case "cp", "mv":
		return s.cpBuiltin(cmd, args)

	case "wget":
		return wgetBuiltin(args)

	case "curl":
		return curlBuiltin(args)

	case "ping":
		return pingBuiltin(args)

	case "perl":
		return s.perlBuiltin(args)

	case "dd":
		return s.ddBuiltin(args, stdin)

	case "more":
		return s.moreBuiltin(args, stdin)

	case "read":
		return s.readBuiltin(args)

	case "true", ":":
		return "", 0

	case "false":
		return "", 1

	case "sh", "bash":
		return s.shBuiltin(cmd, args, bait, action, stdin)

	case "nohup":
		if len(args) == 0 {
			return "nohup: missing operand\r\nTry 'nohup --help' for more information.", 125
		}
		return s.execBuiltin(args[0], args[1:], bait, action, stdin)

	case "sleep":
		if len(args) == 0 {
			return "sleep: missing operand\r\nTry 'sleep --help' for more information.", 1
		}
		return "", 0

	case "kill":
		return s.killBuiltin(args)

	case "pkill":
		return "", 1

	case "killall":
		return killallBuiltin(args)

	default:
		if strings.Contains(cmd, "/") {
			return s.execPath(cmd, args, bait, action, stdin)
		}
		log.Printf("Unknown command: %s", cmd)
		return s.shellMsg(s.profile.msgs.notFound, cmd), 127
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
		return s.content(n), true
	}
	if stdin != nil {
		return *stdin, true
	}
	return "", true
}

func (s *Interpreter) unameOutput(args []string) string {
	p := s.profile
	sysname, release, version, machine := p.sysname, p.release, p.version, p.machine
	nodename := s.Hostname

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
		if p.busyboxUname {
			fields = []string{sysname, nodename, release, version, machine, "GNU/Linux"}
		}
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
	if len(args) > 0 && args[0] == "!" {
		code := s.testBuiltin("test", args[1:])
		if code == 2 {
			return 2
		}
		return 1 - code
	}
	result := func(b bool) int {
		if b {
			return 0
		}
		return 1
	}
	switch len(args) {
	case 0:
		return 1
	case 1:
		return result(args[0] != "")
	case 2:
		flag, target := args[0], args[1]
		_, n := s.lookup(target)
		switch flag {
		case "-f":
			return result(n != nil && n.Type == NodeFile)
		case "-d":
			return result(n != nil && n.Type == NodeDir)
		case "-e", "-r", "-w":
			return result(n != nil)
		case "-x":
			return result(n != nil && strings.Contains(n.Mode, "x"))
		case "-s":
			return result(n != nil && s.sizeOf(n) > 0)
		case "-z":
			return result(target == "")
		case "-n":
			return result(target != "")
		}
		return 2
	case 3:
		a, op, b := args[0], args[1], args[2]
		switch op {
		case "=", "==":
			return result(a == b)
		case "!=":
			return result(a != b)
		}
		x, errA := strconv.Atoi(a)
		y, errB := strconv.Atoi(b)
		if errA != nil || errB != nil {
			return 2
		}
		switch op {
		case "-eq":
			return result(x == y)
		case "-ne":
			return result(x != y)
		case "-lt":
			return result(x < y)
		case "-le":
			return result(x <= y)
		case "-gt":
			return result(x > y)
		case "-ge":
			return result(x >= y)
		}
	}
	return 2
}

func (s *Interpreter) catBuiltin(args []string, bait *[]BaitHit, action string, stdin *string) (string, int) {
	if len(args) < 1 {
		// A standalone `cat` (no pipe/redirect in) keeps the original
		// "missing operand" error; only a piped/redirected cat reads stdin.
		if stdin != nil {
			return s.textOut(norm(*stdin))
		}
		return "cat: missing operand", 1
	}
	if len(args) == 1 && args[0] == "-" {
		// A lone "-" is standard input. With nothing piped in, an exec session's stdin is at EOF.
		if stdin != nil {
			return s.textOut(norm(*stdin))
		}
		return "", 0
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
	content := s.content(n)
	if action == deceptionActionEnrich && n.EnrichedContent != "" {
		content = s.expandHostname(n.EnrichedContent)
	}
	return strings.ReplaceAll(content, "\n", "\r\n"), 0
}

func (s *Interpreter) lsBuiltin(args []string, action string) (string, int) {
	var longFormat, showAll, dirOnly bool
	var targets []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") || a == "-" {
			targets = append(targets, a)
			continue
		}
		longFormat = longFormat || strings.Contains(a, "l")
		showAll = showAll || strings.ContainsAny(a, "aA")
		dirOnly = dirOnly || strings.Contains(a, "d")
	}
	if len(targets) == 0 {
		if _, n := s.lookup(s.Cwd); n != nil && !dirOnly {
			return s.lsListing(n, action, longFormat, showAll), 0
		}
		targets = []string{"."}
	}

	// Like coreutils: missing names on stderr first, then the files (one
	// listing), then each directory under a "name:" header.
	code := 0
	var files []lsEntry
	var dirs []string
	for _, t := range targets {
		_, n := s.lookupNoFollow(t)
		if n == nil {
			s.pendingErr = append(s.pendingErr, "ls: cannot access '"+t+"': No such file or directory")
			code = 2
			continue
		}
		if n.Link != "" && !longFormat {
			if _, to := s.lookup(t); to != nil && to.Type == NodeDir {
				n = to
			}
		}
		if n.Type == NodeDir && !dirOnly {
			dirs = append(dirs, t)
			continue
		}
		files = append(files, s.entryFor(t, n))
	}
	sort.SliceStable(files, func(i, j int) bool { return files[i].name < files[j].name })
	sort.Strings(dirs)

	var parts []string
	if len(files) > 0 {
		if longFormat {
			parts = append(parts, formatLong(files))
		} else {
			names := make([]string, len(files))
			for i, f := range files {
				names[i] = f.name
			}
			parts = append(parts, strings.Join(names, s.lsSep()))
		}
	}
	for _, d := range dirs {
		_, n := s.lookup(d)
		listing := s.lsListing(n, action, longFormat, showAll)
		if len(targets) > 1 {
			listing = strings.TrimSuffix(d+":\r\n"+listing, "\r\n")
		}
		parts = append(parts, listing)
	}
	if code != 0 && len(parts) == 0 {
		return "", code
	}
	return strings.Join(parts, "\r\n\r\n"), code
}

func (s *Interpreter) cdBuiltin(args []string) (string, int) {
	target := s.HomeDir
	if len(args) >= 1 {
		target = args[0]
	}
	clean, n := s.lookup(target)
	if n == nil || n.Type != NodeDir {
		return s.shellMsg(s.profile.msgs.cdMissing, target), 1
	}
	if _, ok := s.Env["PWD"]; ok {
		s.Env["OLDPWD"] = s.Cwd
		s.Env["PWD"] = clean
	}
	s.Cwd = clean
	return "", 0
}

// grepBuiltin implements a simplified grep: -i/-v/-n/-c, pattern as a RE2
// regex, falling back to a literal substring match on an invalid pattern.
func (s *Interpreter) grepBuiltin(args []string, stdin *string, mode string) (string, int) {
	var invert, ignoreCase, lineNumbers, countOnly, quiet, onlyMatching, word, whole, noName, withName bool
	var patterns, files []string
	maxCount := -1
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			files = append(files, args[i+1:]...)
			break
		}
		if len(a) < 2 || a[0] != '-' {
			files = append(files, a)
			continue
		}
		if strings.HasPrefix(a, "--") {
			switch {
			case a == "--extended-regexp":
				mode = "E"
			case a == "--fixed-strings":
				mode = "F"
			case a == "--quiet" || a == "--silent":
				quiet = true
			case a == "--ignore-case":
				ignoreCase = true
			case a == "--invert-match":
				invert = true
			case a == "--only-matching":
				onlyMatching = true
			case a == "--count":
				countOnly = true
			case strings.HasPrefix(a, "--regexp="):
				patterns = append(patterns, strings.TrimPrefix(a, "--regexp="))
			}
			continue
		}
		cluster := a[1:]
		for k := 0; k < len(cluster); k++ {
			f := cluster[k]
			takeArg := func() (string, bool) {
				if k+1 < len(cluster) {
					v := cluster[k+1:]
					k = len(cluster)
					return v, true
				}
				if i+1 < len(args) {
					i++
					return args[i], true
				}
				return "", false
			}
			switch f {
			case 'v':
				invert = true
			case 'i', 'y':
				ignoreCase = true
			case 'n':
				lineNumbers = true
			case 'c':
				countOnly = true
			case 'E':
				mode = "E"
			case 'F':
				mode = "F"
			case 'G':
				mode = ""
			case 'q':
				quiet = true
			case 'o':
				onlyMatching = true
			case 'w':
				word = true
			case 'x':
				whole = true
			case 'h':
				noName = true
			case 'H':
				withName = true
			case 's', 'r', 'R', 'a', 'I', 'U', 'z', 'l', 'L':
			case 'e':
				if v, ok := takeArg(); ok {
					patterns = append(patterns, v)
				}
			case 'm':
				if v, ok := takeArg(); ok {
					if n, err := strconv.Atoi(v); err == nil {
						maxCount = n
					}
				}
			case 'A', 'B', 'C':
				takeArg()
			default:
				return fmt.Sprintf("grep: invalid option -- '%c'\r\nUsage: grep [OPTION]... PATTERNS [FILE]...\r\nTry 'grep --help' for more information.", f), 2
			}
		}
	}
	if len(patterns) == 0 {
		if len(files) == 0 {
			return "Usage: grep [OPTION]... PATTERNS [FILE]...\r\nTry 'grep --help' for more information.", 2
		}
		patterns, files = []string{files[0]}, files[1:]
	}
	var alts []string
	for _, p := range patterns {
		for _, one := range strings.Split(p, "\n") {
			switch mode {
			case "F":
				alts = append(alts, regexp.QuoteMeta(one))
			default:
				alts = append(alts, breToRE2(one, mode == "E"))
			}
		}
	}
	src := strings.Join(alts, "|")
	if len(alts) > 1 {
		src = "(?:" + strings.Join(alts, ")|(?:") + ")"
	}
	switch {
	case whole:
		src = "^(?:" + src + ")$"
	case word:
		src = `\b(?:` + src + `)\b`
	}
	if ignoreCase {
		src = "(?i)" + src
	}
	re, err := regexp.Compile(src)
	if err != nil {
		return "grep: Unmatched ( or \\(", 2
	}

	type source struct{ name, text string }
	var srcs []source
	if len(files) == 0 {
		in := ""
		if stdin != nil {
			in = *stdin
		}
		srcs = append(srcs, source{"(standard input)", in})
	}
	var errs []string
	for _, f := range files {
		text, ok := s.builtinInput(f, stdin)
		if !ok {
			errs = append(errs, "grep: "+f+": No such file or directory")
			continue
		}
		srcs = append(srcs, source{f, text})
	}
	showName := (len(files) > 1 || withName) && !noName

	var out []string
	total := 0
	for _, src := range srcs {
		count := 0
		for i, line := range splitLines(norm(src.text)) {
			if maxCount >= 0 && count >= maxCount {
				break
			}
			if re.MatchString(line) == invert {
				continue
			}
			count++
			total++
			if quiet {
				return "", 0
			}
			if countOnly {
				continue
			}
			prefix := ""
			if showName {
				prefix = src.name + ":"
			}
			if lineNumbers {
				prefix += strconv.Itoa(i+1) + ":"
			}
			if onlyMatching && !invert {
				for _, m := range re.FindAllString(line, -1) {
					if m != "" {
						out = append(out, prefix+m)
					}
				}
				continue
			}
			out = append(out, prefix+line)
		}
		if countOnly {
			p := ""
			if showName {
				p = src.name + ":"
			}
			out = append(out, p+strconv.Itoa(count))
		}
	}
	out = append(out, errs...)
	code := boolToExit(total > 0)
	if len(errs) > 0 {
		code = 2
	}
	if quiet {
		return "", code
	}
	return strings.Join(out, "\r\n"), code
}

// headTailBuiltin implements `head`/`tail -n N` (default 10), reading a
// file argument if given, otherwise stdin.
func (s *Interpreter) headTailBuiltin(args []string, stdin *string, head bool) (string, int) {
	n := 10
	byteMode := false
	var fileArg string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-c" && i+1 < len(args):
			i++
			n, byteMode = parseByteCount(args[i]), true
		case strings.HasPrefix(a, "-c") && len(a) > 2:
			n, byteMode = parseByteCount(a[2:]), true
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

	if byteMode {
		text = norm(text)
		var part string
		switch {
		case head && n < len(text):
			part = text[:n]
		case !head && n < len(text):
			part = text[len(text)-n:]
		default:
			part = text
		}
		return s.textOut(part)
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
// psOutput renders a `ps aux`-style process table. PIDs come from this
// session's s.pids (see randomPIDs) rather than hardcoded values, and daemon
// START times are derived from s.BootTime -- both fixed once per session, so
// two connections show a plausibly different but internally consistent
// picture instead of the exact same table every time. netstatOutput below
// must agree with this on any PID/name it also shows (sshd, gunicorn, nginx).
func (s *Interpreter) psOutput(args []string) string {
	daemonStart := formatPsStart(s.BootTime, s.SessionStart)
	shellStart := formatPsStart(s.SessionStart, s.SessionStart)
	rows := []string{
		"USER         PID  %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND",
		fmt.Sprintf("root           1   0.0  0.1 168456 11024 ?        Ss   %-5s   0:03 /sbin/init", daemonStart),
		fmt.Sprintf("root       %5d   0.0  0.1  16812  8760 ?        Ss   %-5s   0:00 /usr/sbin/sshd -D", s.pids["sshd"], daemonStart),
		fmt.Sprintf("root       %5d   0.0  0.2  55880 18220 ?        Ss   %-5s   0:00 /usr/sbin/cron -f", s.pids["cron"], daemonStart),
		fmt.Sprintf("syslog     %5d   0.0  0.1 222968  9040 ?        Ssl  %-5s   0:01 /usr/sbin/rsyslogd -n", s.pids["rsyslogd"], daemonStart),
		fmt.Sprintf("root       %5d   0.0  0.1  55164 10552 ?        Ss   %-5s   0:00 nginx: master process /usr/sbin/nginx", s.pids["nginx_master"], daemonStart),
		fmt.Sprintf("www-data   %5d   0.0  0.1  55592  7280 ?        S    %-5s   0:00 nginx: worker process", s.pids["nginx_worker"], daemonStart),
		fmt.Sprintf("ubuntu     %5d   0.2  1.4 178452 57316 ?        Sl   %-5s   0:14 /home/ubuntu/.local/bin/gunicorn app.wsgi:application --bind 127.0.0.1:8000", s.pids["gunicorn1"], daemonStart),
		fmt.Sprintf("ubuntu     %5d   0.1  1.3 178452 55908 ?        S    %-5s   0:09 /home/ubuntu/.local/bin/gunicorn app.wsgi:application --bind 127.0.0.1:8000", s.pids["gunicorn2"], daemonStart),
		fmt.Sprintf("ubuntu     %5d   0.0  0.0  10404  5192 pts/0    Ss   %-5s   0:00 -bash", s.pids["bash"], shellStart),
		fmt.Sprintf("ubuntu     %5d   0.0  0.0  10744  3364 pts/0    R+   %-5s   0:00 ps aux", s.pids["ps"], shellStart),
	}
	return strings.Join(rows, "\r\n")
}

// netstatOutput returns a "netstat -tulpn"-style listening-socket table.
// Every entry has to agree with a service the rest of the filesystem story
// implies is running (see psOutput above): nginx on :80, gunicorn on
// 127.0.0.1:8000 (not externally reachable, matching nginx's proxy_pass
// target in fs.go), sshd on :22 -- and, since this session's PIDs, on the
// same PIDs psOutput just showed for those processes. The Postgres the
// app's DATABASE_URL points at (10.0.4.12:5432, see .env) is deliberately
// absent -- it's a different host, so it would never appear in this box's
// own netstat.
func (s *Interpreter) netstatOutput() string {
	rows := []string{
		"Active Internet connections (only servers)",
		"Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name",
		fmt.Sprintf("tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      %d/sshd", s.pids["sshd"]),
		fmt.Sprintf("tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      %d/gunicorn", s.pids["gunicorn1"]),
		fmt.Sprintf("tcp6       0      0 :::80                   :::*                    LISTEN      %d/nginx", s.pids["nginx_master"]),
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

func (s *Interpreter) idFlags(args []string) (string, bool) {
	flags, _ := splitFlags(args)
	if flags == "" {
		return "", false
	}
	uid, name, groups := "1000", "ubuntu", "1000 27"
	if s.Username == "root" {
		uid, name, groups = "0", "root", "0"
	}
	named := strings.Contains(flags, "n")
	switch {
	case strings.Contains(flags, "u"), strings.Contains(flags, "g") && !strings.Contains(flags, "G"):
		if named {
			return name, true
		}
		return uid, true
	case strings.Contains(flags, "G"):
		if named {
			if s.Username == "root" {
				return "root", true
			}
			return "ubuntu sudo", true
		}
		return groups, true
	}
	return "", false
}

// parseByteCount reads a head/tail -c argument: a number with an optional
// GNU multiplier suffix (b=512, K=1024, M, G; kB=1000, MB, GB).
func parseByteCount(v string) int {
	mult := 1
	for _, suf := range []struct {
		s string
		m int
	}{{"kB", 1000}, {"MB", 1000000}, {"GB", 1000000000}, {"KiB", 1024}, {"MiB", 1 << 20}, {"GiB", 1 << 30}, {"K", 1024}, {"M", 1 << 20}, {"G", 1 << 30}, {"b", 512}} {
		if strings.HasSuffix(v, suf.s) {
			v, mult = strings.TrimSuffix(v, suf.s), suf.m
			break
		}
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n * mult
}

// commandBuiltin implements `command [-pvV] name [args]`: -v names where a
// command would come from (printing nothing, status 1, if it is unknown);
// otherwise it just runs name.
func (s *Interpreter) commandBuiltin(args []string, bait *[]BaitHit, action string, stdin *string) (string, int) {
	verbose := false
	i := 0
	for ; i < len(args) && strings.HasPrefix(args[i], "-") && args[i] != "--"; i++ {
		if strings.ContainsAny(args[i], "vV") {
			verbose = true
		}
	}
	if i < len(args) && args[i] == "--" {
		i++
	}
	names := args[i:]
	if !verbose {
		if len(names) == 0 {
			return "", 0
		}
		return s.execBuiltin(names[0], names[1:], bait, action, stdin)
	}
	var found []string
	missing := len(names) == 0
	for _, n := range names {
		if p, ok := whichBuiltinNames[n]; ok {
			found = append(found, p)
		} else if IsKnownBuiltin(n) {
			found = append(found, n)
		} else {
			missing = true
		}
	}
	return strings.Join(found, "\r\n"), boolToExit(!missing)
}

// groupStageBody returns the commands inside a pipeline stage that is
// exactly one ( ... ) group.
func groupStageBody(stage string) (string, bool) {
	t := strings.TrimSpace(stage)
	if !strings.HasPrefix(t, "(") {
		return "", false
	}
	if end := closingParen(t); end == len(t)-1 {
		return t[1:end], true
	}
	return "", false
}
