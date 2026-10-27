package shell

import (
	"regexp"
	"strconv"
	"strings"
)

// maxFunctionDepth stops a function that calls itself without end. Real bash runs until it exhausts its
// stack; a honeypot should not.
const maxFunctionDepth = 100

// funcHeader matches `name() rest`, `name () rest` and `function name [()] rest`; rest is the body, usually
// starting with "{".
var funcHeader = regexp.MustCompile(`(?s)^(?:function\s+([A-Za-z_][A-Za-z0-9_.:-]*)\s*(?:\(\s*\))?|([A-Za-z_][A-Za-z0-9_.:-]*)\s*\(\s*\))\s*(.*)$`)

// savedVar is what a variable held before `local` shadowed it.
type savedVar struct {
	val    string
	exists bool
}

// funcFrame is one function call in progress: its positional parameters, and the variables its `local`
// declarations will give back on return.
type funcFrame struct {
	args   []string
	locals map[string]savedVar
}

// funcItem parses the definition whose header is the statement st. A function body is a { } group, which
// may start on the next line.
func (p *parser) funcItem(st statement, name, rest string) (item, error) {
	if rest == "" {
		p.pos++
	} else {
		p.stmts[p.pos] = statement{Text: rest, Sep: st.Sep, Line: st.Line}
	}
	if _, ok := p.cur(); !ok {
		return item{}, syntaxError("")
	}
	body, err := p.itemInner()
	if err != nil {
		return item{}, err
	}
	if body.kind != kindGroup {
		return item{}, syntaxError("(")
	}
	return item{kind: kindFunc, sep: st.Sep, word: name, body: body.body, line: st.Line}, nil
}

// callFunction runs a defined function. Its stdout is returned; what it wrote to stderr goes to pendingErr
// so the caller still keeps the two apart (their relative order is lost). Variables are global except
// those declared `local`, which are restored on return, and the positional parameters are the call's.
func (s *Interpreter) callFunction(body []item, args []string, bait *[]BaitHit, action string, stdin *string) (string, int) {
	if len(s.frames) >= maxFunctionDepth {
		return "bash: maximum function nesting level exceeded", 1
	}
	s.frames = append(s.frames, funcFrame{args: args})
	savedStdin := s.pipeStdin
	if stdin != nil {
		s.pipeStdin = stdin
	}
	var chunks []outChunk
	code := s.runItems(body, 0, bait, action, &chunks)
	if s.returning {
		code, s.returning = s.retCode, false
	}
	s.pipeStdin = savedStdin
	f := s.frames[len(s.frames)-1]
	s.frames = s.frames[:len(s.frames)-1]
	for name, v := range f.locals {
		if v.exists {
			s.Env[name] = v.val
		} else {
			delete(s.Env, name)
		}
	}

	var outs []outChunk
	for _, c := range chunks {
		if c.stderr {
			s.pendingErr = append(s.pendingErr, c.text)
		} else {
			outs = append(outs, c)
		}
	}
	out := joinChunks(outs, "\r\n")
	noNL := len(outs) > 0 && outs[len(outs)-1].noNewline
	s.noTrailingNewline = noNL
	s.blankEcho = len(outs) > 0 && out == "" && !noNL // a function whose last word was a bare echo
	return out, code
}

// posArgs are the positional parameters $1, $2, ... of the function running (none at the top level: `set --`
// is not emulated).
func (s *Interpreter) posArgs() []string {
	if len(s.frames) == 0 {
		return nil
	}
	return s.frames[len(s.frames)-1].args
}

// positional is the value of $N for N >= 1, and whether that parameter is set.
func (s *Interpreter) positional(n int) (string, bool) {
	a := s.posArgs()
	if n < 1 || n > len(a) {
		return "", false
	}
	return a[n-1], true
}

// ifsJoiner is what "$*" puts between the parameters: the first character of IFS, a space when IFS is
// unset, nothing when it is empty.
func (s *Interpreter) ifsJoiner() string {
	ifs, set := s.Env["IFS"]
	switch {
	case !set:
		return " "
	case ifs == "":
		return ""
	}
	return ifs[:1]
}

func (s *Interpreter) localBuiltin(args []string) (string, int) {
	if len(s.frames) == 0 {
		return "bash: local: can only be used in a function", 1
	}
	f := &s.frames[len(s.frames)-1]
	if f.locals == nil {
		f.locals = map[string]savedVar{}
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		name, val, hasVal := strings.Cut(a, "=")
		if _, done := f.locals[name]; !done {
			old, ok := s.Env[name]
			f.locals[name] = savedVar{old, ok}
		}
		if hasVal {
			s.Env[name] = val
		} else {
			delete(s.Env, name) // declared, not set: `local a` hides a global a until it is assigned
		}
	}
	return "", 0
}

func (s *Interpreter) returnBuiltin(args []string) (string, int) {
	if len(s.frames) == 0 {
		return "bash: return: can only `return' from a function or sourced script", 1
	}
	code := s.lastCode
	if len(args) > 0 {
		n, err := strconv.Atoi(args[0])
		if err != nil {
			s.returning, s.retCode = true, 2
			return "bash: return: " + args[0] + ": numeric argument required", 2
		}
		code = n & 0xff
	}
	s.returning, s.retCode = true, code
	return "", code
}

func (s *Interpreter) shiftBuiltin(args []string) (string, int) {
	n := 1
	if len(args) > 0 {
		var err error
		if n, err = strconv.Atoi(args[0]); err != nil || n < 0 {
			return "bash: shift: " + args[0] + ": numeric argument required", 1
		}
	}
	if len(s.frames) == 0 || n > len(s.posArgs()) {
		return "", 1
	}
	f := &s.frames[len(s.frames)-1]
	f.args = f.args[n:]
	return "", 0
}

// isFunc reports whether name is a function defined in this shell, which runs in place of any builtin
// of the same name.
func (s *Interpreter) isFunc(name string) bool {
	_, ok := s.funcs[name]
	return ok
}

// isErr is isErrorChannel, except that a function's status says nothing about which stream its output
// belongs to: `f() { echo hi; return 3; }` still prints hi on stdout.
func (s *Interpreter) isErr(cmd string, code int) bool {
	return !s.isFunc(cmd) && isErrorChannel(cmd, code)
}
