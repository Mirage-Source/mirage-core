package shell

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
)

// awkBuiltin is mawk 1.3.4 (Ubuntu 22.04's awk): the whole language except what is listed in
// ubuntu2204.json's known gaps (the order of a for-in loop is sorted, not mawk's hash order). It is
// split over awk_parse.go (the front end), awk_run.go (statements and expressions), awk_builtins.go
// (functions and input) and awk_num.go (numbers and printf).

const awkUsage = `Usage: mawk [Options] [Program] [file ...]

Program:
    The -f option value is the name of a file containing program text.
    If no -f option is given, a "--" ends option processing; the following
    parameters are the program text.

Options:
    -f program-file  Program  text is read from file instead of from the
                     command-line.  Multiple -f options are accepted.
    -F value         sets the field separator, FS, to value.
    -v var=value     assigns value to program variable var.
    --               unambiguous end of options.

    Implementation-specific options are prefixed with "-W".  They can be
    abbreviated:

    -W version       show version information and exit.
    -W dump          show assembler-like listing of program and exit.
    -W help          show this message and exit.
    -W interactive   set unbuffered output, line-buffered input.
    -W exec file     use file as program as well as last option.
    -W random=number set initial random seed.
    -W sprintf=number adjust size of sprintf buffer.
    -W posix_space   do not consider "\n" a space.
    -W usage         show this message and exit.
`

func (s *Interpreter) awkBuiltin(args []string, stdin *string) (string, int) {
	fs := " "
	var assigns, progFiles []string
	var src string
	i := 0
	needArg := func(opt string) bool { return i+1 < len(args) || len(opt) > 2 }
	fail := func(msg string) (string, int) {
		s.pendingErr = append(s.pendingErr, "awk: "+msg)
		return "", 2
	}
opts:
	for ; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			i++
			break opts
		case a == "-W" || (strings.HasPrefix(a, "-W") && len(a) > 2):
			w := a[2:]
			if a == "-W" {
				if i+1 >= len(args) {
					return fail("option -W lacks argument")
				}
				i++
				w = args[i]
			}
			switch {
			case strings.HasPrefix(w, "v"):
				s.pendingErr = append(s.pendingErr, "random-funcs:       srandom/random", "regex-funcs:        internal", "compiled limits:", "sprintf buffer      8192", "maximum-integer     2147483647")
				s.noTrailingNewline = false
				return "mawk 1.3.4 20200120\r\nCopyright 2008-2019,2020, Thomas E. Dickey\r\nCopyright 1991-1996,2014, Michael D. Brennan\r\n", 0
			case strings.HasPrefix(w, "u"), strings.HasPrefix(w, "h"):
				return s.awkUsageOut(), 0
			}
		case a == "-F" || (strings.HasPrefix(a, "-F") && len(a) > 2):
			if !needArg(a) {
				return fail("option -F lacks argument")
			}
			if a == "-F" {
				i++
				fs = args[i]
			} else {
				fs = a[2:]
			}
			fs = awkUnescape(fs)
		case a == "-v" || (strings.HasPrefix(a, "-v") && len(a) > 2):
			if !needArg(a) {
				return fail("option -v lacks argument")
			}
			if a == "-v" {
				i++
				assigns = append(assigns, args[i])
			} else {
				assigns = append(assigns, a[2:])
			}
		case a == "-f" || (strings.HasPrefix(a, "-f") && len(a) > 2):
			if !needArg(a) {
				return fail("option -f lacks argument")
			}
			if a == "-f" {
				i++
				progFiles = append(progFiles, args[i])
			} else {
				progFiles = append(progFiles, a[2:])
			}
		case a == "-" || !strings.HasPrefix(a, "-"):
			break opts
		default:
			return fail("not an option: " + a)
		}
	}
	if len(progFiles) > 0 {
		var parts []string
		for _, f := range progFiles {
			text, ok := s.builtinInput(f, nil)
			if !ok {
				return fail("cannot open " + f + " (No such file or directory)")
			}
			parts = append(parts, text)
		}
		src = strings.Join(parts, "\n")
	} else {
		if i >= len(args) {
			return s.awkUsageOut(), 0
		}
		src = args[i]
		i++
	}
	var operands []awkOperand
	for _, a := range args[i:] {
		if name, _, ok := strings.Cut(a, "="); ok && name != "" && isIdentStart(name[0]) && strings.IndexFunc(name, func(r rune) bool { return r > 127 || !isIdentPart(byte(r)) }) < 0 {
			operands = append(operands, awkOperand{assign: a})
		} else {
			operands = append(operands, awkOperand{file: a})
		}
	}

	prog, err := parseAwk(src)
	if err != nil {
		return fail(err.Error())
	}
	rt := &awkRT{s: s, prog: prog, operands: operands, stdin: stdin, readers: map[string]*awkReader{},
		outs: map[string]*awkOutStream{}, re: map[string]*regexp.Regexp{}, seed: 1, rng: rand.New(rand.NewSource(1))}
	rt.fs, rt.ofs, rt.ors, rt.rs = rt.global("FS", fs), rt.global("OFS", " "), rt.global("ORS", "\n"), rt.global("RS", "\n")
	rt.subsep, rt.convfmt, rt.ofmt = rt.global("SUBSEP", "\x1c"), rt.global("CONVFMT", "%.6g"), rt.global("OFMT", "%.6g")
	rt.rstart, rt.rlength, rt.filename = rt.global("RSTART", ""), rt.global("RLENGTH", ""), rt.global("FILENAME", "")
	rt.rstart.val, rt.rlength.val = num(0), num(-1)
	rt.global("ENVIRON", "").arr = map[string]awkVal{}
	for k, v := range s.Env {
		rt.global("ENVIRON", "").arr[k] = strnum(v)
	}
	argv := map[string]awkVal{"0": str("awk")}
	for n, o := range operands {
		argv[fmt.Sprint(n+1)] = str(o.file + o.assign)
	}
	rt.global("ARGV", "").arr = argv
	rt.global("ARGC", "").val = num(float64(len(operands) + 1))
	for _, v := range assigns {
		if k, _, ok := strings.Cut(v, "="); ok && k != "" {
			rt.assignOperand(v)
		}
	}
	rt.setRecord("")

	code := rt.run()
	rt.closeAll()

	for _, l := range strings.Split(strings.TrimSuffix(rt.errs.String(), "\n"), "\n") {
		if l != "" {
			s.pendingErr = append(s.pendingErr, l)
		}
	}
	text := rt.out.String()
	s.noTrailingNewline = text != "" // awk's bytes are exact: no newline is added after them
	return strings.ReplaceAll(text, "\n", "\r\n"), code
}

func (s *Interpreter) awkUsageOut() string {
	for _, l := range strings.Split(strings.TrimSuffix(awkUsage, "\n"), "\n") {
		s.pendingErr = append(s.pendingErr, l)
	}
	return ""
}

// run executes the program and returns the exit status. A run-time error ends it with status 2 and
// mawk's message on stderr.
func (rt *awkRT) run() (code int) {
	defer func() {
		switch e := recover().(type) {
		case nil:
		case awkRuntimeErr:
			name := rt.filename.val.s
			if name == "" && rt.opened {
				name = "-"
			}
			rt.errs.WriteString(fmt.Sprintf("awk: run time error: %s\n\tFILENAME=\"%s\" FNR=%d NR=%d\n", string(e), name, rt.fnr, rt.nr))
			code = 2
		case awkFatal:
			rt.errs.WriteString("awk: " + string(e) + "\n")
			code = 2
		default:
			panic(e)
		}
	}()
	for _, b := range rt.prog.begins {
		if rt.exec(b) == flowExit {
			break
		}
	}
	if !rt.exiting && (len(rt.prog.rules) > 0 || len(rt.prog.ends) > 0) {
		rt.mainLoop()
	}
	rt.exiting = false
	for _, b := range rt.prog.ends {
		if rt.exec(b) == flowExit {
			break
		}
	}
	return rt.exitCode
}

func (rt *awkRT) mainLoop() {
	for {
		rec, ok := rt.nextMain()
		if !ok {
			return
		}
		rt.nr++
		rt.fnr++
		rt.setRecord(rec)
	rules:
		for _, r := range rt.prog.rules {
			if !rt.ruleMatches(r) {
				continue
			}
			if r.body == nil {
				rt.out.WriteString(rt.record() + rt.ors.val.s)
				continue
			}
			switch rt.exec(r.body) {
			case flowNext:
				break rules
			case flowNextFile:
				rt.cur = nil
				break rules
			case flowExit:
				return
			}
		}
		if rt.exiting {
			return
		}
	}
}

func (rt *awkRT) ruleMatches(r *awkRuleN) bool {
	if r.pat == nil {
		return true
	}
	if !r.isRange {
		return rt.eval(r.pat).truth()
	}
	if !r.active {
		if !rt.eval(r.pat).truth() {
			return false
		}
		r.active = !rt.eval(r.pat2).truth()
		return true
	}
	if rt.eval(r.pat2).truth() {
		r.active = false
	}
	return true
}
