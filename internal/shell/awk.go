package shell

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// awkBuiltin is the part of mawk 1.3.4 (Ubuntu 22.04's awk) that shell
// one-liners use: rules of pattern {action}, BEGIN/END, print/printf,
// fields, NR/NF/FNR, variables, arithmetic, comparisons, regex matches and
// length/substr/index/toupper/tolower/int. A program outside that subset
// gets mawk's syntax-error message, as a typo would.
func (s *Interpreter) awkBuiltin(args []string, stdin *string) (string, int) {
	fs := " "
	var vars []string
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			i++
		case a == "-F" && i+1 < len(args):
			i++
			fs = args[i]
			continue
		case strings.HasPrefix(a, "-F"):
			fs = a[2:]
			continue
		case a == "-v" && i+1 < len(args):
			i++
			vars = append(vars, args[i])
			continue
		case a == "-W" && i+1 < len(args) && strings.HasPrefix(args[i+1], "v"):
			return "mawk 1.3.4 20200120\r\nCopyright 2008-2019,2020, Thomas E. Dickey\r\nCopyright 1991-1996,2014, Michael D. Brennan\r\n\r\nrandom-funcs:       srandom/random\r\nregex-funcs:        internal\r\ncompiled limits:\r\nsprintf buffer      8192\r\nmaximum-integer     2147483647", 0
		}
		break
	}
	if i >= len(args) {
		return "Usage: mawk [Options] [Program] [file ...]", 2
	}
	prog, files := args[i], args[i+1:]

	p := &awkParser{src: prog, line: 1}
	rules, err := p.program()
	if err != nil {
		return "awk: " + err.Error(), 2
	}
	st := &awkState{vars: map[string]awkVal{}, fs: unescapeAwk(fs)}
	for _, v := range vars {
		if k, val, ok := strings.Cut(v, "="); ok {
			st.vars[k] = strnum(unescapeAwk(val))
		}
	}

	var out strings.Builder
	st.out = &out
	run := func(when int) {
		for _, r := range rules {
			if r.when == when {
				r.run(st)
			}
		}
	}
	run(awkBegin)
	inputs := []string{}
	if len(files) == 0 {
		if stdin != nil {
			inputs = append(inputs, *stdin)
		}
	} else {
		for _, f := range files {
			text, ok := s.builtinInput(f, nil)
			if !ok {
				s.pendingErr = append(s.pendingErr, "awk: cannot open "+f+" (No such file or directory)")
				return strings.ReplaceAll(out.String(), "\n", "\r\n"), 2
			}
			inputs = append(inputs, text)
		}
	}
	for _, text := range inputs {
		st.fnr = 0
		for _, line := range strings.SplitAfter(text, "\n") {
			if line == "" {
				continue
			}
			st.nr++
			st.fnr++
			st.setRecord(strings.TrimSuffix(line, "\n"))
			for _, r := range rules {
				if r.when == awkMain && (r.pattern == nil || r.pattern(st).truth()) {
					r.run(st)
				}
			}
		}
	}
	run(awkEnd)
	text := out.String()
	if strings.HasSuffix(text, "\n") {
		text = strings.TrimSuffix(text, "\n")
	} else if text != "" {
		s.noTrailingNewline = true
	}
	return strings.ReplaceAll(text, "\n", "\r\n"), 0
}

func unescapeAwk(s string) string {
	return strings.NewReplacer(`\t`, "\t", `\n`, "\n", `\\`, `\`).Replace(s)
}

// Values carry awk's dual nature: a number, a string, or a field that is
// compared as a number when it looks like one.
type awkVal struct {
	s     string
	n     float64
	isNum bool // a number, or a field/input value that looks like one
	isStr bool // has a string form
}

func num(n float64) awkVal   { return awkVal{n: n, isNum: true} }
func str(s string) awkVal    { return awkVal{s: s, isStr: true} }
func strnum(s string) awkVal { v := str(s); v.n, v.isNum = looksNumeric(s); return v }

func looksNumeric(s string) (float64, bool) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, false
	}
	n, err := strconv.ParseFloat(t, 64)
	return n, err == nil
}

// leadingNumber is awk's string-to-number: the longest numeric prefix.
func leadingNumber(s string) float64 {
	t := strings.TrimLeft(s, " \t\n")
	end := 0
	for end < len(t) && strings.IndexByte("+-0123456789.eE", t[end]) >= 0 {
		end++
	}
	for ; end > 0; end-- {
		if n, err := strconv.ParseFloat(t[:end], 64); err == nil {
			return n
		}
	}
	return 0
}

func (v awkVal) num() float64 {
	if v.isNum {
		return v.n
	}
	return leadingNumber(v.s)
}

func (v awkVal) str() string {
	if v.isStr {
		return v.s
	}
	return fmtNum(v.n)
}

func fmtNum(n float64) string {
	if n == math.Trunc(n) && math.Abs(n) < 1e16 {
		return strconv.FormatInt(int64(n), 10)
	}
	return strconv.FormatFloat(n, 'g', 6, 64)
}

func (v awkVal) truth() bool {
	if v.isStr && !v.isNum {
		return v.s != ""
	}
	if v.isStr && v.isNum {
		return v.n != 0
	}
	return v.n != 0
}

type awkState struct {
	vars    map[string]awkVal
	fields  []string // fields[0] is $0
	nr, fnr int
	fs      string
	out     *strings.Builder
}

func (st *awkState) setRecord(line string) {
	var f []string
	switch {
	case st.fs == " ":
		f = strings.Fields(line)
	case len(st.fs) == 1:
		f = strings.Split(line, st.fs)
	default:
		if re, err := regexp.Compile(st.fs); err == nil {
			f = re.Split(line, -1)
		} else {
			f = strings.Split(line, st.fs)
		}
	}
	if line == "" {
		f = nil
	}
	st.fields = append([]string{line}, f...)
}

func (st *awkState) field(i int) string {
	if i < 0 || i >= len(st.fields) {
		return ""
	}
	return st.fields[i]
}

const (
	awkMain = iota
	awkBegin
	awkEnd
)

type awkExpr func(*awkState) awkVal

type awkRule struct {
	when    int
	pattern awkExpr
	action  []func(*awkState)
}

func (r awkRule) run(st *awkState) {
	if r.action == nil {
		fmt.Fprintln(st.out, st.field(0))
		return
	}
	for _, a := range r.action {
		a(st)
	}
}

type awkErr string

func (e awkErr) Error() string { return string(e) }

// awkParser is a recursive-descent parser over the program text.
type awkParser struct {
	src  string
	pos  int
	line int
}

func (p *awkParser) fail(near string) error {
	if near == "" {
		near = "end of file"
	}
	return awkErr(fmt.Sprintf("line %d: syntax error at or near %s", p.line, near))
}

// skip passes spaces and, when nl, newlines and semicolons too.
func (p *awkParser) skip(nl bool) {
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch {
		case c == ' ' || c == '\t':
		case c == '\n' && nl:
			p.line++
		case c == ';' && nl:
		case c == '#':
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
			continue
		default:
			return
		}
		p.pos++
	}
}

func (p *awkParser) peek() string {
	p.skip(false)
	if p.pos >= len(p.src) {
		return ""
	}
	for _, op := range []string{"&&", "||", "==", "!=", "<=", ">=", "+=", "-=", "*=", "/=", "++", "--", "!~"} {
		if strings.HasPrefix(p.src[p.pos:], op) {
			return op
		}
	}
	c := p.src[p.pos]
	if isIdentStart(c) {
		j := p.pos
		for j < len(p.src) && isIdentPart(p.src[j]) {
			j++
		}
		return p.src[p.pos:j]
	}
	return string(c)
}

func (p *awkParser) accept(tok string) bool {
	if p.peek() == tok {
		p.pos += len(tok)
		return true
	}
	return false
}

func (p *awkParser) program() ([]awkRule, error) {
	var rules []awkRule
	for {
		p.skip(true)
		if p.pos >= len(p.src) {
			return rules, nil
		}
		r := awkRule{when: awkMain}
		switch p.peek() {
		case "BEGIN":
			p.pos += 5
			r.when = awkBegin
		case "END":
			p.pos += 3
			r.when = awkEnd
		case "{":
		default:
			pat, err := p.expr()
			if err != nil {
				return nil, err
			}
			r.pattern = pat
		}
		if p.peek() == "{" {
			act, err := p.block()
			if err != nil {
				return nil, err
			}
			r.action = act
		} else if r.when != awkMain {
			return nil, p.fail(p.peek())
		}
		rules = append(rules, r)
	}
}

func (p *awkParser) block() ([]func(*awkState), error) {
	p.accept("{")
	var stmts []func(*awkState)
	for {
		p.skip(true)
		if p.pos >= len(p.src) {
			return nil, awkErr(fmt.Sprintf("line %d: missing } near end of file", p.line+1))
		}
		if p.accept("}") {
			if stmts == nil {
				stmts = []func(*awkState){}
			}
			return stmts, nil
		}
		st, err := p.statement()
		if err != nil {
			return nil, err
		}
		stmts = append(stmts, st)
	}
}

func (p *awkParser) statement() (func(*awkState), error) {
	switch p.peek() {
	case "print":
		p.pos += 5
		var list []awkExpr
		for t := p.peek(); t != "" && t != ";" && t != "}" && t != "\n"; t = p.peek() {
			e, err := p.concat()
			if err != nil {
				return nil, err
			}
			list = append(list, e)
			if !p.accept(",") {
				break
			}
		}
		if t := p.peek(); t != "" && t != ";" && t != "}" && t != "\n" {
			return nil, p.fail(t) // e.g. print > file: not supported
		}
		return func(st *awkState) {
			if len(list) == 0 {
				fmt.Fprintln(st.out, st.field(0))
				return
			}
			parts := make([]string, len(list))
			for i, e := range list {
				parts[i] = e(st).str()
			}
			fmt.Fprintln(st.out, strings.Join(parts, " "))
		}, nil
	case "printf":
		p.pos += 6
		var list []awkExpr
		for {
			e, err := p.concat()
			if err != nil {
				return nil, err
			}
			list = append(list, e)
			if !p.accept(",") {
				break
			}
		}
		return func(st *awkState) {
			args := make([]string, len(list)-1)
			for i, e := range list[1:] {
				args[i] = e(st).str()
			}
			sh := &Interpreter{}
			out, _ := sh.printfBuiltin(append([]string{list[0](st).str()}, args...))
			out = strings.ReplaceAll(out, "\r\n", "\n")
			if !sh.noTrailingNewline {
				out += "\n"
			}
			st.out.WriteString(out)
		}, nil
	}
	e, err := p.expr()
	if err != nil {
		return nil, err
	}
	return func(st *awkState) { e(st) }, nil
}

func (p *awkParser) expr() (awkExpr, error) {
	// assignment: NAME op= expr
	save := p.pos
	if name := p.peek(); name != "" && isIdentStart(name[0]) && !awkReserved[name] {
		p.pos += len(name)
		for _, op := range []string{"+=", "-=", "*=", "/=", "="} {
			if p.peek() == op && !(op == "=" && strings.HasPrefix(p.src[p.pos:], "==")) {
				p.pos += len(op)
				rhs, err := p.expr()
				if err != nil {
					return nil, err
				}
				return func(st *awkState) awkVal {
					v := rhs(st)
					if op != "=" {
						v = num(arith(op[:1], st.vars[name].num(), v.num()))
					}
					st.vars[name] = v
					return v
				}, nil
			}
		}
		if p.accept("++") || p.accept("--") {
			inc := 1.0
			if p.src[p.pos-1] == '-' {
				inc = -1
			}
			return func(st *awkState) awkVal {
				old := st.vars[name].num()
				st.vars[name] = num(old + inc)
				return num(old)
			}, nil
		}
		p.pos = save
	}
	return p.or()
}

var awkReserved = map[string]bool{"print": true, "printf": true, "BEGIN": true, "END": true}

func (p *awkParser) or() (awkExpr, error) {
	l, err := p.and()
	for err == nil && p.accept("||") {
		r, e := p.and()
		if e != nil {
			return nil, e
		}
		a := l
		l = func(st *awkState) awkVal { return boolVal(a(st).truth() || r(st).truth()) }
	}
	return l, err
}

func (p *awkParser) and() (awkExpr, error) {
	l, err := p.match()
	for err == nil && p.accept("&&") {
		r, e := p.match()
		if e != nil {
			return nil, e
		}
		a := l
		l = func(st *awkState) awkVal { return boolVal(a(st).truth() && r(st).truth()) }
	}
	return l, err
}

func (p *awkParser) match() (awkExpr, error) {
	l, err := p.compare()
	if err != nil {
		return nil, err
	}
	for {
		neg := false
		switch {
		case p.accept("!~"):
			neg = true
		case p.peek() == "~":
			p.pos++
		default:
			return l, nil
		}
		re, err := p.regexOperand()
		if err != nil {
			return nil, err
		}
		a := l
		l = func(st *awkState) awkVal { return boolVal(re(st).MatchString(a(st).str()) != neg) }
	}
}

// regexOperand is the right side of ~: a /literal/ or any expression.
func (p *awkParser) regexOperand() (func(*awkState) *regexp.Regexp, error) {
	if p.peek() == "/" {
		re, err := p.regexLiteral()
		if err != nil {
			return nil, err
		}
		return func(*awkState) *regexp.Regexp { return re }, nil
	}
	e, err := p.concat()
	if err != nil {
		return nil, err
	}
	return func(st *awkState) *regexp.Regexp {
		re, err := regexp.Compile(e(st).str())
		if err != nil {
			return regexp.MustCompile(regexp.QuoteMeta(e(st).str()))
		}
		return re
	}, nil
}

func (p *awkParser) compare() (awkExpr, error) {
	l, err := p.concat()
	if err != nil {
		return nil, err
	}
	for _, op := range []string{"==", "!=", "<=", ">=", "<", ">"} {
		if p.accept(op) {
			r, err := p.concat()
			if err != nil {
				return nil, err
			}
			return func(st *awkState) awkVal {
				a, b := l(st), r(st)
				var c int
				if a.isNum && b.isNum {
					switch x, y := a.num(), b.num(); {
					case x < y:
						c = -1
					case x > y:
						c = 1
					}
				} else {
					c = strings.Compare(a.str(), b.str())
				}
				return boolVal(map[string]bool{"==": c == 0, "!=": c != 0, "<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0}[op])
			}, nil
		}
	}
	return l, nil
}

// concat is juxtaposition: `$1 $2` and `NR": "$0`.
func (p *awkParser) concat() (awkExpr, error) {
	l, err := p.additive()
	if err != nil {
		return nil, err
	}
	for p.startsOperand() {
		r, err := p.additive()
		if err != nil {
			return nil, err
		}
		a := l
		l = func(st *awkState) awkVal { return str(a(st).str() + r(st).str()) }
	}
	return l, nil
}

func (p *awkParser) startsOperand() bool {
	t := p.peek()
	if t == "" {
		return false
	}
	c := t[0]
	return c == '$' || c == '"' || c == '(' || (c >= '0' && c <= '9') || c == '.' ||
		(isIdentStart(c) && !awkReserved[t]) || (c == '!' && t == "!")
}

func (p *awkParser) additive() (awkExpr, error) {
	l, err := p.term()
	for err == nil {
		t := p.peek()
		if (t != "+" && t != "-") || strings.HasPrefix(p.src[p.pos:], "++") || strings.HasPrefix(p.src[p.pos:], "--") {
			return l, nil
		}
		p.pos++
		r, e := p.term()
		if e != nil {
			return nil, e
		}
		a := l
		l = func(st *awkState) awkVal { return num(arith(t, a(st).num(), r(st).num())) }
	}
	return nil, err
}

func (p *awkParser) term() (awkExpr, error) {
	l, err := p.unary()
	for err == nil {
		t := p.peek()
		if t != "*" && t != "/" && t != "%" {
			return l, nil
		}
		p.pos++
		r, e := p.unary()
		if e != nil {
			return nil, e
		}
		a := l
		l = func(st *awkState) awkVal { return num(arith(t, a(st).num(), r(st).num())) }
	}
	return nil, err
}

func arith(op string, a, b float64) float64 {
	switch op {
	case "+":
		return a + b
	case "-":
		return a - b
	case "*":
		return a * b
	case "/":
		if b == 0 {
			return math.Inf(1)
		}
		return a / b
	case "%":
		return math.Mod(a, b)
	}
	return 0
}

func (p *awkParser) unary() (awkExpr, error) {
	switch p.peek() {
	case "!":
		p.pos++
		e, err := p.unary()
		if err != nil {
			return nil, err
		}
		return func(st *awkState) awkVal { return boolVal(!e(st).truth()) }, nil
	case "-":
		p.pos++
		e, err := p.unary()
		if err != nil {
			return nil, err
		}
		return func(st *awkState) awkVal { return num(-e(st).num()) }, nil
	}
	return p.primary()
}

func boolVal(b bool) awkVal {
	if b {
		return num(1)
	}
	return num(0)
}

func (p *awkParser) regexLiteral() (*regexp.Regexp, error) {
	p.skip(false)
	start := p.pos + 1
	j := start
	for j < len(p.src) && p.src[j] != '/' {
		if p.src[j] == '\\' {
			j++
		}
		j++
	}
	if j >= len(p.src) {
		return nil, awkErr(fmt.Sprintf("line %d: runaway regular expression /%s ...", p.line, p.src[start:min(start+10, len(p.src))]))
	}
	p.pos = j + 1
	re, err := regexp.Compile(p.src[start:j])
	if err != nil {
		return nil, awkErr(fmt.Sprintf("line %d: regular expression compile failed (%s)", p.line, p.src[start:j]))
	}
	return re, nil
}

func (p *awkParser) primary() (awkExpr, error) {
	t := p.peek()
	switch {
	case t == "":
		return nil, p.fail("")
	case t == "/":
		re, err := p.regexLiteral()
		if err != nil {
			return nil, err
		}
		return func(st *awkState) awkVal { return boolVal(re.MatchString(st.field(0))) }, nil
	case t == "$":
		p.pos++
		e, err := p.primary()
		if err != nil {
			return nil, err
		}
		return func(st *awkState) awkVal { return strnum(st.field(int(e(st).num()))) }, nil
	case t == "(":
		p.pos++
		e, err := p.expr()
		if err != nil {
			return nil, err
		}
		if !p.accept(")") {
			return nil, awkErr(fmt.Sprintf("line %d: missing ) near %s", p.line, p.peek()))
		}
		return e, nil
	case t == "\"":
		j := p.pos + 1
		var b strings.Builder
		for j < len(p.src) && p.src[j] != '"' {
			if p.src[j] == '\\' && j+1 < len(p.src) {
				j++
				switch p.src[j] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				default:
					b.WriteByte(p.src[j])
				}
			} else {
				b.WriteByte(p.src[j])
			}
			j++
		}
		if j >= len(p.src) {
			return nil, awkErr(fmt.Sprintf("line %d: runaway string constant \"%s ...", p.line, p.src[p.pos+1:min(p.pos+11, len(p.src))]))
		}
		p.pos = j + 1
		v := str(b.String())
		return func(*awkState) awkVal { return v }, nil
	case (t[0] >= '0' && t[0] <= '9') || t[0] == '.':
		j := p.pos
		for j < len(p.src) && strings.IndexByte("0123456789.eE", p.src[j]) >= 0 {
			j++
		}
		n, err := strconv.ParseFloat(p.src[p.pos:j], 64)
		if err != nil {
			return nil, p.fail(p.src[p.pos:j])
		}
		p.pos = j
		return func(*awkState) awkVal { return num(n) }, nil
	case isIdentStart(t[0]) && !awkReserved[t]:
		p.pos += len(t)
		if (t == "sub" || t == "gsub") && p.peek() == "(" {
			return p.subCall(t == "gsub")
		}
		if fn, ok := awkFuncs[t]; ok {
			var args []awkExpr
			if p.accept("(") {
				for p.peek() != ")" {
					e, err := p.expr()
					if err != nil {
						return nil, err
					}
					args = append(args, e)
					if !p.accept(",") {
						break
					}
				}
				if !p.accept(")") {
					return nil, awkErr(fmt.Sprintf("line %d: missing ) near %s", p.line, p.peek()))
				}
			}
			return func(st *awkState) awkVal {
				vals := make([]awkVal, len(args))
				for i, a := range args {
					vals[i] = a(st)
				}
				return fn(st, vals)
			}, nil
		}
		if p.peek() == "(" {
			return nil, p.fail(t) // user-defined functions are not supported
		}
		switch t {
		case "NR":
			return func(st *awkState) awkVal { return num(float64(st.nr)) }, nil
		case "FNR":
			return func(st *awkState) awkVal { return num(float64(st.fnr)) }, nil
		case "NF":
			return func(st *awkState) awkVal { return num(float64(len(st.fields) - 1)) }, nil
		}
		return func(st *awkState) awkVal { return st.vars[t] }, nil
	}
	return nil, p.fail(t)
}

var awkFuncs = map[string]func(*awkState, []awkVal) awkVal{
	"length": func(st *awkState, a []awkVal) awkVal {
		if len(a) == 0 {
			return num(float64(len(st.field(0))))
		}
		return num(float64(len(a[0].str())))
	},
	"toupper": func(_ *awkState, a []awkVal) awkVal { return str(strings.ToUpper(arg(a, 0).str())) },
	"tolower": func(_ *awkState, a []awkVal) awkVal { return str(strings.ToLower(arg(a, 0).str())) },
	"int":     func(_ *awkState, a []awkVal) awkVal { return num(math.Trunc(arg(a, 0).num())) },
	"index": func(_ *awkState, a []awkVal) awkVal {
		return num(float64(strings.Index(arg(a, 0).str(), arg(a, 1).str()) + 1))
	},
	"substr": func(_ *awkState, a []awkVal) awkVal {
		s := arg(a, 0).str()
		start := int(math.Round(arg(a, 1).num()))
		end := len(s) + 1
		if len(a) > 2 {
			end = start + int(math.Round(a[2].num()))
		}
		start = max(start, 1)
		end = min(end, len(s)+1)
		if start >= end {
			return str("")
		}
		return str(s[start-1 : end-1])
	},
}

func arg(a []awkVal, i int) awkVal {
	if i < len(a) {
		return a[i]
	}
	return str("")
}

// subCall parses sub(re, repl [, target]) and gsub(re, repl [, target]).
// target is $0, $N or a variable and is assigned the result; the call's value
// is the number of replacements made.
func (p *awkParser) subCall(global bool) (awkExpr, error) {
	if !p.accept("(") {
		return nil, p.fail("sub")
	}
	var reOf func(*awkState) *regexp.Regexp
	if p.peek() == "/" {
		re, err := p.regexLiteral()
		if err != nil {
			return nil, err
		}
		reOf = func(*awkState) *regexp.Regexp { return re }
	} else {
		e, err := p.expr()
		if err != nil {
			return nil, err
		}
		reOf = func(st *awkState) *regexp.Regexp {
			re, err := regexp.Compile(e(st).str())
			if err != nil {
				return nil
			}
			return re
		}
	}
	if !p.accept(",") {
		return nil, p.fail(p.peek())
	}
	repl, err := p.expr()
	if err != nil {
		return nil, err
	}
	get := func(st *awkState) string { return st.field(0) }
	set := func(st *awkState, v string) { st.setRecord(v) }
	if p.accept(",") {
		switch t := p.peek(); {
		case t == "$":
			p.pos++
			idx, err := p.primary()
			if err != nil {
				return nil, err
			}
			get = func(st *awkState) string { return st.field(int(idx(st).num())) }
			set = func(st *awkState, v string) {
				n := int(idx(st).num())
				if n == 0 {
					st.setRecord(v)
					return
				}
				for len(st.fields) <= n {
					st.fields = append(st.fields, "")
				}
				st.fields[n] = v
				st.fields[0] = strings.Join(st.fields[1:], " ")
			}
		case t != "" && isIdentStart(t[0]):
			p.pos += len(t)
			get = func(st *awkState) string { return st.vars[t].str() }
			set = func(st *awkState, v string) { st.vars[t] = str(v) }
		default:
			return nil, p.fail(t)
		}
	}
	if !p.accept(")") {
		return nil, awkErr(fmt.Sprintf("line %d: missing ) near %s", p.line, p.peek()))
	}
	return func(st *awkState) awkVal {
		re := reOf(st)
		if re == nil {
			return num(0)
		}
		src, r := get(st), repl(st).str()
		count := 0
		var out strings.Builder
		pos := 0
		for pos <= len(src) {
			m := re.FindStringIndex(src[pos:])
			if m == nil {
				break
			}
			lo, hi := pos+m[0], pos+m[1]
			out.WriteString(src[pos:lo])
			for i := 0; i < len(r); i++ {
				switch {
				case r[i] == '\\' && i+1 < len(r) && r[i+1] == '&':
					out.WriteByte('&')
					i++
				case r[i] == '&':
					out.WriteString(src[lo:hi])
				default:
					out.WriteByte(r[i])
				}
			}
			count++
			if hi == lo { // empty match: step over one byte
				if lo < len(src) {
					out.WriteByte(src[lo])
				}
				pos = hi + 1
			} else {
				pos = hi
			}
			if !global {
				break
			}
		}
		if pos <= len(src) {
			out.WriteString(src[pos:])
		}
		if count > 0 {
			set(st, out.String())
		}
		return num(float64(count))
	}, nil
}
