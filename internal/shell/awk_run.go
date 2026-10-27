package shell

import (
	"fmt"
	"math"
	"math/rand"
	"regexp"
	"strings"
)

// The awk runtime: a tree-walking interpreter over what awk_parse.go builds. Behaviour follows mawk 1.3.4
// (Ubuntu 22.04's awk), checked against the real thing by testdata/ubuntu2204.json.

// awkVal is a value with awk's dual nature: a number, a string, or text from input that compares as a
// number when it looks like one ("strnum"). An unset variable is both "" and 0.
type awkVal struct {
	s     string
	n     float64
	isNum bool // a number, or input text that looks like one, or unset
	isStr bool // has a string form of its own
}

func num(n float64) awkVal { return awkVal{n: n, isNum: true} }
func str(s string) awkVal  { return awkVal{s: s, isStr: true} }
func uninit() awkVal       { return awkVal{isNum: true, isStr: true} }
func strnum(s string) awkVal {
	n, ok := awkLooksNumeric(s)
	return awkVal{s: s, n: n, isNum: ok, isStr: true}
}

func (v awkVal) num() float64 {
	if v.isNum {
		return v.n
	}
	return awkToNum(v.s)
}

func (v awkVal) truth() bool {
	if v.isStr && !v.isNum {
		return v.s != ""
	}
	return v.n != 0
}

// str is the string form with the default CONVFMT; the runtime's toStr honours a changed CONVFMT.
func (v awkVal) str() string {
	if v.isStr {
		return v.s
	}
	return awkNumStr(v.n, "%.6g")
}

type awkErr string

func (e awkErr) Error() string { return string(e) }

// awkCell holds a variable. It is untyped until it is used as a scalar or an array. ref makes a function
// parameter an alias of the caller's untyped variable until the callee decides which it is.
type awkCell struct {
	name string
	val  awkVal
	set  bool
	arr  map[string]awkVal
	ref  *awkCell
}

func (c *awkCell) scalar() awkVal {
	if c.ref != nil {
		return uninit()
	}
	if c.set {
		return c.val
	}
	return uninit()
}

func (c *awkCell) asArray() map[string]awkVal {
	if c.ref != nil {
		t := c.ref
		c.ref = nil
		a := t.asArray()
		c.arr = a
		return a
	}
	if c.arr == nil && !c.set {
		c.arr = map[string]awkVal{}
	}
	return c.arr
}

type awkFlow int

const (
	flowNone awkFlow = iota
	flowBreak
	flowContinue
	flowNext
	flowNextFile
	flowExit
	flowReturn
)

type awkRuntimeErr string

type awkReader struct {
	text string
	pos  int
}

type awkOutStream struct {
	buf      strings.Builder
	appendTo bool
	pipe     bool
}

type awkOperand struct {
	file   string
	assign string
}

type awkRT struct {
	s    *Interpreter
	prog *awkProgram
	out  strings.Builder
	errs strings.Builder

	rec     string
	recFS   string // FS when the record was read: a later change to FS applies from the next record
	fmtFn   string // "printf" or "sprintf", for error messages
	recOK   bool
	fields  []string
	nf      int
	splitOK bool
	nr, fnr int

	fs, ofs, ors, rs, subsep, convfmt, ofmt *awkCell
	rstart, rlength, filename               *awkCell

	frames   [][]*awkCell
	retVal   awkVal
	exiting  bool
	exitCode int

	operands []awkOperand
	opIdx    int
	cur      *awkReader
	opened   bool // some input source has been opened (stdin is used when no file operand is given)
	stdin    *string
	mainDone bool

	readers map[string]*awkReader
	outs    map[string]*awkOutStream
	steps   int
	re      map[string]*regexp.Regexp
	rng     *rand.Rand
	seed    float64
	loops   int
}

const awkMaxSteps = 20_000_000

func (rt *awkRT) failf(format string, a ...any) { // safe on a nil *awkRT

	panic(awkRuntimeErr(fmt.Sprintf(format, a...)))
}

func (rt *awkRT) tick() {
	if rt.steps++; rt.steps > awkMaxSteps {
		rt.failf("program ran too long")
	}
}

func (rt *awkRT) global(name string, init string) *awkCell {
	c := rt.prog.globals[name]
	if c == nil {
		c = &awkCell{name: name}
		rt.prog.globals[name] = c
	}
	if !c.set && c.arr == nil {
		c.val, c.set = str(init), true
	}
	return c
}

func (rt *awkRT) toStr(v awkVal) string {
	if v.isStr {
		return v.s
	}
	return awkNumStr(v.n, rt.convfmt.val.s)
}

func (rt *awkRT) toOut(v awkVal) string {
	if v.isStr {
		return v.s
	}
	return awkNumStr(v.n, rt.ofmt.val.s)
}

// ---- records and fields ----

func (rt *awkRT) setRecord(s string) {
	rt.rec, rt.recOK, rt.splitOK, rt.recFS = s, true, false, rt.fs.val.s
}

func (rt *awkRT) ensureSplit() {
	if rt.splitOK {
		return
	}
	rt.splitOK = true
	rec := rt.rec
	if !rt.recOK {
		rec = rt.record()
	}
	rt.fields = append(rt.fields[:0], "")
	if rec != "" {
		rt.fields = append(rt.fields, rt.splitString(rec, rt.recFS, rt.rs.val.s == "")...)
	}
	rt.nf = len(rt.fields) - 1
}

func (rt *awkRT) record() string {
	if !rt.recOK {
		rt.rec = strings.Join(rt.fields[1:rt.nf+1], rt.ofs.val.s)
		rt.recOK = true
	}
	return rt.rec
}

func (rt *awkRT) getField(i int) awkVal {
	if i < 0 {
		rt.failf("negative field index $%d", i)
	}
	if i == 0 {
		return strnum(rt.record())
	}
	rt.ensureSplit()
	if i > rt.nf {
		return strnum("") // a field that is not there is the empty string, not an unset variable
	}
	return strnum(rt.fields[i])
}

func (rt *awkRT) setField(i int, v string) {
	if i < 0 {
		rt.failf("negative field index $%d", i)
	}
	if i == 0 {
		rt.setRecord(v)
		return
	}
	rt.ensureSplit()
	rt.growTo(i)
	rt.fields[i] = v
	rt.recOK = false
}

func (rt *awkRT) growTo(n int) {
	for rt.nf < n {
		rt.fields = append(rt.fields[:rt.nf+1], "")
		rt.nf++
	}
}

func (rt *awkRT) setNF(n int) {
	rt.ensureSplit()
	if n < 0 {
		n = 0
	}
	if n > rt.nf {
		rt.growTo(n)
	} else {
		rt.nf = n
		rt.fields = rt.fields[:n+1]
	}
	rt.recOK = false
}

// splitString splits s into fields for FS (or split()'s third argument). " " splits on runs of white
// space; any other string is a regular expression, but a single character is taken literally.
func (rt *awkRT) splitString(s, fs string, paragraph bool) []string {
	if s == "" {
		return nil
	}
	switch {
	case fs == " ":
		return strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' })
	case fs == "":
		out := make([]string, 0, len(s))
		for i := 0; i < len(s); i++ {
			out = append(out, s[i:i+1])
		}
		return out
	case len(fs) == 1 && fs != "\\":
		if paragraph {
			return regexSplit(rt.compile("["+regexp.QuoteMeta(fs)+"\n]"), s)
		}
		return strings.Split(s, fs)
	}
	return regexSplit(rt.compile(fs), s)
}

func regexSplit(re *regexp.Regexp, s string) []string {
	var out []string
	last := 0
	for _, m := range re.FindAllStringIndex(s, -1) {
		if m[1] == m[0] {
			continue // an empty match separates nothing
		}
		out = append(out, s[last:m[0]])
		last = m[1]
	}
	return append(out, s[last:])
}

// ---- regular expressions ----

// compile turns an awk (POSIX ERE) pattern into a Go regexp: . matches newline, and the longest match wins.
func (rt *awkRT) compile(src string) *regexp.Regexp {
	if re, ok := rt.re[src]; ok {
		return re
	}
	reason := awkRegexCheck(src)
	var re *regexp.Regexp
	if reason == "" {
		var err error
		if re, err = regexp.Compile("(?s)" + awkRegexTranslate(src)); err != nil {
			reason = reasonOf(err)
		}
	}
	if reason != "" {
		panic(awkFatal("line 1: regular expression compile failed (" + reason + ")\n" + src))
	}
	re.Longest()
	rt.re[src] = re
	return re
}

func reasonOf(err error) string {
	m := err.Error()
	switch {
	case strings.Contains(m, "missing closing )"):
		return "missing )"
	case strings.Contains(m, "unexpected )"):
		return "missing ("
	case strings.Contains(m, "missing argument to repetition"):
		return "missing operand"
	}
	return "bad regular expression"
}

// awkRegexCheck finds what mawk refuses and Go accepts: an operator with nothing to apply to, as in
// "z|", "()" or a leading "+". It returns mawk's reason, or "" when the pattern is fine.
func awkRegexCheck(src string) string {
	operand, inBracket := false, false
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case inBracket:
			if c == '\\' {
				i++
			} else if c == ']' {
				inBracket = false
			}
		case c == '\\':
			i++
			operand = true
		case c == '[':
			inBracket, operand = true, true
			if i+1 < len(src) && src[i+1] == '^' {
				i++
			}
			if i+1 < len(src) && src[i+1] == ']' {
				i++
			}
		case c == '(':
			operand = false
		case c == ')':
			if !operand {
				return "missing operand"
			}
		case c == '|':
			if !operand {
				return "missing operand"
			}
			operand = false
		case c == '*' || c == '+' || c == '?':
			if !operand {
				return "missing operand"
			}
		default:
			operand = true
		}
	}
	if src != "" && !operand {
		return "missing operand"
	}
	return ""
}

// awkRegexTranslate rewrites the corners where mawk's patterns differ from Go's: an escape of a letter it
// does not define means the letter itself, and braces are literal characters.
func awkRegexTranslate(src string) string {
	var b strings.Builder
	inBracket := false
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '\\' && i+1 < len(src):
			i++
			e := src[i]
			switch {
			case strings.IndexByte("tnrfva", e) >= 0, e >= '0' && e <= '7':
				b.WriteByte('\\')
				b.WriteByte(e)
			case e >= 'A' && e <= 'Z', e >= 'a' && e <= 'z', e >= '8' && e <= '9':
				b.WriteByte(e)
			default:
				b.WriteByte('\\')
				b.WriteByte(e)
			}
		case inBracket:
			if c == ']' {
				inBracket = false
			}
			if c == '[' && i+1 < len(src) && src[i+1] == ':' {
				if k := strings.Index(src[i:], ":]"); k > 0 {
					b.WriteString(src[i : i+k+2])
					i += k + 1
					continue
				}
			}
			b.WriteByte(c)
		case c == '[':
			inBracket = true
			b.WriteByte(c)
			if i+1 < len(src) && src[i+1] == '^' {
				b.WriteByte('^')
				i++
			}
			if i+1 < len(src) && src[i+1] == ']' {
				b.WriteString(`\]`)
				i++
			}
		case c == '{' || c == '}':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// regexOf is the pattern a regex-valued operand stands for: a /literal/ as written, anything else as a
// dynamic string.
func (rt *awkRT) regexOf(n *awkNode) *regexp.Regexp {
	if n.op == opRegex {
		return rt.compile(n.str)
	}
	return rt.compile(rt.toStr(rt.eval(n)))
}

// ---- running ----

func (rt *awkRT) cellOf(n *awkNode) *awkCell {
	switch n.op {
	case opVar:
		return n.cell
	case opLocal:
		return rt.frames[len(rt.frames)-1][n.idx]
	}
	rt.failf("not a variable")
	return nil
}

func (rt *awkRT) arrayOf(n *awkNode) map[string]awkVal {
	c := rt.cellOf(n)
	a := c.asArray()
	if a == nil {
		rt.failf("can't use scalar %s as array", c.name)
	}
	return a
}

func (rt *awkRT) subscript(args []*awkNode) string {
	if len(args) == 1 {
		return rt.toStr(rt.eval(args[0]))
	}
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = rt.toStr(rt.eval(a))
	}
	return strings.Join(parts, rt.subsep.val.s)
}

type awkRef struct {
	get func() awkVal
	set func(awkVal)
}

// ref resolves an lvalue once, so that a[i++] += 1 evaluates its subscript a single time.
func (rt *awkRT) ref(n *awkNode) awkRef {
	switch n.op {
	case opVar, opLocal:
		c := rt.cellOf(n)
		return awkRef{
			get: func() awkVal {
				if c.arr != nil {
					rt.failf("can't use array %s in scalar context", c.name)
				}
				return c.scalar()
			},
			set: func(v awkVal) {
				if c.arr != nil {
					rt.failf("can't assign to %s; it's an array name.", c.name)
				}
				c.ref, c.val, c.set = nil, v, true
			},
		}
	case opSpecial:
		return awkRef{
			get: func() awkVal { return rt.eval(n) },
			set: func(v awkVal) {
				switch n.sub {
				case spNF:
					rt.setNF(int(v.num()))
				case spNR:
					rt.nr = int(v.num())
				case spFNR:
					rt.fnr = int(v.num())
				}
			},
		}
	case opIndex:
		arr, key := rt.arrayOf(n.a), rt.subscript(n.args)
		return awkRef{
			get: func() awkVal {
				v, ok := arr[key]
				if !ok {
					v = uninit()
					arr[key] = v
				}
				return v
			},
			set: func(v awkVal) { arr[key] = v },
		}
	case opField:
		i := int(rt.eval(n.a).num())
		return awkRef{
			get: func() awkVal { return rt.getField(i) },
			set: func(v awkVal) { rt.setField(i, rt.toStr(v)) },
		}
	case opGroup:
		return rt.ref(n.a)
	}
	rt.failf("not an lvalue")
	return awkRef{}
}

func boolNum(b bool) awkVal {
	if b {
		return num(1)
	}
	return num(0)
}

func (rt *awkRT) compare(op string, a, b awkVal) bool {
	var c int
	if a.isNum && b.isNum {
		// mawk orders numbers by the sign of the difference, so a NaN is "equal" to everything
		switch {
		case a.n > b.n:
			c = 1
		case a.n < b.n:
			c = -1
		}
	} else {
		c = strings.Compare(rt.toStr(a), rt.toStr(b))
	}
	switch op {
	case "<":
		return c < 0
	case "<=":
		return c <= 0
	case "==":
		return c == 0
	case "!=":
		return c != 0
	case ">":
		return c > 0
	}
	return c >= 0
}

func (rt *awkRT) eval(n *awkNode) awkVal {
	switch n.op {
	case opNum:
		return num(n.num)
	case opStr:
		return str(n.str)
	case opRegex:
		return boolNum(rt.compile(n.str).MatchString(rt.record()))
	case opVar, opLocal:
		c := rt.cellOf(n)
		if c.arr != nil {
			rt.failf("can't use array %s in scalar context", c.name)
		}
		return c.scalar()
	case opSpecial:
		switch n.sub {
		case spNF:
			rt.ensureSplit()
			return num(float64(rt.nf))
		case spNR:
			return num(float64(rt.nr))
		}
		return num(float64(rt.fnr))
	case opIndex:
		arr, key := rt.arrayOf(n.a), rt.subscript(n.args)
		v, ok := arr[key]
		if !ok {
			v = uninit()
			arr[key] = v
		}
		return v
	case opField:
		return rt.getField(int(rt.eval(n.a).num()))
	case opGroup:
		return rt.eval(n.a)
	case opAssign:
		r := rt.ref(n.a)
		v := rt.eval(n.b)
		if n.subStr != "" {
			v = num(rt.arith(n.subStr, r.get().num(), v.num()))
		}
		r.set(v)
		return v
	case opCond:
		if rt.eval(n.a).truth() {
			return rt.eval(n.b)
		}
		return rt.eval(n.c)
	case opOr:
		return boolNum(rt.eval(n.a).truth() || rt.eval(n.b).truth())
	case opAnd:
		return boolNum(rt.eval(n.a).truth() && rt.eval(n.b).truth())
	case opIn:
		_, ok := rt.arrayOf(n.b)[rt.subscript(n.args)]
		return boolNum(ok)
	case opMatch, opNoMatch:
		s := rt.toStr(rt.eval(n.a))
		m := rt.regexOf(n.b).MatchString(s)
		return boolNum(m == (n.op == opMatch))
	case opCmp:
		a := rt.eval(n.a)
		b := rt.eval(n.b)
		return boolNum(rt.compare(n.subStr, a, b))
	case opConcat:
		a := rt.toStr(rt.eval(n.a))
		return str(a + rt.toStr(rt.eval(n.b)))
	case opBinary:
		a := rt.eval(n.a).num()
		b := rt.eval(n.b).num()
		return num(rt.arith(n.subStr, a, b))
	case opNeg:
		return num(-rt.eval(n.a).num())
	case opPlus:
		return num(rt.eval(n.a).num())
	case opNot:
		return boolNum(!rt.eval(n.a).truth())
	case opPreInc, opPostInc:
		r := rt.ref(n.a)
		old := r.get().num()
		nv := old + float64(n.sub)
		r.set(num(nv))
		if n.op == opPreInc {
			return num(nv)
		}
		return num(old)
	case opCall:
		return rt.call(n)
	case opBuiltin:
		return rt.builtin(n)
	case opGetline:
		return rt.getline(n)
	}
	rt.failf("bad expression")
	return awkVal{}
}

func (rt *awkRT) arith(op string, a, b float64) float64 {
	switch op {
	case "+":
		return a + b
	case "-":
		return a - b
	case "*":
		return a * b
	case "/":
		return invalidIsNegNaN(a/b, a, b) // mawk gives inf, not an error
	case "%":
		return invalidIsNegNaN(math.Mod(a, b), a, b)
	}
	r := math.Pow(a, b)
	if math.IsNaN(r) && (math.IsNaN(a) || math.IsNaN(b)) {
		return math.NaN() // pow() drops the sign of a NaN it is given
	}
	return invalidIsNegNaN(r, a, b)
}

// invalidIsNegNaN gives an invalid operation (inf-inf, fmod(x, 0), sqrt(-1)) the NaN an x86 FPU produces,
// whose sign bit is set, so mawk prints it as -nan; a NaN that came in is passed on unchanged.
func invalidIsNegNaN(r float64, in ...float64) float64 {
	if !math.IsNaN(r) {
		return r
	}
	for _, x := range in {
		if math.IsNaN(x) {
			return x
		}
	}
	return math.Copysign(math.NaN(), -1)
}

func (rt *awkRT) call(n *awkNode) awkVal {
	f := rt.prog.funcs[n.str]
	if len(n.args) > len(f.params) {
		rt.failf("too many arguments in call to %s", f.name)
	}
	if len(rt.frames) >= 1000 {
		rt.failf("function call nesting too deep")
	}
	frame := make([]*awkCell, len(f.params))
	for i := range frame {
		if i >= len(n.args) {
			frame[i] = &awkCell{name: f.params[i]}
			continue
		}
		a := n.args[i]
		if a.op == opVar || a.op == opLocal {
			c := rt.cellOf(a)
			switch {
			case c.arr != nil:
				frame[i] = &awkCell{name: f.params[i], arr: c.arr}
			case c.ref != nil || !c.set:
				frame[i] = &awkCell{name: f.params[i], ref: c}
			default:
				frame[i] = &awkCell{name: f.params[i], val: c.val, set: true}
			}
			continue
		}
		frame[i] = &awkCell{name: f.params[i], val: rt.eval(a), set: true}
	}
	rt.frames = append(rt.frames, frame)
	rt.retVal = uninit()
	flow := rt.exec(f.body)
	rt.frames = rt.frames[:len(rt.frames)-1]
	v := uninit()
	if flow == flowReturn {
		v = rt.retVal
	}
	rt.retVal = uninit()
	return v
}

// ---- statements ----

func (rt *awkRT) exec(st *awkStmt) awkFlow {
	rt.tick()
	switch st.kind {
	case stBlock:
		for _, s := range st.list {
			if f := rt.exec(s); f != flowNone {
				return f
			}
		}
	case stExpr:
		rt.eval(st.expr)
		if rt.exiting {
			return flowExit
		}
	case stPrint:
		rt.print(st)
	case stPrintf:
		rt.printf(st)
	case stIf:
		if rt.eval(st.expr).truth() {
			return rt.exec(st.body)
		} else if st.els != nil {
			return rt.exec(st.els)
		}
	case stWhile:
		for rt.eval(st.expr).truth() {
			if f := rt.exec(st.body); f == flowBreak {
				break
			} else if f != flowNone && f != flowContinue {
				return f
			}
			rt.tick()
		}
	case stDo:
		for {
			if f := rt.exec(st.body); f == flowBreak {
				break
			} else if f != flowNone && f != flowContinue {
				return f
			}
			if !rt.eval(st.expr).truth() {
				break
			}
			rt.tick()
		}
	case stFor:
		if st.init != nil {
			rt.exec(st.init)
		}
		for st.expr == nil || rt.eval(st.expr).truth() {
			if f := rt.exec(st.body); f == flowBreak {
				break
			} else if f != flowNone && f != flowContinue {
				return f
			}
			if st.post != nil {
				rt.exec(st.post)
			}
			rt.tick()
		}
	case stForIn:
		arr := rt.arrayOf(st.arr)
		keys := make([]string, 0, len(arr))
		for k := range arr {
			keys = append(keys, k)
		}
		sortKeys(keys)
		r := rt.ref(st.loopVar)
		for _, k := range keys {
			if _, ok := arr[k]; !ok {
				continue
			}
			r.set(strnum(k))
			if f := rt.exec(st.body); f == flowBreak {
				break
			} else if f != flowNone && f != flowContinue {
				return f
			}
			rt.tick()
		}
	case stNext:
		return flowNext
	case stNextFile:
		return flowNextFile
	case stBreak:
		return flowBreak
	case stContinue:
		return flowContinue
	case stExit:
		if st.expr != nil {
			rt.exitCode = int(rt.eval(st.expr).num()) & 0xff
		}
		rt.exiting = true
		return flowExit
	case stReturn:
		rt.retVal = uninit()
		if st.expr != nil {
			rt.retVal = rt.eval(st.expr)
		}
		return flowReturn
	case stDelete:
		arr := rt.arrayOf(st.arr)
		if st.exprs == nil {
			clear(arr)
		} else {
			delete(arr, rt.subscript(st.exprs))
		}
	}
	if rt.exiting {
		return flowExit
	}
	return flowNone
}

// ---- output ----

// stream finds where a print goes: the buffer for stdout or stderr, or a file or pipe collected until it
// is closed.
func (rt *awkRT) stream(st *awkStmt) *strings.Builder {
	if st.redir == "" {
		return &rt.out
	}
	name := rt.toStr(rt.eval(st.dest))
	if st.redir != "|" {
		switch name {
		case "/dev/stdout", "-":
			return &rt.out
		case "/dev/stderr":
			return &rt.errs
		}
	}
	key := st.redir + name
	if st.redir == ">" || st.redir == ">>" {
		key = "f" + name
	}
	o := rt.outs[key]
	if o == nil {
		o = &awkOutStream{appendTo: st.redir == ">>", pipe: st.redir == "|"}
		if st.redir == ">" {
			rt.writeFile(name, "", false) // > starts the file afresh when it is first opened
		}
		rt.outs[key] = o
	}
	return &o.buf
}

func (rt *awkRT) print(st *awkStmt) {
	w := rt.stream(st)
	var b strings.Builder
	if len(st.exprs) == 0 {
		b.WriteString(rt.record())
	} else {
		parts := make([]string, len(st.exprs)) // all evaluated before any is written: an error prints nothing
		for i, e := range st.exprs {
			parts[i] = rt.toOut(rt.eval(e))
		}
		b.WriteString(strings.Join(parts, rt.ofs.val.s))
	}
	b.WriteString(rt.ors.val.s)
	w.WriteString(b.String())
}

func (rt *awkRT) printf(st *awkStmt) {
	w := rt.stream(st)
	format := rt.toStr(rt.eval(st.exprs[0]))
	args := make([]awkVal, len(st.exprs)-1)
	for i, e := range st.exprs[1:] {
		args[i] = rt.eval(e)
	}
	rt.fmtFn = "printf"
	w.WriteString(awkSprintf(format, args, rt))
}

func (rt *awkRT) writeFile(name, content string, appendMode bool) {
	if msg, code := rt.s.writeFile(name, content, appendMode); code != 0 {
		rt.failf("cannot open \"%s\" for output", name)
		_ = msg
	}
}

// closeStream finishes one redirection: a file is written out, a pipe's text is run through its command.
func (rt *awkRT) closeStream(key string) int {
	o := rt.outs[key]
	if o == nil {
		return -1
	}
	delete(rt.outs, key)
	name := key[1:]
	if o.pipe {
		text := o.buf.String()
		return rt.runCommand(name, &text)
	}
	if o.buf.Len() > 0 {
		rt.writeFile(name, o.buf.String(), true)
	}
	return 0
}

func (rt *awkRT) closeAll() {
	for key := range rt.outs {
		rt.closeStream(key)
	}
}

// runCommand runs a shell command line, with stdin when given, adding its stdout to ours.
func (rt *awkRT) runCommand(cmd string, stdin *string) int {
	text, code := rt.captureCommand(cmd, stdin)
	rt.out.WriteString(text)
	return code
}

func (rt *awkRT) captureCommand(cmd string, stdin *string) (string, int) {
	s := rt.s
	savedStdin, savedErr := s.pipeStdin, s.pendingErr
	s.pipeStdin, s.pendingErr = stdin, nil
	if stdin == nil {
		empty := ""
		s.pipeStdin = &empty
	}
	var bait []BaitHit
	var chunks []outChunk
	code := s.asSubshell(func() int {
		var c int
		chunks, c = s.evalChunks(cmd, 1, &bait, "")
		return c
	})
	s.pipeStdin, s.pendingErr = savedStdin, savedErr
	var stdout []outChunk
	for _, c := range chunks {
		if c.stderr {
			rt.errs.WriteString(strings.ReplaceAll(c.text, "\r\n", "\n") + "\n")
		} else {
			stdout = append(stdout, c)
		}
	}
	text := strings.ReplaceAll(joinChunks(stdout, "\r\n"), "\r\n", "\n")
	if text != "" && (len(stdout) == 0 || !stdout[len(stdout)-1].noNewline) {
		text += "\n"
	}
	return text, code
}
