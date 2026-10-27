package shell

import (
	"math"
	"math/rand"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// sortKeys orders the keys a for-in loop visits. mawk visits them in the order of its own hash table,
// which is not reproduced; ubuntu2204.json has no case that depends on it.
func sortKeys(keys []string) { sort.Strings(keys) }

func awkLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func awkUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

func (rt *awkRT) builtin(n *awkNode) awkVal {
	a := n.args
	sarg := func(i int) string { return rt.toStr(rt.eval(a[i])) }
	narg := func(i int) float64 { return rt.eval(a[i]).num() }
	switch n.subStr {
	case "length":
		if len(a) == 0 {
			return num(float64(len(rt.record())))
		}
		if a[0].op == opVar || a[0].op == opLocal {
			if c := rt.cellOf(a[0]); c.arr != nil {
				return num(float64(len(c.arr)))
			}
		}
		return num(float64(len(sarg(0))))
	case "substr":
		return str(rt.substr(sarg(0), narg(1), a[2:], len(a) == 3))
	case "index":
		return num(float64(strings.Index(sarg(0), sarg(1)) + 1))
	case "split":
		return rt.split(n)
	case "sub", "gsub":
		return rt.subst(n)
	case "match":
		s := sarg(0)
		loc := rt.regexOf(a[1]).FindStringIndex(s)
		start, length := 0, -1
		if loc != nil {
			start, length = loc[0]+1, loc[1]-loc[0]
		}
		rt.rstart.val, rt.rstart.set = num(float64(start)), true
		rt.rlength.val, rt.rlength.set = num(float64(length)), true
		return num(float64(start))
	case "sprintf":
		args := make([]awkVal, len(a)-1)
		for i := range args {
			args[i] = rt.eval(a[i+1])
		}
		rt.fmtFn = "sprintf"
		return str(awkSprintf(sarg(0), args, rt))
	case "sin":
		return num(math.Sin(narg(0)))
	case "cos":
		return num(math.Cos(narg(0)))
	case "atan2":
		return num(math.Atan2(narg(0), narg(1)))
	case "exp":
		return num(math.Exp(narg(0)))
	case "log":
		x := narg(0)
		return num(invalidIsNegNaN(math.Log(x), x))
	case "sqrt":
		x := narg(0)
		return num(invalidIsNegNaN(math.Sqrt(x), x))
	case "int":
		return num(math.Trunc(narg(0)))
	case "rand":
		return num(rt.rng.Float64())
	case "srand":
		prev := rt.seed
		if len(a) > 0 {
			rt.seed = narg(0)
		} else {
			rt.seed++
		}
		rt.rng = rand.New(rand.NewSource(int64(rt.seed)))
		return num(prev)
	case "tolower":
		return str(awkLower(sarg(0)))
	case "toupper":
		return str(awkUpper(sarg(0)))
	case "system":
		text, code := rt.captureCommand(sarg(0), nil)
		rt.out.WriteString(text)
		return num(float64(code))
	case "close":
		name := sarg(0)
		found := false
		for _, k := range []string{"<" + name, "|" + name} {
			if _, ok := rt.readers[k]; ok {
				delete(rt.readers, k)
				found = true
			}
		}
		for _, k := range []string{"f" + name, "|" + name} {
			if rt.closeStream(k) >= 0 {
				found = true
			}
		}
		if !found {
			return num(-1)
		}
		return num(0)
	case "fflush":
		return num(0)
	}
	rt.failf("unknown function %s", n.subStr)
	return awkVal{}
}

// substr follows mawk 1.3.4 20200120, which truncates its arguments and, when the start is below 1,
// lengthens the result by the amount it is below (substr("hello", -1, 3) is "hell"). Measured, not
// derived: see the substr grid in testdata/ubuntu2204.json.
func (rt *awkRT) substr(s string, start float64, rest []*awkNode, hasLen bool) string {
	n := math.Inf(1)
	if hasLen {
		n = math.Trunc(rt.eval(rest[0]).num())
	}
	b := math.Trunc(start)
	if math.IsNaN(b) {
		b = 0
	}
	if b < 1 {
		if hasLen {
			n += math.Trunc(-start)
		}
		b = 1
	}
	l := float64(len(s))
	if n <= 0 || b > l {
		return ""
	}
	end := math.Min(b-1+n, l)
	return s[int(b)-1 : int(end)]
}

func (rt *awkRT) split(n *awkNode) awkVal {
	a := n.args
	s := rt.toStr(rt.eval(a[0]))
	arr := rt.arrayOf(a[1])
	var parts []string
	switch {
	case len(a) == 3 && a[2].op == opRegex:
		if s != "" {
			parts = regexSplit(rt.compile(a[2].str), s)
		}
	case len(a) == 3:
		parts = rt.splitString(s, rt.toStr(rt.eval(a[2])), false)
	default:
		parts = rt.splitString(s, rt.fs.val.s, false)
	}
	clear(arr)
	for i, p := range parts {
		arr[strconv.Itoa(i+1)] = strnum(p)
	}
	return num(float64(len(parts)))
}

// awkRepl expands the replacement text of sub and gsub: & is the matched text, \& a literal &.
func awkRepl(repl, matched string) string {
	if !strings.ContainsAny(repl, `&\`) {
		return repl
	}
	var b strings.Builder
	for i := 0; i < len(repl); i++ {
		switch c := repl[i]; {
		case c == '\\' && i+1 < len(repl) && (repl[i+1] == '&' || repl[i+1] == '\\'):
			i++
			b.WriteByte(repl[i])
		case c == '&':
			b.WriteString(matched)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func (rt *awkRT) subst(n *awkNode) awkVal {
	a := n.args
	re := rt.regexOf(a[0])
	repl := rt.toStr(rt.eval(a[1]))
	var target awkRef
	if len(a) == 3 && isLvalue(a[2]) {
		target = rt.ref(a[2])
	} else if len(a) == 3 {
		v := rt.eval(a[2])
		target = awkRef{get: func() awkVal { return v }, set: func(awkVal) {}}
	} else {
		target = rt.ref(&awkNode{op: opField, a: &awkNode{op: opNum}})
	}
	src := rt.toStr(target.get())
	var locs [][]int
	if n.subStr == "gsub" {
		locs = re.FindAllStringIndex(src, -1)
	} else if loc := re.FindStringIndex(src); loc != nil {
		locs = [][]int{loc}
	}
	if len(locs) == 0 {
		return num(0)
	}
	var b strings.Builder
	last := 0
	for _, m := range locs {
		b.WriteString(src[last:m[0]])
		b.WriteString(awkRepl(repl, src[m[0]:m[1]]))
		last = m[1]
	}
	b.WriteString(src[last:])
	target.set(str(b.String()))
	return num(float64(len(locs)))
}

// ---- input ----

type awkFatal string

func (rt *awkRT) readRec(r *awkReader) (string, bool) {
	rs := rt.rs.val.s
	if r.pos >= len(r.text) {
		return "", false
	}
	text := r.text[r.pos:]
	switch {
	case rs == "":
		trimmed := strings.TrimLeft(text, "\n")
		r.pos += len(text) - len(trimmed)
		if trimmed == "" {
			return "", false
		}
		end := strings.Index(trimmed, "\n\n")
		if end < 0 {
			r.pos = len(r.text)
			return strings.TrimRight(trimmed, "\n"), true
		}
		rest := strings.TrimLeft(trimmed[end:], "\n")
		r.pos = len(r.text) - len(rest)
		return trimmed[:end], true
	case len(rs) == 1:
		if i := strings.IndexByte(text, rs[0]); i >= 0 {
			r.pos += i + 1
			return text[:i], true
		}
	default:
		for _, m := range rt.compile(rs).FindAllStringIndex(text, -1) {
			if m[1] > m[0] {
				r.pos += m[1]
				return text[:m[0]], true
			}
		}
	}
	r.pos = len(r.text)
	return text, true
}

// nextMain reads the next record of the main input, moving on through the file operands (and
// var=value operands, which take effect when reached).
func (rt *awkRT) nextMain() (string, bool) {
	for {
		if rt.cur == nil && !rt.openNext() {
			return "", false
		}
		if rec, ok := rt.readRec(rt.cur); ok {
			return rec, true
		}
		rt.cur = nil
	}
}

func (rt *awkRT) openNext() bool {
	for rt.opIdx < len(rt.operands) {
		op := rt.operands[rt.opIdx]
		rt.opIdx++
		if op.assign != "" {
			rt.assignOperand(op.assign)
			continue
		}
		rt.opened = true
		var text string
		if op.file == "-" {
			if rt.stdin != nil {
				text = *rt.stdin
			}
		} else {
			t, ok := rt.s.builtinInput(op.file, nil)
			if !ok {
				panic(awkFatal("cannot open " + op.file + " (No such file or directory)"))
			}
			text = t
		}
		rt.cur, rt.fnr = &awkReader{text: text}, 0
		rt.filename.val, rt.filename.set = str(op.file), true
		return true
	}
	if !rt.opened {
		rt.opened = true
		text := ""
		if rt.stdin != nil {
			text = *rt.stdin
		}
		rt.cur, rt.fnr = &awkReader{text: text}, 0
		return true
	}
	return false
}

func (rt *awkRT) assignOperand(a string) {
	name, val, _ := strings.Cut(a, "=")
	c := rt.global(name, "")
	c.val, c.set = strnum(awkUnescape(val)), true
}

// awkUnescape handles the escapes in -v values and var=value operands.
func awkUnescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	l := &awkLexer{src: s + `"`, line: 1}
	l.pos = -1 // str() steps over an opening quote
	if v, err := l.str(); err == nil {
		return v
	}
	return s
}

func (rt *awkRT) reader(key, name string, isCmd bool) *awkReader {
	if r, ok := rt.readers[key]; ok {
		return r
	}
	var text string
	if isCmd {
		text, _ = rt.captureCommand(name, nil)
	} else if name == "-" {
		if rt.stdin != nil {
			text = *rt.stdin
		}
	} else {
		t, ok := rt.s.builtinInput(name, nil)
		if !ok {
			return nil
		}
		text = t
	}
	r := &awkReader{text: text}
	rt.readers[key] = r
	return r
}

func (rt *awkRT) getline(n *awkNode) awkVal {
	var rec string
	switch n.sub {
	case glPlain:
		r, ok := rt.nextMain()
		if !ok {
			return num(0)
		}
		rec = r
		rt.nr++
		rt.fnr++
	case glFile:
		name := rt.toStr(rt.eval(n.b))
		r := rt.reader("<"+name, name, false)
		if r == nil {
			return num(-1)
		}
		s, ok := rt.readRec(r)
		if !ok {
			return num(0)
		}
		rec = s
	default:
		cmd := rt.toStr(rt.eval(n.b))
		r := rt.reader("|"+cmd, cmd, true)
		s, ok := rt.readRec(r)
		if !ok {
			return num(0)
		}
		rec = s
	}
	if n.a == nil {
		rt.setRecord(rec)
	} else {
		rt.ref(n.a).set(strnum(rec))
	}
	return num(1)
}

var _ = regexp.QuoteMeta
