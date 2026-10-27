package shell

import (
	"fmt"
	"strconv"
	"strings"
)

// The awk front end: a lexer and a recursive-descent parser that build the tree awk_run.go walks.

type awkTokKind int

const (
	tkEOF awkTokKind = iota
	tkNewline
	tkNumber
	tkString
	tkName
	tkFuncName // a name followed at once by "("
	tkBuiltin
	tkKeyword
	tkPunct
)

type awkTok struct {
	kind awkTokKind
	s    string
	n    float64
	pos  int // offset of the first byte
	line int
}

var awkKeywords = map[string]bool{
	"BEGIN": true, "END": true, "function": true, "func": true, "if": true, "else": true, "while": true,
	"for": true, "do": true, "break": true, "continue": true, "next": true, "nextfile": true, "exit": true,
	"return": true, "delete": true, "in": true, "getline": true, "print": true, "printf": true,
}

var awkBuiltins = map[string]bool{
	"length": true, "substr": true, "index": true, "split": true, "sub": true, "gsub": true, "match": true,
	"sprintf": true, "sin": true, "cos": true, "atan2": true, "exp": true, "log": true, "sqrt": true,
	"int": true, "rand": true, "srand": true, "tolower": true, "toupper": true, "system": true,
	"close": true, "fflush": true,
}

var awkPuncts = []string{"&&", "||", "==", "!=", "<=", ">=", "+=", "-=", "*=", "/=", "%=", "^=", "++", "--", "!~", ">>"}

type awkLexer struct {
	src  string
	pos  int
	line int
}

func (l *awkLexer) next() (awkTok, error) {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			l.pos++
		case c == '\\' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '\n':
			l.pos += 2
			l.line++
		case c == '\\' && l.pos+2 < len(l.src) && l.src[l.pos+1] == '\r' && l.src[l.pos+2] == '\n':
			l.pos += 3
			l.line++
		case c == '#':
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
		default:
			goto token
		}
	}
	return awkTok{kind: tkEOF, pos: l.pos, line: l.line}, nil
token:
	start, c := l.pos, l.src[l.pos]
	t := awkTok{pos: start, line: l.line}
	switch {
	case c == '\n':
		l.pos++
		l.line++
		t.kind, t.s = tkNewline, "\n"
	case c >= '0' && c <= '9' || (c == '.' && l.pos+1 < len(l.src) && l.src[l.pos+1] >= '0' && l.src[l.pos+1] <= '9'):
		n := scanDecimal(l.src[l.pos:])
		v, _ := strconv.ParseFloat(l.src[l.pos:l.pos+n], 64)
		l.pos += n
		t.kind, t.s, t.n = tkNumber, l.src[start:l.pos], v
	case c == '"':
		s, err := l.str()
		if err != nil {
			return t, err
		}
		t.kind, t.s = tkString, s
	case isIdentStart(c):
		j := l.pos
		for j < len(l.src) && isIdentPart(l.src[j]) {
			j++
		}
		word := l.src[l.pos:j]
		l.pos = j
		t.s = word
		switch {
		case awkKeywords[word]:
			t.kind = tkKeyword
		case awkBuiltins[word]:
			t.kind = tkBuiltin
		case l.pos < len(l.src) && l.src[l.pos] == '(':
			t.kind = tkFuncName
		default:
			t.kind = tkName
		}
	default:
		t.kind = tkPunct
		for _, p := range awkPuncts {
			if strings.HasPrefix(l.src[l.pos:], p) {
				t.s = p
				break
			}
		}
		if t.s == "" {
			t.s = string(c)
		}
		l.pos += len(t.s)
	}
	return t, nil
}

// str reads a double-quoted string with awk's escapes. An escape it does not know stays as written.
func (l *awkLexer) str() (string, error) {
	var b strings.Builder
	l.pos++
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '"':
			l.pos++
			return b.String(), nil
		case c == '\n':
			return "", awkErr(fmt.Sprintf("line %d: runaway string constant \"%s ...", l.line, truncate(b.String(), 10)))
		case c == '\\' && l.pos+1 < len(l.src):
			l.pos++
			e := l.src[l.pos]
			switch e {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '\\':
				b.WriteByte('\\')
			case '"':
				b.WriteByte('"')
			case 'a':
				b.WriteByte(7)
			case 'b':
				b.WriteByte(8)
			case 'f':
				b.WriteByte(12)
			case 'v':
				b.WriteByte(11)
			case '\n':
				l.line++
			case '0', '1', '2', '3', '4', '5', '6', '7':
				v, k := 0, 0
				for k < 3 && l.pos < len(l.src) && l.src[l.pos] >= '0' && l.src[l.pos] <= '7' {
					v = v*8 + int(l.src[l.pos]-'0')
					l.pos++
					k++
				}
				l.pos--
				b.WriteByte(byte(v))
			default:
				b.WriteByte('\\')
				b.WriteByte(e)
			}
			l.pos++
		default:
			b.WriteByte(c)
			l.pos++
		}
	}
	return "", awkErr(fmt.Sprintf("line %d: runaway string constant \"%s ...", l.line, truncate(b.String(), 10)))
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// regex reads the body of a regular expression whose opening "/" ended at pos.
func (l *awkLexer) regex() (string, error) {
	var b strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '/':
			l.pos++
			return b.String(), nil
		case c == '\n':
			return "", awkErr(fmt.Sprintf("line %d: runaway regular expression /%s ...", l.line, truncate(b.String(), 10)))
		case c == '\\' && l.pos+1 < len(l.src):
			if l.src[l.pos+1] == '/' {
				b.WriteByte('/')
			} else {
				b.WriteByte('\\')
				b.WriteByte(l.src[l.pos+1])
			}
			l.pos += 2
		default:
			b.WriteByte(c)
			l.pos++
		}
	}
	return "", awkErr(fmt.Sprintf("line %d: runaway regular expression /%s ...", l.line, truncate(b.String(), 10)))
}

// ---- tree ----

type awkOp uint8

const (
	opNum awkOp = iota
	opStr
	opRegex   // /re/ used as a value: $0 ~ /re/
	opVar     // a global variable or array: cell
	opLocal   // a function parameter: idx
	opSpecial // NF, NR, FNR: sub
	opIndex   // a[subs]: a, args
	opField   // $a
	opAssign  // a = b, a += b ...: sub is the operator
	opCond    // a ? b : c
	opOr
	opAnd
	opIn      // a in b, or (args) in b
	opMatch   // a ~ b
	opNoMatch // a !~ b
	opCmp     // sub is the comparison
	opConcat
	opBinary // sub is + - * / % ^
	opNeg
	opPlus
	opNot
	opPreInc // sub is +1 or -1
	opPostInc
	opCall    // a user function: str, args
	opBuiltin // sub is the builtin
	opGetline // plain, "< file" or "cmd |": sub says which; a is the lvalue, b the source
	opGroup   // (a)
)

const (
	spNF = iota
	spNR
	spFNR
)

const (
	glPlain = iota // getline [var]
	glFile         // getline [var] < file
	glCmd          // cmd | getline [var]
)

type awkNode struct {
	op      awkOp
	sub     int
	subStr  string
	a, b, c *awkNode
	args    []*awkNode
	num     float64
	str     string
	cell    *awkCell
	idx     int
	line    int
}

type awkStmtKind uint8

const (
	stExpr awkStmtKind = iota
	stPrint
	stPrintf
	stIf
	stWhile
	stDo
	stFor
	stForIn
	stBlock
	stNext
	stNextFile
	stExit
	stReturn
	stBreak
	stContinue
	stDelete
)

type awkStmt struct {
	kind       awkStmtKind
	expr       *awkNode
	exprs      []*awkNode
	init, post *awkStmt
	body, els  *awkStmt
	list       []*awkStmt
	redir      string // ">", ">>" or "|" for print and printf
	dest       *awkNode
	loopVar    *awkNode
	arr        *awkNode
}

type awkFunc struct {
	name    string
	params  []string
	body    *awkStmt
	defined bool
}

type awkRuleN struct {
	pat, pat2 *awkNode
	isRange   bool
	body      *awkStmt // nil: print $0
	active    bool
}

type awkProgram struct {
	begins, ends []*awkStmt
	rules        []*awkRuleN
	funcs        map[string]*awkFunc
	globals      map[string]*awkCell
}

// ---- parser ----

type awkParser struct {
	lex      *awkLexer
	tok      awkTok
	prog     *awkProgram
	locals   map[string]int // the parameters of the function being parsed
	noGt     int            // above 0, ">" ends a print expression instead of comparing
	inFunc   bool
	calls    []*awkNode
	loopNest int
}

type awkMark struct {
	pos, line int
	tok       awkTok
	noGt      int
}

func (p *awkParser) mark() awkMark { return awkMark{p.lex.pos, p.lex.line, p.tok, p.noGt} }
func (p *awkParser) reset(m awkMark) {
	p.lex.pos, p.lex.line, p.tok, p.noGt = m.pos, m.line, m.tok, m.noGt
}

func (p *awkParser) advance() error {
	t, err := p.lex.next()
	if err != nil {
		return err
	}
	p.tok = t
	return nil
}

func (p *awkParser) fail() error {
	near := p.tok.s
	switch p.tok.kind {
	case tkEOF:
		near = "end of file"
	case tkNewline:
		near = "end of line"
	}
	return awkErr(fmt.Sprintf("line %d: syntax error at or near %s", p.tok.line, near))
}

func (p *awkParser) isP(s string) bool { return p.tok.kind == tkPunct && p.tok.s == s }
func (p *awkParser) isK(s string) bool { return p.tok.kind == tkKeyword && p.tok.s == s }

func (p *awkParser) acceptP(s string) (bool, error) {
	if p.isP(s) {
		return true, p.advance()
	}
	return false, nil
}

func (p *awkParser) expectP(s string) error {
	if !p.isP(s) {
		return p.fail()
	}
	return p.advance()
}

func (p *awkParser) skipNL() error {
	for p.tok.kind == tkNewline {
		if err := p.advance(); err != nil {
			return err
		}
	}
	return nil
}

// skipTerms passes newlines and semicolons between program items and statements.
func (p *awkParser) skipTerms() error {
	for p.tok.kind == tkNewline || p.isP(";") {
		if err := p.advance(); err != nil {
			return err
		}
	}
	return nil
}

func parseAwk(src string) (*awkProgram, error) {
	p := &awkParser{lex: &awkLexer{src: src, line: 1}, prog: &awkProgram{funcs: map[string]*awkFunc{}, globals: map[string]*awkCell{}}}
	if err := p.advance(); err != nil {
		return nil, err
	}
	if err := p.program(); err != nil {
		return nil, err
	}
	for _, c := range p.calls {
		f := p.prog.funcs[c.str]
		if f == nil || !f.defined {
			return nil, awkErr(fmt.Sprintf("line %d: function %s never defined", p.lex.line+1, c.str))
		}
	}
	return p.prog, nil
}

func (p *awkParser) program() error {
	for {
		if err := p.skipTerms(); err != nil {
			return err
		}
		if p.tok.kind == tkEOF {
			return nil
		}
		switch {
		case p.isK("function") || p.isK("func"):
			if err := p.function(); err != nil {
				return err
			}
		case p.isK("BEGIN"), p.isK("END"):
			begin := p.tok.s == "BEGIN"
			if err := p.advance(); err != nil {
				return err
			}
			if !p.isP("{") {
				return p.fail()
			}
			body, err := p.block()
			if err != nil {
				return err
			}
			if begin {
				p.prog.begins = append(p.prog.begins, body)
			} else {
				p.prog.ends = append(p.prog.ends, body)
			}
		default:
			r := &awkRuleN{}
			if !p.isP("{") {
				pat, err := p.expr()
				if err != nil {
					return err
				}
				r.pat = pat
				if p.isP(",") {
					if err := p.advance(); err != nil {
						return err
					}
					if err := p.skipNL(); err != nil {
						return err
					}
					if r.pat2, err = p.expr(); err != nil {
						return err
					}
					r.isRange = true
				}
			}
			if p.isP("{") {
				body, err := p.block()
				if err != nil {
					return err
				}
				r.body = body
			} else if p.tok.kind != tkNewline && p.tok.kind != tkEOF && !p.isP(";") {
				return p.fail()
			}
			p.prog.rules = append(p.prog.rules, r)
		}
	}
}

func (p *awkParser) function() error {
	if err := p.advance(); err != nil {
		return err
	}
	if p.tok.kind != tkName && p.tok.kind != tkFuncName {
		return p.fail()
	}
	name := p.tok.s
	if err := p.advance(); err != nil {
		return err
	}
	if err := p.expectP("("); err != nil {
		return err
	}
	f := p.prog.funcs[name]
	if f == nil {
		f = &awkFunc{name: name}
		p.prog.funcs[name] = f
	}
	if f.defined {
		return awkErr(fmt.Sprintf("line %d: function %s redefined", p.tok.line, name))
	}
	f.defined = true
	p.locals = map[string]int{}
	for !p.isP(")") {
		if err := p.skipNL(); err != nil {
			return err
		}
		if p.tok.kind != tkName {
			return p.fail()
		}
		p.locals[p.tok.s] = len(f.params)
		f.params = append(f.params, p.tok.s)
		if err := p.advance(); err != nil {
			return err
		}
		if ok, err := p.acceptP(","); err != nil {
			return err
		} else if ok {
			if err := p.skipNL(); err != nil {
				return err
			}
		}
	}
	if err := p.advance(); err != nil {
		return err
	}
	if err := p.skipNL(); err != nil {
		return err
	}
	if !p.isP("{") {
		return p.fail()
	}
	p.inFunc = true
	body, err := p.block()
	p.inFunc = false
	p.locals = nil
	if err != nil {
		return err
	}
	f.body = body
	return nil
}

func (p *awkParser) block() (*awkStmt, error) {
	if err := p.advance(); err != nil { // {
		return nil, err
	}
	blk := &awkStmt{kind: stBlock}
	for {
		if err := p.skipTerms(); err != nil {
			return nil, err
		}
		if p.isP("}") {
			return blk, p.advance()
		}
		if p.tok.kind == tkEOF {
			return nil, awkErr(fmt.Sprintf("line %d: missing } near end of file", p.tok.line+1))
		}
		st, err := p.statement()
		if err != nil {
			return nil, err
		}
		blk.list = append(blk.list, st)
	}
}

// endSimple ends a simple statement: a ; or newline is consumed, a } or the end of the program is not.
func (p *awkParser) endSimple() error {
	switch {
	case p.tok.kind == tkNewline || p.isP(";"):
		return p.advance()
	case p.isP("}") || p.tok.kind == tkEOF:
		return nil
	}
	return p.fail()
}

func (p *awkParser) statement() (*awkStmt, error) {
	switch {
	case p.isP("{"):
		return p.block()
	case p.isK("if"):
		return p.ifStmt()
	case p.isK("while"):
		if err := p.advance(); err != nil {
			return nil, err
		}
		cond, err := p.parenCond()
		if err != nil {
			return nil, err
		}
		if p.isP(";") { // while (c) ;
			if err := p.advance(); err != nil {
				return nil, err
			}
			return &awkStmt{kind: stWhile, expr: cond, body: &awkStmt{kind: stBlock}}, nil
		}
		body, err := p.body()
		if err != nil {
			return nil, err
		}
		return &awkStmt{kind: stWhile, expr: cond, body: body}, nil
	case p.isK("do"):
		if err := p.advance(); err != nil {
			return nil, err
		}
		body, err := p.body()
		if err != nil {
			return nil, err
		}
		if err := p.skipTerms(); err != nil {
			return nil, err
		}
		if !p.isK("while") {
			return nil, p.fail()
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
		cond, err := p.parenCond()
		if err != nil {
			return nil, err
		}
		return &awkStmt{kind: stDo, expr: cond, body: body}, p.endSimple()
	case p.isK("for"):
		return p.forStmt()
	case p.isP(";"):
		return &awkStmt{kind: stBlock}, p.advance()
	}
	return p.simple()
}

// body is the statement a control construct governs, after any newlines.
func (p *awkParser) body() (*awkStmt, error) {
	if err := p.skipNL(); err != nil {
		return nil, err
	}
	if p.isP(";") {
		return &awkStmt{kind: stBlock}, p.advance()
	}
	return p.statement()
}

func (p *awkParser) parenCond() (*awkNode, error) {
	if err := p.expectP("("); err != nil {
		return nil, err
	}
	saved := p.noGt
	p.noGt = 0
	e, err := p.expr()
	p.noGt = saved
	if err != nil {
		return nil, err
	}
	if err := p.expectP(")"); err != nil {
		return nil, err
	}
	return e, nil
}

func (p *awkParser) ifStmt() (*awkStmt, error) {
	if err := p.advance(); err != nil {
		return nil, err
	}
	cond, err := p.parenCond()
	if err != nil {
		return nil, err
	}
	then, err := p.body()
	if err != nil {
		return nil, err
	}
	st := &awkStmt{kind: stIf, expr: cond, body: then}
	m := p.mark()
	if err := p.skipTerms(); err != nil {
		return nil, err
	}
	if p.isK("else") {
		if err := p.advance(); err != nil {
			return nil, err
		}
		if st.els, err = p.body(); err != nil {
			return nil, err
		}
	} else {
		p.reset(m)
	}
	return st, nil
}

func (p *awkParser) forStmt() (*awkStmt, error) {
	if err := p.advance(); err != nil {
		return nil, err
	}
	if err := p.expectP("("); err != nil {
		return nil, err
	}
	// for (name in array)
	m := p.mark()
	if p.tok.kind == tkName {
		v, err := p.primary()
		if err == nil && p.isK("in") {
			if err := p.advance(); err != nil {
				return nil, err
			}
			if p.tok.kind == tkName {
				arr, err := p.nameNode()
				if err != nil {
					return nil, err
				}
				if p.isP(")") {
					if err := p.advance(); err != nil {
						return nil, err
					}
					body, err := p.body()
					if err != nil {
						return nil, err
					}
					return &awkStmt{kind: stForIn, loopVar: v, arr: arr, body: body}, nil
				}
			}
		}
	}
	p.reset(m)
	st := &awkStmt{kind: stFor}
	var err error
	if !p.isP(";") {
		if st.init, err = p.simpleNoEnd(); err != nil {
			return nil, err
		}
	}
	if err := p.expectP(";"); err != nil {
		return nil, err
	}
	if err := p.skipNL(); err != nil {
		return nil, err
	}
	if !p.isP(";") {
		if st.expr, err = p.expr(); err != nil {
			return nil, err
		}
	}
	if err := p.expectP(";"); err != nil {
		return nil, err
	}
	if err := p.skipNL(); err != nil {
		return nil, err
	}
	if !p.isP(")") {
		if st.post, err = p.simpleNoEnd(); err != nil {
			return nil, err
		}
	}
	if err := p.expectP(")"); err != nil {
		return nil, err
	}
	if p.isP(";") {
		st.body = &awkStmt{kind: stBlock}
		return st, p.advance()
	}
	if st.body, err = p.body(); err != nil {
		return nil, err
	}
	return st, nil
}

func (p *awkParser) simple() (*awkStmt, error) {
	st, err := p.simpleNoEnd()
	if err != nil {
		return nil, err
	}
	return st, p.endSimple()
}

func (p *awkParser) atStmtEnd() bool {
	return p.tok.kind == tkNewline || p.tok.kind == tkEOF || p.isP(";") || p.isP("}")
}

func (p *awkParser) simpleNoEnd() (*awkStmt, error) {
	switch {
	case p.isK("print"), p.isK("printf"):
		return p.printStmt()
	case p.isK("next"):
		return &awkStmt{kind: stNext}, p.advance()
	case p.isK("nextfile"):
		return &awkStmt{kind: stNextFile}, p.advance()
	case p.isK("break"):
		return &awkStmt{kind: stBreak}, p.advance()
	case p.isK("continue"):
		return &awkStmt{kind: stContinue}, p.advance()
	case p.isK("exit"), p.isK("return"):
		kind := stExit
		if p.tok.s == "return" {
			kind = stReturn
			if !p.inFunc {
				return nil, p.fail()
			}
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
		st := &awkStmt{kind: kind}
		if !p.atStmtEnd() {
			e, err := p.expr()
			if err != nil {
				return nil, err
			}
			st.expr = e
		}
		return st, nil
	case p.isK("delete"):
		if err := p.advance(); err != nil {
			return nil, err
		}
		if p.tok.kind != tkName {
			return nil, p.fail()
		}
		arr, err := p.nameNode()
		if err != nil {
			return nil, err
		}
		st := &awkStmt{kind: stDelete, arr: arr}
		if ok, err := p.acceptP("["); err != nil {
			return nil, err
		} else if ok {
			if st.exprs, err = p.exprList("]"); err != nil {
				return nil, err
			}
		}
		return st, nil
	}
	e, err := p.expr()
	if err != nil {
		return nil, err
	}
	return &awkStmt{kind: stExpr, expr: e}, nil
}

func (p *awkParser) printStmt() (*awkStmt, error) {
	st := &awkStmt{kind: stPrint}
	if p.tok.s == "printf" {
		st.kind = stPrintf
	}
	if err := p.advance(); err != nil {
		return nil, err
	}
	isRedir := func() bool { return p.isP(">") || p.isP(">>") || p.isP("|") }
	if !p.atStmtEnd() && !isRedir() {
		parsed := false
		if p.isP("(") {
			m := p.mark()
			if err := p.advance(); err == nil {
				saved := p.noGt
				p.noGt = 0
				list, err := p.exprList(")")
				p.noGt = saved
				if err == nil && (p.atStmtEnd() || isRedir()) {
					st.exprs, parsed = list, true
				}
			}
			if !parsed {
				p.reset(m)
			}
		}
		if !parsed {
			p.noGt++
			list, err := p.exprListUntilEnd()
			p.noGt--
			if err != nil {
				return nil, err
			}
			st.exprs = list
		}
	}
	if st.kind == stPrintf && len(st.exprs) == 0 {
		return nil, p.fail()
	}
	if isRedir() {
		st.redir = p.tok.s
		if err := p.advance(); err != nil {
			return nil, err
		}
		p.noGt++
		dest, err := p.ternary()
		p.noGt--
		if err != nil {
			return nil, err
		}
		st.dest = dest
	}
	return st, nil
}

// exprList reads expressions separated by commas up to the closing token, which it consumes.
func (p *awkParser) exprList(closer string) ([]*awkNode, error) {
	var list []*awkNode
	saved := p.noGt
	p.noGt = 0
	defer func() { p.noGt = saved }()
	if err := p.skipNL(); err != nil {
		return nil, err
	}
	if p.isP(closer) {
		return list, p.advance()
	}
	for {
		e, err := p.expr()
		if err != nil {
			return nil, err
		}
		list = append(list, e)
		if err := p.skipNL(); err != nil {
			return nil, err
		}
		if p.isP(",") {
			if err := p.advance(); err != nil {
				return nil, err
			}
			if err := p.skipNL(); err != nil {
				return nil, err
			}
			continue
		}
		if p.isP(closer) {
			return list, p.advance()
		}
		return nil, p.fail()
	}
}

// exprListUntilEnd reads a print argument list, which ends at a statement end or a redirection.
func (p *awkParser) exprListUntilEnd() ([]*awkNode, error) {
	var list []*awkNode
	for {
		e, err := p.expr()
		if err != nil {
			return nil, err
		}
		list = append(list, e)
		if p.isP(",") {
			if err := p.advance(); err != nil {
				return nil, err
			}
			if err := p.skipNL(); err != nil {
				return nil, err
			}
			continue
		}
		return list, nil
	}
}

// ---- expressions ----

func isLvalue(n *awkNode) bool {
	switch n.op {
	case opVar, opLocal, opSpecial, opIndex, opField:
		return true
	}
	return false
}

var awkAssignOps = map[string]string{"=": "", "+=": "+", "-=": "-", "*=": "*", "/=": "/", "%=": "%", "^=": "^"}

func (p *awkParser) expr() (*awkNode, error) {
	lhs, err := p.ternary()
	if err != nil {
		return nil, err
	}
	if p.tok.kind == tkPunct {
		// "/=" at the start of an operand is a regex, never reached here: an operator is expected
		if op, ok := awkAssignOps[p.tok.s]; ok && isLvalue(lhs) {
			line := p.tok.line
			if err := p.advance(); err != nil {
				return nil, err
			}
			if err := p.skipNL(); err != nil {
				return nil, err
			}
			rhs, err := p.expr()
			if err != nil {
				return nil, err
			}
			return &awkNode{op: opAssign, subStr: op, a: lhs, b: rhs, line: line}, nil
		}
	}
	return lhs, nil
}

func (p *awkParser) ternary() (*awkNode, error) {
	cond, err := p.or()
	if err != nil {
		return nil, err
	}
	if !p.isP("?") {
		return cond, nil
	}
	if err := p.advance(); err != nil {
		return nil, err
	}
	if err := p.skipNL(); err != nil {
		return nil, err
	}
	a, err := p.expr()
	if err != nil {
		return nil, err
	}
	if err := p.skipNL(); err != nil {
		return nil, err
	}
	if err := p.expectP(":"); err != nil {
		return nil, err
	}
	if err := p.skipNL(); err != nil {
		return nil, err
	}
	b, err := p.expr()
	if err != nil {
		return nil, err
	}
	return &awkNode{op: opCond, a: cond, b: a, c: b}, nil
}

func (p *awkParser) or() (*awkNode, error) {
	l, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.isP("||") {
		if err := p.advance(); err != nil {
			return nil, err
		}
		if err := p.skipNL(); err != nil {
			return nil, err
		}
		r, err := p.and()
		if err != nil {
			return nil, err
		}
		l = &awkNode{op: opOr, a: l, b: r}
	}
	return l, nil
}

func (p *awkParser) and() (*awkNode, error) {
	l, err := p.in()
	if err != nil {
		return nil, err
	}
	for p.isP("&&") {
		if err := p.advance(); err != nil {
			return nil, err
		}
		if err := p.skipNL(); err != nil {
			return nil, err
		}
		r, err := p.in()
		if err != nil {
			return nil, err
		}
		l = &awkNode{op: opAnd, a: l, b: r}
	}
	return l, nil
}

func (p *awkParser) in() (*awkNode, error) {
	l, err := p.match()
	if err != nil {
		return nil, err
	}
	for p.isK("in") {
		if err := p.advance(); err != nil {
			return nil, err
		}
		if p.tok.kind != tkName {
			return nil, p.fail()
		}
		arr, err := p.nameNode()
		if err != nil {
			return nil, err
		}
		l = &awkNode{op: opIn, args: []*awkNode{l}, b: arr}
	}
	return l, nil
}

func (p *awkParser) match() (*awkNode, error) {
	l, err := p.cmp()
	if err != nil {
		return nil, err
	}
	for p.isP("~") || p.isP("!~") {
		op := opMatch
		if p.tok.s == "!~" {
			op = opNoMatch
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
		r, err := p.cmp()
		if err != nil {
			return nil, err
		}
		l = &awkNode{op: op, a: l, b: r}
	}
	return l, nil
}

func (p *awkParser) cmp() (*awkNode, error) {
	l, err := p.concat()
	if err != nil {
		return nil, err
	}
	for {
		switch {
		case p.isP("|"):
			// cmd | getline [var]
			m := p.mark()
			if err := p.advance(); err != nil {
				return nil, err
			}
			if !p.isK("getline") {
				p.reset(m)
				return l, nil
			}
			if err := p.advance(); err != nil {
				return nil, err
			}
			g := &awkNode{op: opGetline, sub: glCmd, b: l}
			if g.a, err = p.optLvalue(); err != nil {
				return nil, err
			}
			l = g
			continue
		case p.isP("<") || p.isP("<=") || p.isP("==") || p.isP("!=") || p.isP(">=") || (p.isP(">") && p.noGt == 0):
			op := p.tok.s
			if err := p.advance(); err != nil {
				return nil, err
			}
			r, err := p.concat()
			if err != nil {
				return nil, err
			}
			l = &awkNode{op: opCmp, subStr: op, a: l, b: r}
			continue
		}
		return l, nil
	}
}

func (p *awkParser) startsOperand() bool {
	switch p.tok.kind {
	case tkNumber, tkString, tkName, tkFuncName, tkBuiltin:
		return true
	case tkPunct:
		switch p.tok.s {
		case "$", "(", "!", "++", "--", "-", "+":
			return p.tok.s == "$" || p.tok.s == "(" || p.tok.s == "++" || p.tok.s == "--"
		}
	}
	return false
}

func (p *awkParser) concat() (*awkNode, error) {
	l, err := p.additive()
	if err != nil {
		return nil, err
	}
	for p.startsOperand() {
		r, err := p.additive()
		if err != nil {
			return nil, err
		}
		l = &awkNode{op: opConcat, a: l, b: r}
	}
	return l, nil
}

func (p *awkParser) additive() (*awkNode, error) {
	l, err := p.multiplicative()
	if err != nil {
		return nil, err
	}
	for p.isP("+") || p.isP("-") {
		op := p.tok.s
		if err := p.advance(); err != nil {
			return nil, err
		}
		r, err := p.multiplicative()
		if err != nil {
			return nil, err
		}
		l = &awkNode{op: opBinary, subStr: op, a: l, b: r}
	}
	return l, nil
}

func (p *awkParser) multiplicative() (*awkNode, error) {
	l, err := p.unary()
	if err != nil {
		return nil, err
	}
	for p.isP("*") || p.isP("/") || p.isP("%") {
		op := p.tok.s
		if err := p.advance(); err != nil {
			return nil, err
		}
		r, err := p.unary()
		if err != nil {
			return nil, err
		}
		l = &awkNode{op: opBinary, subStr: op, a: l, b: r, line: p.tok.line}
	}
	return l, nil
}

func (p *awkParser) unary() (*awkNode, error) {
	switch {
	case p.isP("!"):
		if err := p.advance(); err != nil {
			return nil, err
		}
		e, err := p.unary()
		return &awkNode{op: opNot, a: e}, err
	case p.isP("-"):
		if err := p.advance(); err != nil {
			return nil, err
		}
		e, err := p.unary()
		return &awkNode{op: opNeg, a: e}, err
	case p.isP("+"):
		if err := p.advance(); err != nil {
			return nil, err
		}
		e, err := p.unary()
		return &awkNode{op: opPlus, a: e}, err
	}
	return p.pow()
}

func (p *awkParser) pow() (*awkNode, error) {
	base, err := p.postfix()
	if err != nil {
		return nil, err
	}
	if p.isP("^") {
		if err := p.advance(); err != nil {
			return nil, err
		}
		var exp *awkNode
		switch {
		case p.isP("-"), p.isP("+"), p.isP("!"):
			exp, err = p.unary()
		default:
			exp, err = p.pow()
		}
		if err != nil {
			return nil, err
		}
		return &awkNode{op: opBinary, subStr: "^", a: base, b: exp}, nil
	}
	return base, nil
}

func (p *awkParser) postfix() (*awkNode, error) {
	if p.isP("++") || p.isP("--") {
		d := 1
		if p.tok.s == "--" {
			d = -1
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
		if p.tok.kind != tkName && !p.isP("$") {
			return nil, p.fail()
		}
		e, err := p.primary()
		if err != nil {
			return nil, err
		}
		if !isLvalue(e) {
			return nil, p.fail()
		}
		return &awkNode{op: opPreInc, sub: d, a: e}, nil
	}
	e, err := p.primary()
	if err != nil {
		return nil, err
	}
	if isLvalue(e) && (p.isP("++") || p.isP("--")) {
		d := 1
		if p.tok.s == "--" {
			d = -1
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
		return &awkNode{op: opPostInc, sub: d, a: e}, nil
	}
	return e, nil
}

// nameNode resolves the current name token to a variable node and moves past it.
func (p *awkParser) nameNode() (*awkNode, error) {
	name := p.tok.s
	if err := p.advance(); err != nil {
		return nil, err
	}
	return p.varNode(name), nil
}

func (p *awkParser) varNode(name string) *awkNode {
	if i, ok := p.locals[name]; ok {
		return &awkNode{op: opLocal, idx: i, str: name}
	}
	switch name {
	case "NF":
		return &awkNode{op: opSpecial, sub: spNF, str: name}
	case "NR":
		return &awkNode{op: opSpecial, sub: spNR, str: name}
	case "FNR":
		return &awkNode{op: opSpecial, sub: spFNR, str: name}
	}
	c := p.prog.globals[name]
	if c == nil {
		c = &awkCell{name: name}
		p.prog.globals[name] = c
	}
	return &awkNode{op: opVar, cell: c, str: name}
}

// optLvalue reads the variable after getline, when there is one.
func (p *awkParser) optLvalue() (*awkNode, error) {
	if p.tok.kind != tkName && !p.isP("$") {
		return nil, nil
	}
	return p.primary()
}

func (p *awkParser) primary() (*awkNode, error) {
	t := p.tok
	switch t.kind {
	case tkNumber:
		return &awkNode{op: opNum, num: t.n}, p.advance()
	case tkString:
		return &awkNode{op: opStr, str: t.s}, p.advance()
	case tkName:
		if err := p.advance(); err != nil {
			return nil, err
		}
		v := p.varNode(t.s)
		if p.isP("[") {
			if err := p.advance(); err != nil {
				return nil, err
			}
			subs, err := p.exprList("]")
			if err != nil {
				return nil, err
			}
			if len(subs) == 0 {
				return nil, p.fail()
			}
			return &awkNode{op: opIndex, a: v, args: subs}, nil
		}
		return v, nil
	case tkFuncName:
		if err := p.advance(); err != nil {
			return nil, err
		}
		if err := p.expectP("("); err != nil {
			return nil, err
		}
		args, err := p.exprList(")")
		if err != nil {
			return nil, err
		}
		n := &awkNode{op: opCall, str: t.s, args: args, line: t.line}
		p.calls = append(p.calls, n)
		return n, nil
	case tkBuiltin:
		return p.builtin()
	case tkKeyword:
		if t.s == "getline" {
			if err := p.advance(); err != nil {
				return nil, err
			}
			g := &awkNode{op: opGetline, sub: glPlain}
			var err error
			if g.a, err = p.optLvalue(); err != nil {
				return nil, err
			}
			if p.isP("<") {
				if err := p.advance(); err != nil {
					return nil, err
				}
				g.sub = glFile
				if g.b, err = p.postfixNoCmp(); err != nil {
					return nil, err
				}
			}
			return g, nil
		}
	case tkPunct:
		switch t.s {
		case "(":
			if err := p.advance(); err != nil {
				return nil, err
			}
			list, err := p.exprList(")")
			if err != nil {
				return nil, err
			}
			if len(list) == 0 {
				return nil, p.fail()
			}
			if len(list) > 1 {
				// (i, j) in array
				if !p.isK("in") {
					return nil, p.fail()
				}
				if err := p.advance(); err != nil {
					return nil, err
				}
				if p.tok.kind != tkName {
					return nil, p.fail()
				}
				arr, err := p.nameNode()
				if err != nil {
					return nil, err
				}
				return &awkNode{op: opIn, args: list, b: arr}, nil
			}
			return &awkNode{op: opGroup, a: list[0]}, nil
		case "$":
			if err := p.advance(); err != nil {
				return nil, err
			}
			var e *awkNode
			var err error
			switch {
			case p.isP("++") || p.isP("--"):
				e, err = p.postfix()
			case p.isP("-") || p.isP("+") || p.isP("!"):
				e, err = p.unary()
			default:
				e, err = p.primary()
			}
			if err != nil {
				return nil, err
			}
			return &awkNode{op: opField, a: e}, nil
		case "/", "/=":
			p.lex.pos = t.pos + 1
			re, err := p.lex.regex()
			if err != nil {
				return nil, err
			}
			if err := p.advance(); err != nil {
				return nil, err
			}
			return &awkNode{op: opRegex, str: re}, nil
		}
	}
	return nil, p.fail()
}

// postfixNoCmp is the file operand of `getline < file`: a primary, not a whole concatenation.
func (p *awkParser) postfixNoCmp() (*awkNode, error) { return p.primary() }

var awkBuiltinIDs = map[string]int{}

func (p *awkParser) builtin() (*awkNode, error) {
	name := p.tok.s
	if err := p.advance(); err != nil {
		return nil, err
	}
	n := &awkNode{op: opBuiltin, subStr: name, line: p.tok.line}
	if !p.isP("(") {
		if name == "length" {
			return n, nil // length with no parentheses is length($0)
		}
		return nil, p.fail()
	}
	if err := p.advance(); err != nil {
		return nil, err
	}
	args, err := p.exprList(")")
	if err != nil {
		return nil, err
	}
	n.args = args
	if err := checkBuiltinArgs(name, args); err != nil {
		return nil, awkErr(fmt.Sprintf("line %d: %s", p.tok.line, err))
	}
	return n, nil
}

func checkBuiltinArgs(name string, args []*awkNode) error {
	lo, hi := 1, 1
	switch name {
	case "length", "rand", "srand", "fflush", "int":
		lo, hi = 0, 1
		if name == "int" {
			lo = 1
		}
		if name == "rand" {
			hi = 0
		}
	case "substr":
		lo, hi = 2, 3
	case "index", "atan2", "match":
		lo, hi = 2, 2
	case "split":
		lo, hi = 2, 3
	case "sub", "gsub":
		lo, hi = 2, 3
	case "sprintf":
		lo, hi = 1, 1<<30
	}
	if len(args) < lo || len(args) > hi {
		return fmt.Errorf("wrong number of arguments in call to %s", name)
	}
	return nil
}
