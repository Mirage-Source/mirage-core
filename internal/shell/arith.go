package shell

import (
	"strconv"
	"strings"
)

// evalArith evaluates a bash $(( )) expression over integers: + - * / % ( ),
// unary - + !, comparisons, && ||, numbers (decimal, 0x, 0 octal) and
// variable names with or without $. ok is false for a malformed expression.
func (s *Interpreter) evalArith(expr string) (int64, bool) {
	a := &shArith{s: s, src: strings.TrimSpace(expr)}
	v, ok := a.or()
	a.skip()
	return v, ok && a.pos == len(a.src)
}

type shArith struct {
	s     *Interpreter
	src   string
	pos   int
	depth int // expressions nested through variable values
}

func (a *shArith) skip() {
	for a.pos < len(a.src) && (a.src[a.pos] == ' ' || a.src[a.pos] == '\t') {
		a.pos++
	}
}

func (a *shArith) eat(tok string) bool {
	a.skip()
	if strings.HasPrefix(a.src[a.pos:], tok) {
		a.pos += len(tok)
		return true
	}
	return false
}

func (a *shArith) or() (int64, bool) {
	l, ok := a.and()
	for ok && a.eat("||") {
		r, ok2 := a.and()
		ok = ok2
		l = b2i(l != 0 || r != 0)
	}
	return l, ok
}

func (a *shArith) and() (int64, bool) {
	l, ok := a.cmp()
	for ok && a.eat("&&") {
		r, ok2 := a.cmp()
		ok = ok2
		l = b2i(l != 0 && r != 0)
	}
	return l, ok
}

func (a *shArith) cmp() (int64, bool) {
	l, ok := a.add()
	for ok {
		var f func(x, y int64) bool
		switch {
		case a.eat("=="):
			f = func(x, y int64) bool { return x == y }
		case a.eat("!="):
			f = func(x, y int64) bool { return x != y }
		case a.eat("<="):
			f = func(x, y int64) bool { return x <= y }
		case a.eat(">="):
			f = func(x, y int64) bool { return x >= y }
		case a.eat("<"):
			f = func(x, y int64) bool { return x < y }
		case a.eat(">"):
			f = func(x, y int64) bool { return x > y }
		default:
			return l, ok
		}
		r, ok2 := a.add()
		ok = ok2
		l = b2i(f(l, r))
	}
	return l, ok
}

func (a *shArith) add() (int64, bool) {
	l, ok := a.mul()
	for ok {
		switch {
		case a.eat("+"):
			r, ok2 := a.mul()
			ok, l = ok2, l+r
		case a.eat("-"):
			r, ok2 := a.mul()
			ok, l = ok2, l-r
		default:
			return l, ok
		}
	}
	return l, ok
}

func (a *shArith) mul() (int64, bool) {
	l, ok := a.unary()
	for ok {
		switch {
		case a.eat("*"):
			r, ok2 := a.unary()
			ok, l = ok2, l*r
		case a.eat("/"):
			r, ok2 := a.unary()
			if ok2 && r == 0 {
				return 0, false
			}
			if ok2 {
				l /= r
			}
			ok = ok2
		case a.eat("%"):
			r, ok2 := a.unary()
			if ok2 && r == 0 {
				return 0, false
			}
			if ok2 {
				l %= r
			}
			ok = ok2
		default:
			return l, ok
		}
	}
	return l, ok
}

func (a *shArith) unary() (int64, bool) {
	switch {
	case a.eat("-"):
		v, ok := a.unary()
		return -v, ok
	case a.eat("+"):
		return a.unary()
	case a.eat("!"):
		v, ok := a.unary()
		return b2i(v == 0), ok
	case a.eat("("):
		v, ok := a.or()
		return v, ok && a.eat(")")
	}
	a.skip()
	start := a.pos
	if a.pos < len(a.src) && a.src[a.pos] == '$' {
		a.pos++
	}
	nameStart := a.pos
	switch {
	case a.pos < len(a.src) && a.src[a.pos] >= '0' && a.src[a.pos] <= '9' && start == nameStart:
		for a.pos < len(a.src) && (isIdentPart(a.src[a.pos])) {
			a.pos++
		}
		n, err := strconv.ParseInt(a.src[start:a.pos], 0, 64)
		return n, err == nil
	case start != nameStart && a.pos < len(a.src) && (a.src[a.pos] == '#' || a.src[a.pos] == '?' || (a.src[a.pos] >= '0' && a.src[a.pos] <= '9')):
		// $1, $#, $?: positional and special parameters
		if a.src[a.pos] >= '0' && a.src[a.pos] <= '9' {
			for a.pos < len(a.src) && a.src[a.pos] >= '0' && a.src[a.pos] <= '9' {
				a.pos++
			}
		} else {
			a.pos++
		}
		v := strings.TrimSpace(a.s.param(a.src[nameStart:a.pos]))
		if v == "" {
			return 0, true
		}
		n, err := strconv.ParseInt(v, 0, 64)
		return n, err == nil
	case a.pos < len(a.src) && isIdentStart(a.src[a.pos]):
		for a.pos < len(a.src) && isIdentPart(a.src[a.pos]) {
			a.pos++
		}
		v := strings.TrimSpace(a.s.param(a.src[nameStart:a.pos]))
		if v == "" {
			return 0, true
		}
		n, err := strconv.ParseInt(v, 0, 64)
		if err != nil && a.depth < 16 {
			// bash evaluates a variable's text as an expression of its own (a=b, b=3 gives a=3)
			inner := &shArith{s: a.s, src: v, depth: a.depth + 1}
			n, ok := inner.or()
			inner.skip()
			return n, ok && inner.pos == len(inner.src)
		}
		return n, err == nil
	}
	return 0, false
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
