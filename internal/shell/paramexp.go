package shell

import (
	"regexp"
	"strconv"
	"strings"
)

// Parameter expansion: the ${...} forms bash scripts lean on. NAME may be a variable, a digit string or
// one of ? $ ! @ * # -. The operators implemented are
//
//	:- - := = :? ? :+ +      default, assign, error, alternative (: also treats empty as unset)
//	# ## % %%                remove the shortest/longest prefix/suffix matching a glob
//	/ // /# /%               replace the first/every/leading/trailing match of a glob
//	:off :off:len            substring
//	^ ^^ , ,,                change case
//	#NAME                    length
//
// Anything else (arrays, ${!name}) expands as it always did.

// maxExpandLen bounds the work done on one value: replacing and trimming try many match boundaries, and
// the value is attacker-controlled.
const maxExpandLen = 2048

// matchingBrace returns the index of the } closing a ${ whose body starts at pos, or -1.
func matchingBrace(s string, pos int) int {
	depth := 1
	for i := pos; i < len(s); i++ {
		switch {
		case s[i] == '\\':
			i++
		case s[i] == '\'':
			if j := strings.IndexByte(s[i+1:], '\''); j >= 0 {
				i += j + 1
			}
		case s[i] == '$' && i+1 < len(s) && s[i+1] == '{':
			depth++
			i++
		case s[i] == '}':
			if depth--; depth == 0 {
				return i
			}
		}
	}
	return -1
}

func splitParamName(inner string) (name, rest string) {
	if inner == "" {
		return "", ""
	}
	switch c := inner[0]; {
	case isIdentStart(c):
		j := 1
		for j < len(inner) && isIdentPart(inner[j]) {
			j++
		}
		return inner[:j], inner[j:]
	case c >= '0' && c <= '9':
		j := 1
		for j < len(inner) && inner[j] >= '0' && inner[j] <= '9' {
			j++
		}
		return inner[:j], inner[j:]
	}
	return inner[:1], inner[1:]
}

// paramSet reports whether NAME is set (not merely non-empty). Positional parameters are set only up to
// the number a function was called with; ! is never set.
func (s *Interpreter) paramSet(name string) bool {
	switch name {
	case "?", "$", "#", "-", "0":
		return true
	case "!":
		return false
	case "@", "*":
		return len(s.posArgs()) > 0
	}
	if name != "" && name[0] >= '0' && name[0] <= '9' {
		n, err := strconv.Atoi(name)
		_, ok := s.positional(n)
		return err == nil && ok
	}
	_, ok := s.Env[name]
	return ok
}

// expandBrace expands the text between ${ and }. ok is false for a form it does not know.
func (s *Interpreter) expandBrace(inner string, depth int, bait *[]BaitHit, action string) (string, bool) {
	if len(inner) > 1 && inner[0] == '#' {
		if name, rest := splitParamName(inner[1:]); rest == "" && name != "" {
			return strconv.Itoa(len([]rune(s.param(name)))), true
		}
	}
	name, rest := splitParamName(inner)
	if name == "" {
		return "", false
	}
	val := s.param(name)
	if rest == "" {
		return val, true
	}
	// An operand with quotes or backslashes goes through the tokenizer, which removes them; any other
	// operand is expanded as it stands, because its spaces matter (${y// /_}).
	expand := func(w string) string {
		if strings.ContainsAny(w, "'\"\\") {
			return s.expandWord(w, depth, bait, action)
		}
		return s.substitute(w, depth, bait, action)
	}

	colon := rest[0] == ':'
	op := rest
	if colon {
		if len(rest) < 2 {
			return "", false
		}
		op = rest[1:]
	}
	unsetOrNull := !s.paramSet(name) || (colon && val == "")

	switch {
	case op[0] == '-':
		if unsetOrNull {
			return expand(op[1:]), true
		}
		return val, true
	case op[0] == '=':
		if unsetOrNull {
			v := expand(op[1:])
			if isIdentStart(name[0]) {
				s.Env[name] = v
			}
			return v, true
		}
		return val, true
	case op[0] == '+':
		if unsetOrNull {
			return "", true
		}
		return expand(op[1:]), true
	case op[0] == '?':
		if unsetOrNull {
			msg := expand(op[1:])
			if msg == "" {
				msg = "parameter not set"
				if colon {
					msg = "parameter null or not set"
				}
			}
			s.pendingErr = append(s.pendingErr, "bash: "+name+": "+msg)
			if s.exec {
				s.halted, s.haltCode = true, 127
			}
			return "", true
		}
		return val, true
	}
	if colon { // ${v:offset[:length]}
		return s.substring(val, op, depth, bait, action), true
	}

	switch {
	case strings.HasPrefix(rest, "##"), strings.HasPrefix(rest, "#"):
		longest := strings.HasPrefix(rest, "##")
		pat := rest[1:]
		if longest {
			pat = rest[2:]
		}
		return trimGlob(val, expand(pat), true, longest), true
	case strings.HasPrefix(rest, "%%"), strings.HasPrefix(rest, "%"):
		longest := strings.HasPrefix(rest, "%%")
		pat := rest[1:]
		if longest {
			pat = rest[2:]
		}
		return trimGlob(val, expand(pat), false, longest), true
	case rest[0] == '/':
		return replaceGlob(val, rest[1:], expand), true
	case strings.HasPrefix(rest, "^^"):
		return strings.ToUpper(val), true
	case rest[0] == '^':
		return upperFirst(val, true), true
	case strings.HasPrefix(rest, ",,"):
		return strings.ToLower(val), true
	case rest[0] == ',':
		return upperFirst(val, false), true
	}
	return "", false
}

func upperFirst(v string, up bool) string {
	r := []rune(v)
	if len(r) == 0 {
		return v
	}
	f := string(r[0])
	if up {
		f = strings.ToUpper(f)
	} else {
		f = strings.ToLower(f)
	}
	return f + string(r[1:])
}

// substring is ${v:off} and ${v:off:len}; a negative offset counts from the end, a negative length
// stops that many characters before the end.
func (s *Interpreter) substring(val, spec string, depth int, bait *[]BaitHit, action string) string {
	offExpr, lenExpr, hasLen := strings.Cut(spec, ":")
	num := func(e string) (int, bool) {
		e = strings.TrimSpace(s.substitute(e, depth, bait, action))
		if e == "" {
			return 0, true
		}
		v, ok := s.evalArith(e)
		return int(v), ok
	}
	off, ok := num(offExpr)
	if !ok {
		return ""
	}
	r := []rune(val)
	if off < 0 {
		off += len(r)
		if off < 0 {
			return ""
		}
	}
	if off > len(r) {
		return ""
	}
	end := len(r)
	if hasLen {
		n, ok := num(lenExpr)
		if !ok {
			return ""
		}
		if n < 0 {
			end = len(r) + n
			if end < off {
				return ""
			}
		} else if off+n < end {
			end = off + n
		}
	}
	return string(r[off:end])
}

// globRegexp turns a shell pattern (* ? [set] and backslash escapes) into an anchored regexp.
func globRegexp(pat string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("(?s)^")
	for i := 0; i < len(pat); i++ {
		switch c := pat[i]; c {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		case '\\':
			if i+1 < len(pat) {
				i++
				b.WriteString(regexp.QuoteMeta(string(pat[i])))
			}
		case '[':
			j := i + 1
			if j < len(pat) && (pat[j] == '!' || pat[j] == '^') {
				j++
			}
			if j < len(pat) && pat[j] == ']' {
				j++
			}
			for j < len(pat) && pat[j] != ']' {
				j++
			}
			if j >= len(pat) {
				b.WriteString(`\[`)
				continue
			}
			set := pat[i+1 : j]
			if set != "" && (set[0] == '!' || set[0] == '^') {
				set = "^" + set[1:]
			}
			b.WriteString("[" + strings.ReplaceAll(set, `\`, `\\`) + "]")
			i = j
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	return re
}

// globMatch reports whether text matches the shell pattern pat, as a case arm does: * crosses "/" and [!x]
// negates a set.
func globMatch(pat, text string) bool {
	re := globRegexp(pat)
	return re != nil && re.MatchString(text)
}

// trimGlob is ${v#pat} ${v##pat} (prefix) and ${v%pat} ${v%%pat} (suffix).
func trimGlob(val, pat string, prefix, longest bool) string {
	r := []rune(val)
	if pat == "" || len(r) > maxExpandLen {
		return val
	}
	re := globRegexp(pat)
	if re == nil {
		return val
	}
	n := len(r)
	if prefix {
		for k := 0; k <= n; k++ {
			l := k
			if longest {
				l = n - k
			}
			if re.MatchString(string(r[:l])) {
				return string(r[l:])
			}
		}
		return val
	}
	for k := 0; k <= n; k++ {
		l := k
		if !longest {
			l = n - k
		}
		if re.MatchString(string(r[l:])) {
			return string(r[:l])
		}
	}
	return val
}

// replaceGlob is ${v/pat/rep} (first), ${v//pat/rep} (all), ${v/#pat/rep} and ${v/%pat/rep}.
func replaceGlob(val, spec string, expand func(string) string) string {
	all, anchor := false, byte(0)
	switch {
	case strings.HasPrefix(spec, "/"):
		all, spec = true, spec[1:]
	case strings.HasPrefix(spec, "#"), strings.HasPrefix(spec, "%"):
		anchor, spec = spec[0], spec[1:]
	}
	patRaw, repRaw, _ := strings.Cut(spec, "/")
	pat, rep := expand(patRaw), expand(repRaw)
	r := []rune(val)
	if pat == "" || len(r) > maxExpandLen {
		return val
	}
	re := globRegexp(pat)
	if re == nil {
		return val
	}
	var out strings.Builder
	for i := 0; i < len(r); {
		matched := -1
		for e := len(r); e > i; e-- { // longest match starting at i
			if anchor == '#' && i != 0 {
				break
			}
			if anchor == '%' && e != len(r) {
				continue
			}
			if re.MatchString(string(r[i:e])) {
				matched = e
				break
			}
		}
		if matched < 0 {
			out.WriteRune(r[i])
			i++
			continue
		}
		out.WriteString(rep)
		i = matched
		if !all || anchor != 0 {
			out.WriteString(string(r[i:]))
			return out.String()
		}
	}
	return out.String()
}
