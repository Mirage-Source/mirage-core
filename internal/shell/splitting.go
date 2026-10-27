package shell

import (
	"regexp"
	"strings"
)

// expansion collects the result of expanding one word. Literal text and the result of an expansion are told
// apart because bash splits only the second kind, and only when it was not quoted: with a="x y", `$a` is two
// words, `"$a"` is one, and so is the literal `x\ y`. A word whose unquoted expansion is empty vanishes
// (`$e` with e unset is no argument at all), while a quoted empty string stays one empty argument.
type expansion struct {
	split  bool   // split unquoted expansion results on ifs
	ifs    string // IFS characters; empty means no splitting at all
	fields []string
	cur    strings.Builder
	has    bool // cur holds a field, even an empty one (a quoted "")
	quoted bool
	zeroAt bool // inside quotes, "$@" expanded to no words at all
	mask   bool // hide quoted < and > from extractRedirects (see litLT)
}

// newExpansion starts an expansion that splits on the interpreter's IFS (" \t\n" when it is unset).
func (s *Interpreter) newExpansion(split bool) *expansion {
	ifs, set := s.Env["IFS"]
	if !set {
		ifs = " \t\n"
	}
	return &expansion{split: split, ifs: ifs}
}

func (e *expansion) lit(text string) {
	if e.mask && e.quoted {
		text = maskRedir.Replace(text)
	}
	if text != "" {
		e.cur.WriteString(text)
		e.has = true
	}
}

func (e *expansion) flush() {
	e.fields = append(e.fields, e.cur.String())
	e.cur.Reset()
	e.has = false
}

// exp appends the result of an expansion, splitting it on IFS unless it is quoted or splitting is off.
// IFS whitespace (space, tab, newline) around and between fields is dropped; any other IFS character ends
// a field exactly, so a:b::c has an empty third field, but a trailing delimiter adds no empty field. Text
// before and after the expansion in the same word joins the first and last field (pre$a -> prex y).
func (e *expansion) exp(text string) {
	if !e.split || e.quoted || e.ifs == "" {
		e.lit(text)
		return
	}
	closedByWS := false // the previous field was just ended by whitespace: a delimiter next to it adds nothing
	for i := 0; i < len(text); i++ {
		c := text[i]
		if strings.IndexByte(e.ifs, c) < 0 {
			e.cur.WriteByte(c)
			e.has = true
			closedByWS = false
			continue
		}
		isWS := c == ' ' || c == '\t' || c == '\n'
		switch {
		case isWS && e.has:
			e.flush()
			closedByWS = true
		case isWS:
			// leading or repeated whitespace
		case e.has:
			e.flush()
			closedByWS = false
		case closedByWS:
			closedByWS = false // "a : b": the colon belongs to the space before it
		default:
			e.flush() // a delimiter with nothing before it: an empty field
		}
	}
}

// params expands $@ or $* (at tells which) over the positional parameters args. Quoted, "$@" is one word
// per parameter, and no word at all when there are none; "$*" is one word joined by the first IFS
// character. Unquoted, each parameter is split like any other expansion. Where nothing is split (the right
// side of an assignment) both give one string.
func (e *expansion) params(args []string, at bool, join string) {
	switch {
	case !e.split:
		sep := join
		if at {
			sep = " "
		}
		e.lit(strings.Join(args, sep))
	case e.quoted && at:
		if len(args) == 0 {
			e.zeroAt = true
			return
		}
		for i, a := range args {
			if i > 0 {
				e.flush()
			}
			e.lit(a)
			e.has = true
		}
	case e.quoted:
		e.lit(strings.Join(args, join))
	default:
		for i, a := range args {
			if i > 0 && e.has {
				e.flush()
			}
			e.exp(a)
		}
	}
}

// result returns the fields, with the literal-dollar marks turned back into "$". Without splitting it is
// always exactly one string, empty or not.
func (e *expansion) result() []string {
	if !e.split {
		return []string{strings.ReplaceAll(e.cur.String(), litDollar, "$")}
	}
	if e.has {
		e.flush()
	}
	for i, f := range e.fields {
		e.fields[i] = strings.ReplaceAll(f, litDollar, "$")
	}
	return e.fields
}

var assignWord = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\+?=`)

// declarers take NAME=value arguments that bash does not split either (`export b=$a`).
var declarers = map[string]bool{"export": true, "local": true, "readonly": true, "declare": true, "typeset": true}

// substituteFields expands one marked word (see tokenizeWordsMarked) into the words it becomes: the
// substitutions of substitute, then word splitting of what unquoted expansions produced.
func (s *Interpreter) substituteFields(word string, split bool, depth int, bait *[]BaitHit, action string) []string {
	e := s.newExpansion(split)
	e.mask = true
	s.expandInto(word, depth, bait, action, e)
	return e.result()
}

// expandCommandWords is expandCommandWordsMasked for a caller with no redirects to look for.
func (s *Interpreter) expandCommandWords(text string, depth int, bait *[]BaitHit, action string) []string {
	return unmaskAll(s.expandCommandWordsMasked(text, depth, bait, action))
}

// expandCommandWordsMasked tokenizes and expands the words of one simple command. NAME=value words in
// front of the command, or after export/local/readonly/declare, keep their value whole, as bash does. A
// quoted < or > comes back masked: run extractRedirects, then unmaskAll what is left.
func (s *Interpreter) expandCommandWordsMasked(text string, depth int, bait *[]BaitHit, action string) []string {
	var out []string
	leading, declaring := true, false
	for _, w := range tokenizeWordsMarked(text) {
		if assignWord.MatchString(w) && (leading || declaring) {
			out = append(out, s.substituteFields(w, false, depth, bait, action)...)
			continue
		}
		fields := s.substituteFields(w, true, depth, bait, action)
		if leading && len(fields) > 0 {
			declaring = declarers[fields[0]]
		}
		if len(fields) > 0 {
			leading = false
		}
		out = append(out, fields...)
	}
	return out
}
