package shell

import (
	"path"
	"strings"
)

type itemKind int

const (
	kindSimple itemKind = iota
	kindIf
	kindGroup
	kindCase
)

type caseArm struct {
	patterns []string
	body     []item
}

// item is one node of a parsed line: a simple statement, or an if/{ }/case
// compound built from several statements. sep links it to the previous item.
type item struct {
	kind     itemKind
	sep      string
	text     string
	conds    [][]item
	bodies   [][]item
	elseBody []item
	body     []item
	word     string
	arms     []caseArm
}

type syntaxError string

func (e syntaxError) Error() string {
	if e == "" {
		return "bash: syntax error: unexpected end of file"
	}
	return "bash: syntax error near unexpected token `" + string(e) + "'"
}

var reservedWords = map[string]bool{"then": true, "elif": true, "else": true, "fi": true, "}": true, "esac": true}

// IsReservedWord reports whether name is shell syntax the interpreter parses
// itself (if/case/{ } and their closing words) rather than a command.
func IsReservedWord(name string) bool {
	return reservedWords[name] || name == "if" || name == "case" || name == "{"
}

func splitKeyword(text string) (string, string) {
	i := strings.IndexAny(text, " \t")
	if i < 0 {
		return text, ""
	}
	return text[:i], strings.TrimSpace(text[i+1:])
}

// firstRawWord splits off the first word of text, leaving quotes and $( )
// intact for later substitution.
func firstRawWord(text string) (string, string) {
	var quote byte
	depth := 0
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(':
			depth++
		case c == ')' && depth > 0:
			depth--
		case depth == 0 && (c == ' ' || c == '\t'):
			return text[:i], strings.TrimSpace(text[i+1:])
		}
	}
	return text, ""
}

type parser struct {
	stmts []statement
	pos   int
}

func parseStatements(stmts []statement) ([]item, error) {
	p := &parser{stmts: stmts}
	items, err := p.list(nil, false)
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.stmts) {
		kw, _ := splitKeyword(p.stmts[p.pos].Text)
		if p.stmts[p.pos].Sep == ";;" {
			kw = ";;"
		}
		return nil, syntaxError(kw)
	}
	return items, nil
}

func (p *parser) cur() (statement, bool) {
	if p.pos >= len(p.stmts) {
		return statement{}, false
	}
	return p.stmts[p.pos], true
}

// advance replaces the current statement with what follows a consumed
// keyword or case pattern.
func (p *parser) advance(rest string) {
	if rest == "" {
		p.pos++
		return
	}
	p.stmts[p.pos] = statement{Text: rest}
}

func (p *parser) list(stops map[string]bool, stopAtDoubleSemi bool) ([]item, error) {
	var items []item
	for {
		st, ok := p.cur()
		if !ok {
			return items, nil
		}
		kw, _ := splitKeyword(st.Text)
		if stops[kw] || (st.Sep == ";;" && stopAtDoubleSemi) {
			return items, nil
		}
		if st.Sep == ";;" {
			return nil, syntaxError(";;")
		}
		if reservedWords[kw] {
			return items, nil
		}
		it, err := p.item()
		if err != nil {
			return nil, err
		}
		items = append(items, it)
	}
}

func (p *parser) expect(kw string) error {
	st, ok := p.cur()
	if !ok {
		return syntaxError("")
	}
	got, rest := splitKeyword(st.Text)
	if got != kw {
		return syntaxError(got)
	}
	p.advance(rest)
	return nil
}

func (p *parser) nonEmpty(stops map[string]bool, stopAtDoubleSemi bool) ([]item, error) {
	items, err := p.list(stops, stopAtDoubleSemi)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		st, ok := p.cur()
		if !ok {
			return nil, syntaxError("")
		}
		kw, _ := splitKeyword(st.Text)
		return nil, syntaxError(kw)
	}
	return items, nil
}

func (p *parser) item() (item, error) {
	st, _ := p.cur()
	kw, rest := splitKeyword(st.Text)
	switch kw {
	case "if":
		p.advance(rest)
		return p.ifItem(st.Sep)
	case "{":
		p.advance(rest)
		body, err := p.nonEmpty(map[string]bool{"}": true}, false)
		if err != nil {
			return item{}, err
		}
		if err := p.expect("}"); err != nil {
			return item{}, err
		}
		return item{kind: kindGroup, sep: st.Sep, body: body}, nil
	case "case":
		return p.caseItem(st.Sep, rest)
	}
	p.pos++
	return item{kind: kindSimple, sep: st.Sep, text: st.Text}, nil
}

func (p *parser) ifItem(sep string) (item, error) {
	it := item{kind: kindIf, sep: sep}
	for {
		cond, err := p.nonEmpty(map[string]bool{"then": true}, false)
		if err != nil {
			return item{}, err
		}
		if err := p.expect("then"); err != nil {
			return item{}, err
		}
		body, err := p.nonEmpty(map[string]bool{"elif": true, "else": true, "fi": true}, false)
		if err != nil {
			return item{}, err
		}
		it.conds = append(it.conds, cond)
		it.bodies = append(it.bodies, body)

		st, ok := p.cur()
		if !ok {
			return item{}, syntaxError("")
		}
		kw, rest := splitKeyword(st.Text)
		switch kw {
		case "elif":
			p.advance(rest)
			continue
		case "else":
			p.advance(rest)
			if it.elseBody, err = p.nonEmpty(map[string]bool{"fi": true}, false); err != nil {
				return item{}, err
			}
		}
		return it, p.expect("fi")
	}
}

func (p *parser) caseItem(sep, rest string) (item, error) {
	word, rest := firstRawWord(rest)
	in, rest := splitKeyword(rest)
	if word == "" || in != "in" {
		return item{}, syntaxError(in)
	}
	it := item{kind: kindCase, sep: sep, word: word}
	p.advance(rest)
	for {
		st, ok := p.cur()
		if !ok {
			return item{}, syntaxError("")
		}
		if kw, after := splitKeyword(st.Text); kw == "esac" {
			p.advance(after)
			return it, nil
		}
		text := strings.TrimPrefix(st.Text, "(")
		end := strings.IndexByte(text, ')')
		if end < 0 {
			kw, _ := splitKeyword(st.Text)
			return item{}, syntaxError(kw)
		}
		var pats []string
		for _, pat := range strings.Split(text[:end], "|") {
			pats = append(pats, strings.TrimSpace(pat))
		}
		p.advance(strings.TrimSpace(text[end+1:]))
		body, err := p.list(map[string]bool{"esac": true}, true)
		if err != nil {
			return item{}, err
		}
		it.arms = append(it.arms, caseArm{patterns: pats, body: body})
	}
}

func (s *Interpreter) expandWord(raw string, depth int, bait *[]BaitHit, action string) string {
	words := tokenizeWords(raw)
	for i, w := range words {
		words[i] = s.substitute(w, depth, bait, action)
	}
	return strings.Join(words, " ")
}

func (s *Interpreter) runItems(items []item, depth int, bait *[]BaitHit, action string, outputs *[]string) int {
	last := 0
	for i, it := range items {
		if i > 0 && ((it.sep == "&&" && last != 0) || (it.sep == "||" && last == 0)) {
			continue
		}
		switch it.kind {
		case kindSimple:
			out, code, ran := s.execStatement(it.text, depth, bait, action)
			if !ran {
				continue
			}
			last = code
			if out != "" {
				*outputs = append(*outputs, out)
			}
		case kindGroup:
			last = s.runItems(it.body, depth, bait, action, outputs)
		case kindIf:
			last = 0
			taken := false
			for j, cond := range it.conds {
				if s.runItems(cond, depth, bait, action, outputs) == 0 {
					last = s.runItems(it.bodies[j], depth, bait, action, outputs)
					taken = true
					break
				}
			}
			if !taken && it.elseBody != nil {
				last = s.runItems(it.elseBody, depth, bait, action, outputs)
			}
		case kindCase:
			last = 0
			word := s.expandWord(it.word, depth, bait, action)
		arms:
			for _, arm := range it.arms {
				for _, pat := range arm.patterns {
					if ok, _ := path.Match(s.expandWord(pat, depth, bait, action), word); ok {
						last = s.runItems(arm.body, depth, bait, action, outputs)
						break arms
					}
				}
			}
		}
	}
	return last
}
