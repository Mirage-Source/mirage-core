package shell

import (
	"maps"
	"path"
	"strings"
)

type itemKind int

const (
	kindSimple itemKind = iota
	kindIf
	kindGroup
	kindCase
	kindFor
	kindWhile
	kindUntil
	kindSubshell
)

const maxLoopIterations = 1000

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
	words    []string
	input    string // while/until: file from `done < file`, read by `read`
}

type syntaxError string

func (e syntaxError) Error() string {
	if e == "" {
		return "bash: syntax error: unexpected end of file"
	}
	return "bash: syntax error near unexpected token `" + string(e) + "'"
}

var reservedWords = map[string]bool{"then": true, "elif": true, "else": true, "fi": true, "}": true, "esac": true, "do": true, "done": true}

// IsReservedWord reports whether name is shell syntax the interpreter parses
// itself (if/case/{ } and their closing words) rather than a command.
func IsReservedWord(name string) bool {
	return reservedWords[name] || name == "if" || name == "case" || name == "for" || name == "while" || name == "until" || name == "{"
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
	if strings.HasPrefix(st.Text, "(") && !strings.HasPrefix(st.Text, "((") {
		return p.subshellItem(st)
	}
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
	case "for":
		return p.forItem(st.Sep, rest)
	case "while", "until":
		p.advance(rest)
		return p.whileItem(st.Sep, kw == "until")
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

func (p *parser) forItem(sep, rest string) (item, error) {
	name, rest := firstRawWord(rest)
	in, rest := splitKeyword(rest)
	if name == "" || in != "in" {
		return item{}, syntaxError(in)
	}
	it := item{kind: kindFor, sep: sep, word: name}
	for rest != "" {
		var w string
		w, rest = firstRawWord(rest)
		it.words = append(it.words, w)
	}
	p.pos++
	if err := p.expect("do"); err != nil {
		return item{}, err
	}
	body, err := p.nonEmpty(map[string]bool{"done": true}, false)
	if err != nil {
		return item{}, err
	}
	it.body = body
	return it, p.expect("done")
}

// subshellItem parses `( list ) [redirects]`. The statement splitter keeps
// a parenthesised group in one statement, so its body is re-split here and
// whatever follows the closing paren is kept as the group's redirects.
func (p *parser) subshellItem(st statement) (item, error) {
	end := closingParen(st.Text)
	if end < 0 {
		return item{}, syntaxError("")
	}
	body, err := parseStatements(splitStatements(st.Text[1:end]))
	if err != nil {
		return item{}, err
	}
	if len(body) == 0 {
		return item{}, syntaxError(")")
	}
	p.pos++
	return item{kind: kindSubshell, sep: st.Sep, body: body, text: strings.TrimSpace(st.Text[end+1:])}, nil
}

// closingParen returns the index of the paren closing text[0], or -1.
func closingParen(text string) int {
	depth := 0
	var quote byte
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
		case c == ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// runSubshell runs a ( ) group: cd and variable changes stay inside it, file
// writes do not. Output that follows a nonzero exit is treated as the
// group's stderr, the same heuristic simple commands use (isErrorChannel),
// so `(fetch || fetch) > f` shows its errors and still creates f.
func (s *Interpreter) runSubshell(it item, depth int, bait *[]BaitHit, action string, outputs *[]string) int {
	cwd, env := s.Cwd, maps.Clone(s.Env)
	var inner []string
	code := s.runItems(it.body, depth, bait, action, &inner)
	s.Cwd, s.Env = cwd, env

	// `( ... ) | cmd` hands the output to a reader this shell doesn't run.
	if strings.HasPrefix(it.text, "|") {
		return code
	}
	var words []string
	for _, w := range tokenizeWords(it.text) {
		words = append(words, s.substitute(w, depth, bait, action))
	}
	_, red := extractRedirects(words)
	errChan := code != 0
	if errChan && red.stdoutFile != "" {
		if msg, c := s.writeFile(red.stdoutFile, "", red.appendMode); c != 0 {
			*outputs = append(*outputs, msg)
			return 1
		}
	}
	visible, ok := s.routeStageOutput(strings.Join(inner, "\r\n"), errChan, red, true)
	if visible != "" {
		*outputs = append(*outputs, visible)
	}
	if !ok {
		return 1
	}
	return code
}

func (p *parser) whileItem(sep string, until bool) (item, error) {
	it := item{kind: kindWhile, sep: sep}
	if until {
		it.kind = kindUntil
	}
	cond, err := p.nonEmpty(map[string]bool{"do": true}, false)
	if err != nil {
		return item{}, err
	}
	if err := p.expect("do"); err != nil {
		return item{}, err
	}
	body, err := p.nonEmpty(map[string]bool{"done": true}, false)
	if err != nil {
		return item{}, err
	}
	it.conds, it.body = [][]item{cond}, body

	// `done < file` feeds the loop's `read`; it must be consumed here, or
	// "< file" would be left behind as a statement of its own.
	st, ok := p.cur()
	if !ok {
		return item{}, syntaxError("")
	}
	got, rest := splitKeyword(st.Text)
	if strings.HasPrefix(got, "done<") {
		got, rest = "done", strings.TrimSpace(st.Text[len("done"):])
	}
	if got != "done" {
		return item{}, syntaxError(got)
	}
	if strings.HasPrefix(rest, "<") {
		it.input, rest = firstRawWord(strings.TrimSpace(rest[1:]))
	}
	p.advance(rest)
	return it, nil
}

// runWhile runs a while/until loop, capped like for at maxLoopIterations.
// A `done < file` redirect becomes the lines `read` consumes.
func (s *Interpreter) runWhile(it item, depth int, bait *[]BaitHit, action string, outputs *[]string) int {
	saved := s.loopInput
	defer func() { s.loopInput = saved }()
	if it.input != "" {
		file := s.expandWord(it.input, depth, bait, action)
		text, ok := s.builtinInput(file, nil)
		if !ok || file == "" {
			*outputs = append(*outputs, s.shellMsg(s.profile.msgs.openMissing, file))
			return 1
		}
		lines := splitLines(text)
		s.loopInput = &lines
	} else {
		s.loopInput = nil
	}

	last := 0
	for n := 0; n < maxLoopIterations; n++ {
		ok := s.runItems(it.conds[0], depth, bait, action, outputs) == 0
		if ok == (it.kind == kindUntil) {
			break
		}
		last = s.runItems(it.body, depth, bait, action, outputs)
	}
	return last
}

// readBuiltin assigns the next line of the enclosing loop's redirected
// input. With no such input it fails at once instead of blocking on a
// terminal, which ends the loop.
func (s *Interpreter) readBuiltin(args []string) (string, int) {
	if s.loopInput == nil || len(*s.loopInput) == 0 {
		return "", 1
	}
	line := (*s.loopInput)[0]
	*s.loopInput = (*s.loopInput)[1:]
	var names []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			names = append(names, a)
		}
	}
	if len(names) == 0 {
		names = []string{"REPLY"}
	}
	fields := strings.Fields(line)
	for i, name := range names {
		switch {
		case i == len(names)-1 && i < len(fields):
			s.Env[name] = strings.Join(fields[i:], " ")
		case i < len(fields):
			s.Env[name] = fields[i]
		default:
			s.Env[name] = ""
		}
	}
	return "", 0
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
		case kindFor:
			last = 0
			var values []string
			for _, raw := range it.words {
				v := s.expandWord(raw, depth, bait, action)
				if strings.Contains(raw, "$") && raw[0] != '"' && raw[0] != '\'' {
					values = append(values, strings.Fields(v)...)
				} else {
					values = append(values, v)
				}
			}
			for n, v := range values {
				if n == maxLoopIterations {
					break
				}
				s.Env[it.word] = v
				last = s.runItems(it.body, depth, bait, action, outputs)
			}
		case kindWhile, kindUntil:
			last = s.runWhile(it, depth, bait, action, outputs)
		case kindSubshell:
			last = s.runSubshell(it, depth, bait, action, outputs)
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
