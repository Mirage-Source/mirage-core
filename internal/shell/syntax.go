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
	feed     string // while/until: the producer of `producer | while ...`; its output is what `read` consumes
	line     int    // simple: see statement.Line
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
	// A closing word can take a redirect with no space: `done</proc/self/exe`.
	for _, kw := range []string{"done", "fi", "esac", "}"} {
		if rest, ok := strings.CutPrefix(text, kw); ok && rest != "" && (rest[0] == '<' || rest[0] == '>') {
			return kw, rest
		}
	}
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
	var cs caseScope
	for i := 0; i < len(text); i++ {
		c := text[i]
		skip := quote == 0 && cs.step(text, i)
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(' && !skip:
			depth++
		case c == ')' && depth > 0 && !skip:
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

// item parses one item. A compound command (`{ }`, if, for, while, case)
// followed by `| cmd` keeps that pipe as its text, so its output can be fed on.
func (p *parser) item() (item, error) {
	it, err := p.itemInner()
	if err != nil || it.kind == kindSimple || it.kind == kindSubshell {
		return it, err
	}
	if st, ok := p.cur(); ok {
		if t := strings.TrimSpace(st.Text); strings.HasPrefix(t, "|") && !strings.HasPrefix(t, "||") {
			it.text = t
			p.pos++
		}
	}
	return it, nil
}

func (p *parser) itemInner() (item, error) {
	st, _ := p.cur()
	// `producer | while read ...; do ...; done`: the loop is the last stage of the pipeline and reads the
	// producer's output. Parse it as the loop and remember the producer.
	if feed, loop, ok := splitFeed(st.Text); ok {
		p.stmts[p.pos].Text = loop
		it, err := p.itemInner()
		it.feed = feed
		return it, err
	}
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
	return item{kind: kindSimple, sep: st.Sep, text: st.Text, line: st.Line}, nil
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
	return item{kind: kindSubshell, sep: st.Sep, body: body, line: st.Line, text: strings.TrimSpace(st.Text[end+1:])}, nil
}

// closingParen returns the index of the paren closing text[0], or -1.
func closingParen(text string) int {
	depth := 0
	var quote byte
	var cs caseScope
	for i := 0; i < len(text); i++ {
		c := text[i]
		skip := quote == 0 && cs.step(text, i)
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(' && !skip:
			depth++
		case c == ')' && !skip:
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
func (s *Interpreter) runSubshell(it item, depth int, bait *[]BaitHit, action string, outputs *[]outChunk) int {
	cwd, env := s.Cwd, maps.Clone(s.Env)
	var inner []outChunk
	savedBase := s.lineBase
	s.lineBase += it.line - 1 // the group's text was split again: keep script line numbers
	code := s.asSubshell(func() int { return s.runItems(it.body, depth, bait, action, &inner) })
	s.lineBase = savedBase
	s.Cwd, s.Env = cwd, env

	// `( ... ) | cmd`: the group's stdout is the stdin of the rest of the
	// pipeline, which is run here (it may be more groups, or plain commands).
	if strings.HasPrefix(it.text, "|") {
		return s.pipeInto(inner, it.text, depth, bait, action, outputs, code)
	}
	var words []string
	for _, w := range tokenizeWords(it.text) {
		words = append(words, s.substitute(w, depth, bait, action))
	}
	_, red := extractRedirects(words)
	errChan := code != 0
	if errChan && red.stdoutFile != "" {
		if msg, c := s.writeFile(red.stdoutFile, "", red.appendMode); c != 0 {
			*outputs = append(*outputs, s.chunk(msg, true))
			return 1
		}
	}
	if red.stdoutFile == "" && red.stderrFile == "" && red.combinedFile == "" {
		*outputs = append(*outputs, inner...) // nothing redirected: keep each stream
		return code
	}
	visible, ok := s.routeStageOutput(joinChunks(inner, "\r\n"), errChan, red, true)
	if visible != "" {
		*outputs = append(*outputs, outChunk{text: visible, stderr: errChan || !ok})
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
func (s *Interpreter) runWhile(it item, depth int, bait *[]BaitHit, action string, outputs *[]outChunk) int {
	saved, savedPartial := s.loopInput, s.loopPartial
	defer func() { s.loopInput, s.loopPartial = saved, savedPartial }()
	s.loopPartial = false
	switch {
	case it.feed != "":
		// A pipeline stage runs in a subshell: nothing the loop assigns or `cd`s into outlives it.
		cwd, env := s.Cwd, maps.Clone(s.Env)
		defer func() { s.Cwd, s.Env = cwd, env }()
		chunks, _ := s.evalChunks(it.feed, depth, bait, action)
		var stdout []outChunk
		for _, c := range chunks {
			if c.stderr {
				*outputs = append(*outputs, c)
			} else {
				stdout = append(stdout, c)
			}
		}
		text := strings.ReplaceAll(joinChunks(stdout, "\r\n"), "\r\n", "\n")
		if text != "" && (len(stdout) == 0 || !stdout[len(stdout)-1].noNewline) {
			text += "\n"
		}
		lines, partial := readLines(text)
		s.loopInput, s.loopPartial = &lines, partial
	case it.input != "":
		file := s.expandWord(it.input, depth, bait, action)
		text, ok := s.builtinInput(file, nil)
		if !ok || file == "" {
			*outputs = append(*outputs, s.chunk(s.shellMsg(s.profile.msgs.openMissing, file), true))
			return 1
		}
		lines, partial := readLines(text)
		s.loopInput, s.loopPartial = &lines, partial
	default:
		s.loopInput = nil
	}

	last := 0
	s.loopDepth++
	defer func() { s.loopDepth-- }()
	for n := 0; n < maxLoopIterations; n++ {
		s.errexitOff++
		ok := s.runItems(it.conds[0], depth, bait, action, outputs) == 0
		s.errexitOff--
		if s.halted || ok == (it.kind == kindUntil) {
			break
		}
		last = s.runItems(it.body, depth, bait, action, outputs)
		if s.halted {
			break
		}
		if s.loopCtl == "break" {
			s.loopCtl = ""
			break
		}
		s.loopCtl = ""
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
	partial := s.loopPartial && len(*s.loopInput) == 0 // an unterminated last line is assigned, but read fails

	var names []string
	raw := false
	for _, a := range args {
		switch {
		case a == "--":
		case strings.HasPrefix(a, "-"):
			raw = raw || strings.Contains(a, "r")
		default:
			names = append(names, a)
		}
	}
	if !raw {
		line = unescapeRead(line)
	}
	if len(names) == 0 {
		s.Env["REPLY"] = line // no names: the whole line, untrimmed
	} else {
		ifs, set := s.Env["IFS"]
		if !set {
			ifs = " \t\n"
		}
		for i, v := range splitReadFields(line, len(names), ifs) {
			s.Env[names[i]] = v
		}
	}
	if partial {
		return "", 1
	}
	return "", 0
}

// unescapeRead drops the backslash `read` removes without -r, keeping the character after it.
func unescapeRead(line string) string {
	if !strings.Contains(line, "\\") {
		return line
	}
	var b strings.Builder
	for i := 0; i < len(line); i++ {
		if line[i] == '\\' {
			i++
			if i >= len(line) {
				break
			}
		}
		b.WriteByte(line[i])
	}
	return b.String()
}

// readLines splits text into the lines `read` sees. Blank lines are kept; partial is true when the last
// line has no newline.
func readLines(text string) (lines []string, partial bool) {
	if text == "" {
		return nil, false
	}
	lines = strings.Split(text, "\n")
	if lines[len(lines)-1] == "" {
		return lines[:len(lines)-1], false
	}
	return lines, true
}

// splitFeed finds `producer | while ...` (or until): a loop that is the last stage of a pipeline. It
// returns the producer and the loop's first statement, splitting at the last top-level pipe whose
// right-hand side starts with while or until.
func splitFeed(text string) (feed, loop string, ok bool) {
	var quote byte
	depth, cut := 0, -1
	for i := 0; i < len(text); i++ {
		c := text[i]
		if quote != 0 {
			switch {
			case c == '\\' && quote == '"':
				i++
			case c == quote:
				quote = 0
			}
			continue
		}
		switch {
		case c == '\\':
			i++
		case c == '\'' || c == '"':
			quote = c
		case c == '(':
			depth++
		case c == ')' && depth > 0:
			depth--
		case c == '|' && depth == 0:
			if i+1 < len(text) && text[i+1] == '|' {
				i++
				continue
			}
			if kw, _ := splitKeyword(strings.TrimSpace(text[i+1:])); kw == "while" || kw == "until" {
				cut = i
			}
		}
	}
	if cut < 0 {
		return "", "", false
	}
	return strings.TrimSpace(text[:cut]), strings.TrimSpace(text[cut+1:]), true
}

func (s *Interpreter) expandWord(raw string, depth int, bait *[]BaitHit, action string) string {
	words := tokenizeWords(raw)
	for i, w := range words {
		words[i] = s.substitute(w, depth, bait, action)
	}
	return strings.Join(words, " ")
}

func (s *Interpreter) runItems(items []item, depth int, bait *[]BaitHit, action string, outputs *[]outChunk) int {
	last := 0
	for i, it := range items {
		if s.loopCtl != "" || s.halted {
			return last
		}
		if i > 0 && ((it.sep == "&&" && last != 0) || (it.sep == "||" && last == 0)) {
			continue
		}
		if it.kind != kindSimple && it.kind != kindSubshell && strings.HasPrefix(it.text, "|") {
			head := it
			head.text, head.sep = "", ""
			var inner []outChunk
			last = s.runItems([]item{head}, depth, bait, action, &inner)
			last = s.pipeInto(inner, it.text, depth, bait, action, outputs, last)
			continue
		}
		switch it.kind {
		case kindSimple:
			s.line = s.lineBase + it.line
			s.blankEcho = false
			s.direct = &items[i] == s.lastTop
			s.pendingErr = nil
			out, code, ran, isErr := s.execStatement(it.text, depth, bait, action)
			if out != "" {
				c := s.chunk(out, isErr)
				c.noNewline = s.noTrailingNewline && !isErr
				*outputs = append(*outputs, c)
			}
			if out == "" && s.blankEcho && ran {
				*outputs = append(*outputs, outChunk{}) // a bare echo prints an empty line
			}
			if len(s.pendingErr) > 0 {
				*outputs = append(*outputs, s.chunk(strings.Join(s.pendingErr, "\r\n"), true))
				s.pendingErr = nil
			}
			if !ran {
				continue
			}
			last = code
			s.lastCode = code
			s.errexitCheck(items, i, code)
		case kindGroup:
			last = s.runItems(it.body, depth, bait, action, outputs)
		case kindIf:
			last = 0
			taken := false
			for j, cond := range it.conds {
				s.errexitOff++
				condCode := s.runItems(cond, depth, bait, action, outputs)
				s.errexitOff--
				if condCode == 0 {
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
			s.loopDepth++
			for n, v := range values {
				if n == maxLoopIterations {
					break
				}
				s.Env[it.word] = v
				last = s.runItems(it.body, depth, bait, action, outputs)
				if s.halted {
					break
				}
				if s.loopCtl == "break" {
					s.loopCtl = ""
					break
				}
				s.loopCtl = ""
			}
			s.loopDepth--
		case kindWhile, kindUntil:
			if it.feed != "" {
				last = s.asSubshell(func() int { return s.runWhile(it, depth, bait, action, outputs) })
			} else {
				last = s.runWhile(it, depth, bait, action, outputs)
			}
		case kindSubshell:
			last = s.runSubshell(it, depth, bait, action, outputs)
			s.lastCode = last
			s.errexitCheck(items, i, last)
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

// pipeInto feeds the stdout of a finished compound command (inner) to the
// rest of its pipeline, written "| cmd | cmd ...". stderr passes through.
func (s *Interpreter) pipeInto(inner []outChunk, tail string, depth int, bait *[]BaitHit, action string, outputs *[]outChunk, code int) int {
	var stdout []outChunk
	for _, c := range inner {
		if c.stderr {
			*outputs = append(*outputs, c)
		} else {
			stdout = append(stdout, c)
		}
	}
	fwd := strings.ReplaceAll(joinChunks(stdout, "\r\n"), "\r\n", "\n")
	if fwd != "" && (len(stdout) == 0 || !stdout[len(stdout)-1].noNewline) {
		fwd += "\n"
	}
	saved := s.pipeStdin
	s.pipeStdin = &fwd
	var chunks []outChunk
	c2 := s.asSubshell(func() int {
		var cc int
		chunks, cc = s.evalChunks(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(tail), "|")), depth, bait, action)
		return cc
	})
	s.pipeStdin = saved
	*outputs = append(*outputs, chunks...)
	return c2
}

// errexitCheck ends the shell if set -e is on and the statement items[i] failed, except where bash
// exempts it: a command followed by && or || (only the last of such a list counts) and anything inside
// an if or while condition.
func (s *Interpreter) errexitCheck(items []item, i, code int) {
	if code == 0 || !s.errexit || s.errexitOff > 0 {
		return
	}
	if i+1 < len(items) && (items[i+1].sep == "&&" || items[i+1].sep == "||") {
		return
	}
	s.halted, s.haltCode = true, code
}

// splitReadFields splits line into n fields the way `read` does with IFS. Whitespace in IFS is dropped at
// the ends and runs of it count as one separator; any other IFS character separates exactly (a,,b has an
// empty middle field). The last field takes the rest of the line. An empty IFS does not split at all.
func splitReadFields(line string, n int, ifs string) []string {
	isSep := func(c byte) bool { return strings.IndexByte(ifs, c) >= 0 }
	isWS := func(c byte) bool { return (c == ' ' || c == '\t' || c == '\n') && isSep(c) }
	fields := make([]string, n)
	i := 0
	for i < len(line) && isWS(line[i]) {
		i++
	}
	for f := 0; f < n; f++ {
		if f == n-1 {
			rest := line[i:]
			for len(rest) > 0 && isWS(rest[len(rest)-1]) {
				rest = rest[:len(rest)-1]
			}
			fields[f] = rest
			break
		}
		j := i
		for j < len(line) && !isSep(line[j]) {
			j++
		}
		fields[f] = line[i:j]
		i = j
		for i < len(line) && isWS(line[i]) {
			i++
		}
		if i < len(line) && isSep(line[i]) && !isWS(line[i]) {
			i++
			for i < len(line) && isWS(line[i]) {
				i++
			}
		}
	}
	return fields
}
