package shell

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Text filters real hosts have and recon one-liners pipe into: tr, cut, sort
// and sed (the common subset). Behaviour and error text follow GNU coreutils
// 8.32 and sed 4.8 (Ubuntu 22.04); expected values in textutils_test.go were
// measured against GNU tools, not guessed.

// textOut joins lines for display. If the text ends with a newline that
// newline is dropped, because the display path adds it; otherwise the
// interpreter is told the output has none, as `printf a | tr a b` has none.
func (s *Interpreter) textOut(text string) (string, int) {
	if text == "" {
		return "", 0
	}
	if strings.HasSuffix(text, "\n") {
		text = strings.TrimSuffix(text, "\n")
	} else {
		s.noTrailingNewline = true
	}
	return strings.ReplaceAll(text, "\n", "\r\n"), 0
}

func norm(text string) string { return strings.ReplaceAll(text, "\r\n", "\n") }

// ---------------------------------------------------------------- tr

func trExpand(set string) []rune {
	in := []rune(set)
	var out []rune
	for i := 0; i < len(in); i++ {
		c := in[i]
		if c == '[' && i+1 < len(in) && in[i+1] == ':' {
			if end := strings.Index(string(in[i:]), ":]"); end > 0 {
				name := string(in[i+2 : i+end])
				if cls := trClass(name); cls != nil {
					out = append(out, cls...)
					i += len([]rune(string(in[i:])[:end+2])) - 1
					continue
				}
			}
		}
		if c == '\\' && i+1 < len(in) {
			i++
			switch in[i] {
			case 'n':
				c = '\n'
			case 't':
				c = '\t'
			case 'r':
				c = '\r'
			case 'a':
				c = 7
			case 'b':
				c = 8
			case 'f':
				c = 12
			case 'v':
				c = 11
			case '\\':
				c = '\\'
			default:
				if in[i] >= '0' && in[i] <= '7' {
					v, n := 0, 0
					for n < 3 && i < len(in) && in[i] >= '0' && in[i] <= '7' {
						v = v*8 + int(in[i]-'0')
						i++
						n++
					}
					i--
					c = rune(v)
				} else {
					c = in[i]
				}
			}
		}
		if i+2 < len(in) && in[i+1] == '-' {
			hi := in[i+2]
			if hi == '\\' && i+3 < len(in) {
				hi = in[i+3]
				i++
			}
			for r := c; r <= hi; r++ {
				out = append(out, r)
			}
			i += 2
			continue
		}
		out = append(out, c)
	}
	return out
}

func trClass(name string) []rune {
	var out []rune
	add := func(lo, hi rune) {
		for r := lo; r <= hi; r++ {
			out = append(out, r)
		}
	}
	switch name {
	case "lower":
		add('a', 'z')
	case "upper":
		add('A', 'Z')
	case "digit":
		add('0', '9')
	case "alpha":
		add('A', 'Z')
		add('a', 'z')
	case "alnum":
		add('0', '9')
		add('A', 'Z')
		add('a', 'z')
	case "space":
		out = []rune{'\t', '\n', 11, 12, '\r', ' '}
	case "blank":
		out = []rune{'\t', ' '}
	case "punct":
		add('!', '/')
		add(':', '@')
		add('[', '`')
		add('{', '~')
	default:
		return nil
	}
	return out
}

func (s *Interpreter) trBuiltin(args []string, stdin *string) (string, int) {
	var del, squeeze, comp bool
	var sets []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			sets = append(sets, args[i+1:]...)
			break
		}
		if len(a) > 1 && a[0] == '-' && !(len(a) == 2 && a[1] == '-') {
			for _, f := range a[1:] {
				switch f {
				case 'd':
					del = true
				case 's':
					squeeze = true
				case 'c', 'C':
					comp = true
				default:
					return fmt.Sprintf("tr: invalid option -- '%c'\r\nTry 'tr --help' for more information.", f), 1
				}
			}
			continue
		}
		sets = append(sets, a)
	}
	switch {
	case len(sets) == 0:
		return "tr: missing operand\r\nTry 'tr --help' for more information.", 1
	case !del && !squeeze && len(sets) == 1:
		return fmt.Sprintf("tr: missing operand after %s\r\nTwo strings must be given when translating.", shellQuote(sets[0])), 1
	case len(sets) > 2 || (del && !squeeze && len(sets) == 2):
		return fmt.Sprintf("tr: extra operand %s\r\nTry 'tr --help' for more information.", shellQuote(sets[len(sets)-1])), 1
	}
	set1 := trExpand(sets[0])
	var set2 []rune
	if len(sets) == 2 {
		set2 = trExpand(sets[1])
	}
	in1 := map[rune]int{}
	for i, r := range set1 {
		if _, ok := in1[r]; !ok {
			in1[r] = i
		}
	}
	inSet1 := func(r rune) bool { _, ok := in1[r]; return ok != comp }

	text := ""
	if stdin != nil {
		text = norm(*stdin)
	}
	var out []rune
	var last rune = -1
	squeezeSet := set1
	if len(set2) > 0 {
		squeezeSet = set2
	}
	sq := map[rune]bool{}
	for _, r := range squeezeSet {
		sq[r] = true
	}
	if comp && squeeze && len(set2) == 0 {
		sq = nil
	}
	for _, r := range text {
		switch {
		case del && inSet1(r):
			continue
		case !del && len(set2) > 0 && inSet1(r):
			if comp {
				r = set2[len(set2)-1]
			} else if i := in1[r]; i < len(set2) {
				r = set2[i]
			} else {
				r = set2[len(set2)-1]
			}
		}
		if squeeze {
			inSq := sq[r]
			if sq == nil {
				inSq = inSet1(r)
			}
			if inSq && r == last {
				continue
			}
		}
		out = append(out, r)
		last = r
	}
	return s.textOut(string(out))
}

func shellQuote(s string) string { return "'" + s + "'" }

// ---------------------------------------------------------------- cut

type cutRange struct{ lo, hi int } // 1-based, hi==0 means open-ended

func parseCutList(list string) ([]cutRange, bool) {
	var rs []cutRange
	for _, part := range strings.Split(list, ",") {
		if part == "" {
			return nil, false
		}
		lo, hi, isRange := strings.Cut(part, "-")
		var r cutRange
		var err error
		if !isRange {
			if r.lo, err = strconv.Atoi(lo); err != nil || r.lo < 1 {
				return nil, false
			}
			r.hi = r.lo
		} else {
			if lo != "" {
				if r.lo, err = strconv.Atoi(lo); err != nil || r.lo < 1 {
					return nil, false
				}
			} else {
				r.lo = 1
			}
			if hi != "" {
				if r.hi, err = strconv.Atoi(hi); err != nil || r.hi < r.lo {
					return nil, false
				}
			}
		}
		rs = append(rs, r)
	}
	return rs, len(rs) > 0
}

func inCut(rs []cutRange, i int) bool {
	for _, r := range rs {
		if i >= r.lo && (r.hi == 0 || i <= r.hi) {
			return true
		}
	}
	return false
}

func (s *Interpreter) cutBuiltin(args []string, stdin *string) (string, int) {
	delim := "\t"
	var fields, chars string
	onlyDelimited := false
	var files []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		val := func(short string) (string, bool) {
			if a == short && i+1 < len(args) {
				i++
				return args[i], true
			}
			if strings.HasPrefix(a, short) && len(a) > len(short) {
				return a[len(short):], true
			}
			return "", false
		}
		switch {
		case a == "-s":
			onlyDelimited = true
		case strings.HasPrefix(a, "-d"):
			v, _ := val("-d")
			delim = v
		case strings.HasPrefix(a, "-f"):
			fields, _ = val("-f")
		case strings.HasPrefix(a, "-c"):
			chars, _ = val("-c")
		case strings.HasPrefix(a, "-b"):
			chars, _ = val("-b")
		case a == "-":
			files = append(files, a)
		case strings.HasPrefix(a, "-"):
			return fmt.Sprintf("cut: invalid option -- '%s'\r\nTry 'cut --help' for more information.", strings.TrimLeft(a, "-")), 1
		default:
			files = append(files, a)
		}
	}
	if fields == "" && chars == "" {
		return "cut: you must specify a list of bytes, characters, or fields\r\nTry 'cut --help' for more information.", 1
	}
	if len([]rune(delim)) != 1 {
		return "cut: the delimiter must be a single character\r\nTry 'cut --help' for more information.", 1
	}
	list := fields
	if chars != "" {
		list = chars
	}
	rs, ok := parseCutList(list)
	if !ok {
		return "cut: invalid field range\r\nTry 'cut --help' for more information.", 1
	}
	fileArg := ""
	if len(files) > 0 && files[0] != "-" {
		fileArg = files[0]
	}
	text, ok := s.builtinInput(fileArg, stdin)
	if !ok {
		return "cut: " + fileArg + ": No such file or directory", 1
	}
	var outLines []string
	for _, line := range splitLines(norm(text)) {
		switch {
		case chars != "":
			var b []rune
			for i, r := range []rune(line) {
				if inCut(rs, i+1) {
					b = append(b, r)
				}
			}
			outLines = append(outLines, string(b))
		default:
			if !strings.Contains(line, delim) {
				if !onlyDelimited {
					outLines = append(outLines, line)
				}
				continue
			}
			var keep []string
			for i, f := range strings.Split(line, delim) {
				if inCut(rs, i+1) {
					keep = append(keep, f)
				}
			}
			outLines = append(outLines, strings.Join(keep, delim))
		}
	}
	return s.textOut(strings.Join(outLines, "\n") + "\n")
}

// ---------------------------------------------------------------- sort

func (s *Interpreter) sortBuiltin(args []string, stdin *string) (string, int) {
	var rev, num, uniq, fold, stable bool
	sep := ""
	keyField, keyEnd := 0, 0
	var files []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-t" && i+1 < len(args):
			i++
			sep = args[i]
		case strings.HasPrefix(a, "-t") && len(a) > 2:
			sep = a[2:]
		case a == "-k" && i+1 < len(args):
			i++
			keyField, keyEnd = parseSortKey(args[i], &num, &rev)
		case strings.HasPrefix(a, "-k") && len(a) > 2:
			keyField, keyEnd = parseSortKey(a[2:], &num, &rev)
		case len(a) > 1 && a[0] == '-' && a[1] != '-':
			for _, f := range a[1:] {
				switch f {
				case 'r':
					rev = true
				case 'n':
					num = true
				case 'u':
					uniq = true
				case 'f':
					fold = true
				case 's':
					stable = true
				case 'b', 'h', 'V', 'g', 'M':
				default:
					return fmt.Sprintf("sort: invalid option -- '%c'\r\nTry 'sort --help' for more information.", f), 2
				}
			}
		case a == "--":
		case strings.HasPrefix(a, "--"):
		default:
			files = append(files, a)
		}
	}
	fileArg := ""
	if len(files) > 0 {
		fileArg = files[0]
	}
	text, ok := s.builtinInput(fileArg, stdin)
	if !ok {
		return "sort: cannot read: " + fileArg + ": No such file or directory", 2
	}
	lines := splitLines(norm(text))
	key := func(line string) string {
		if keyField == 0 {
			return line
		}
		var fs []string
		if sep == "" {
			fs = strings.Fields(line)
		} else {
			fs = strings.Split(line, sep)
		}
		if keyField > len(fs) {
			return ""
		}
		end := keyField
		if keyEnd > 0 {
			end = keyEnd
		}
		if end > len(fs) {
			end = len(fs)
		}
		j := " "
		if sep != "" {
			j = sep
		}
		return strings.Join(fs[keyField-1:end], j)
	}
	cmp := func(a, b string) int {
		ka, kb := key(a), key(b)
		if num {
			fa, fb := sortLeadingNumber(ka), sortLeadingNumber(kb)
			switch {
			case fa < fb:
				return -1
			case fa > fb:
				return 1
			}
		} else {
			if fold {
				ka, kb = strings.ToLower(ka), strings.ToLower(kb)
			}
			if c := strings.Compare(ka, kb); c != 0 {
				return c
			}
		}
		return 0
	}
	sort.SliceStable(lines, func(i, j int) bool {
		c := cmp(lines[i], lines[j])
		if c == 0 && !stable && !uniq {
			c = strings.Compare(lines[i], lines[j]) // last-resort whole-line comparison
		}
		if rev {
			return c > 0
		}
		return c < 0
	})
	if uniq {
		var kept []string
		for _, l := range lines {
			if len(kept) == 0 || cmp(kept[len(kept)-1], l) != 0 {
				kept = append(kept, l)
			}
		}
		lines = kept
	}
	if len(lines) == 0 {
		return "", 0
	}
	return s.textOut(strings.Join(lines, "\n") + "\n")
}

func parseSortKey(k string, num, rev *bool) (int, int) {
	for len(k) > 0 {
		switch k[len(k)-1] {
		case 'n':
			*num = true
		case 'r':
			*rev = true
		default:
			goto done
		}
		k = k[:len(k)-1]
	}
done:
	start, end, _ := strings.Cut(k, ",")
	a, _ := strconv.Atoi(strings.SplitN(start, ".", 2)[0])
	b, _ := strconv.Atoi(strings.SplitN(end, ".", 2)[0])
	return a, b
}

func sortLeadingNumber(s string) float64 {
	s = strings.TrimLeft(s, " \t")
	end := 0
	for end < len(s) && (s[end] == '-' || s[end] == '+' || s[end] == '.' || (s[end] >= '0' && s[end] <= '9')) {
		end++
	}
	for end > 0 {
		if f, err := strconv.ParseFloat(s[:end], 64); err == nil {
			return f
		}
		end--
	}
	return 0
}

// ---------------------------------------------------------------- sed

type sedCmd struct {
	addr1, addr2 sedAddr
	negate       bool
	op           byte
	re           *regexp.Regexp
	repl         string
	global, pr   bool
	nth          int
	y            map[rune]rune
}

type sedAddr struct {
	kind byte // 0 none, 'n' line, '$' last, '/' regex
	n    int
	re   *regexp.Regexp
}

// breToRE2 converts a POSIX basic regular expression (GNU flavour) to RE2.
func breToRE2(bre string, ere bool) string {
	var b strings.Builder
	in := []rune(bre)
	start := true
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch {
		case c == '[':
			j := i + 1
			if j < len(in) && in[j] == '^' {
				j++
			}
			if j < len(in) && in[j] == ']' {
				j++
			}
			for j < len(in) && in[j] != ']' {
				if in[j] == '[' && j+1 < len(in) && (in[j+1] == ':' || in[j+1] == '.' || in[j+1] == '=') {
					if k := strings.Index(string(in[j+2:]), string(in[j+1])+"]"); k >= 0 {
						j += 2 + len([]rune(string(in[j+2:])[:k])) + 1
					}
				}
				j++
			}
			if j >= len(in) {
				b.WriteString(`\[`)
			} else {
				b.WriteString(string(in[i : j+1]))
				i = j
			}
			start = false
			continue
		case c == '\\' && i+1 < len(in):
			i++
			n := in[i]
			switch {
			case !ere && (n == '(' || n == ')' || n == '{' || n == '}' || n == '+' || n == '?' || n == '|'):
				b.WriteRune(n)
				start = n == '(' || n == '|'
				continue
			case n == '<' || n == '>':
				b.WriteString(`\b`)
			case n == 'n':
				b.WriteString(`\n`)
			case n == 't':
				b.WriteString(`\t`)
			default:
				b.WriteRune('\\')
				b.WriteRune(n)
			}
		case !ere && (c == '(' || c == ')' || c == '{' || c == '}' || c == '+' || c == '?' || c == '|'):
			b.WriteRune('\\')
			b.WriteRune(c)
		case c == '*' && start:
			b.WriteString(`\*`)
		case c == '^' && !start && !ere:
			b.WriteString(`\^`)
		default:
			b.WriteRune(c)
		}
		start = false
	}
	return b.String()
}

func sedReadDelim(script string, i int, delim byte) (string, int, bool) {
	var b strings.Builder
	for ; i < len(script); i++ {
		c := script[i]
		if c == '\\' && i+1 < len(script) {
			if script[i+1] == delim && delim != '\\' {
				b.WriteByte(delim)
			} else {
				b.WriteByte(c)
				b.WriteByte(script[i+1])
			}
			i++
			continue
		}
		if c == delim {
			return b.String(), i + 1, true
		}
		b.WriteByte(c)
	}
	return "", i, false
}

func parseSed(script string, ere bool) ([]sedCmd, string) {
	var cmds []sedCmd
	i := 0
	skip := func() {
		for i < len(script) && (script[i] == ' ' || script[i] == '\t' || script[i] == ';' || script[i] == '\n') {
			i++
		}
	}
	parseAddr := func() (sedAddr, string) {
		switch {
		case i < len(script) && script[i] >= '0' && script[i] <= '9':
			j := i
			for j < len(script) && script[j] >= '0' && script[j] <= '9' {
				j++
			}
			n, _ := strconv.Atoi(script[i:j])
			i = j
			return sedAddr{kind: 'n', n: n}, ""
		case i < len(script) && script[i] == '$':
			i++
			return sedAddr{kind: '$'}, ""
		case i < len(script) && script[i] == '/':
			pat, next, ok := sedReadDelim(script, i+1, '/')
			if !ok {
				return sedAddr{}, "unterminated address regex"
			}
			re, err := regexp.Compile(breToRE2(pat, ere))
			if err != nil {
				return sedAddr{}, "invalid regex"
			}
			i = next
			return sedAddr{kind: '/', re: re}, ""
		}
		return sedAddr{}, ""
	}
	for {
		skip()
		if i >= len(script) {
			return cmds, ""
		}
		var c sedCmd
		var msg string
		if c.addr1, msg = parseAddr(); msg != "" {
			return nil, msg
		}
		if c.addr1.kind != 0 && i < len(script) && script[i] == ',' {
			i++
			if c.addr2, msg = parseAddr(); msg != "" {
				return nil, msg
			}
		}
		for i < len(script) && script[i] == ' ' {
			i++
		}
		if i < len(script) && script[i] == '!' {
			c.negate = true
			i++
		}
		if i >= len(script) {
			return nil, "missing command"
		}
		c.op = script[i]
		i++
		switch c.op {
		case 's', 'y':
			if i >= len(script) {
				return nil, "unterminated `" + string(c.op) + "' command"
			}
			delim := script[i]
			pat, next, ok := sedReadDelim(script, i+1, delim)
			if !ok {
				return nil, "unterminated `" + string(c.op) + "' command"
			}
			repl, next2, ok := sedReadDelim(script, next, delim)
			if !ok {
				return nil, "unterminated `" + string(c.op) + "' command"
			}
			i = next2
			if c.op == 'y' {
				from, to := []rune(pat), []rune(repl)
				if len(from) != len(to) {
					return nil, "strings for `y' command are different lengths"
				}
				c.y = map[rune]rune{}
				for k := range from {
					c.y[from[k]] = to[k]
				}
				break
			}
			flags := ""
			for i < len(script) && !strings.ContainsRune(";\n} ", rune(script[i])) {
				flags += string(script[i])
				i++
			}
			icase := false
			for _, f := range flags {
				switch {
				case f == 'g':
					c.global = true
				case f == 'p':
					c.pr = true
				case f == 'i' || f == 'I':
					icase = true
				case f >= '0' && f <= '9':
					c.nth = c.nth*10 + int(f-'0')
				default:
					return nil, "unknown option to `s'"
				}
			}
			src := breToRE2(pat, ere)
			if icase {
				src = "(?i)" + src
			}
			re, err := regexp.Compile(src)
			if err != nil {
				return nil, "Invalid preceding regular expression"
			}
			c.re, c.repl = re, repl
		case 'd', 'p', 'q', 'P', 'n', 'N':
		default:
			return nil, "unknown command: `" + string(c.op) + "'"
		}
		cmds = append(cmds, c)
	}
}

func sedExpand(c sedCmd, line string, m []int) string {
	var b strings.Builder
	r := c.repl
	for i := 0; i < len(r); i++ {
		switch {
		case r[i] == '&':
			b.WriteString(line[m[0]:m[1]])
		case r[i] == '\\' && i+1 < len(r):
			i++
			switch {
			case r[i] >= '0' && r[i] <= '9':
				g := int(r[i] - '0')
				if 2*g+1 < len(m) && m[2*g] >= 0 {
					b.WriteString(line[m[2*g]:m[2*g+1]])
				}
			case r[i] == 'n':
				b.WriteByte('\n')
			case r[i] == 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(r[i])
			}
		default:
			b.WriteByte(r[i])
		}
	}
	return b.String()
}

func (s *Interpreter) sedBuiltin(args []string, stdin *string) (string, int) {
	quiet, ere, inplace := false, false, false
	var scripts, files []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-n" || a == "--quiet" || a == "--silent":
			quiet = true
		case a == "-E" || a == "-r" || a == "--regexp-extended":
			ere = true
		case a == "-i" || strings.HasPrefix(a, "-i") && len(a) > 2 && !strings.HasPrefix(a, "-in") || a == "--in-place":
			inplace = true
		case a == "-e" && i+1 < len(args):
			i++
			scripts = append(scripts, args[i])
		case strings.HasPrefix(a, "-e") && len(a) > 2:
			scripts = append(scripts, a[2:])
		case a == "-s" || a == "--":
		case len(a) > 1 && a[0] == '-' && !strings.HasPrefix(a, "--"):
			for _, f := range a[1:] {
				switch f {
				case 'n':
					quiet = true
				case 'E', 'r':
					ere = true
				case 'i':
					inplace = true
				default:
					return fmt.Sprintf("sed: invalid option -- '%c'\r\nUsage: sed [OPTION]... {script-only-if-no-other-script} [input-file]...", f), 1
				}
			}
		default:
			if len(scripts) == 0 && !strings.HasPrefix(a, "-") && !containsScript(scripts) {
				scripts = append(scripts, a)
			} else {
				files = append(files, a)
			}
		}
	}
	if len(scripts) == 0 {
		return "Usage: sed [OPTION]... {script-only-if-no-other-script} [input-file]...", 1
	}
	cmds, msg := parseSed(strings.Join(scripts, "\n"), ere)
	if msg != "" {
		return "sed: -e expression #1, char " + strconv.Itoa(len(strings.Join(scripts, "\n"))) + ": " + msg, 1
	}
	run := func(text string) string {
		lines := splitLines(norm(text))
		var out strings.Builder
		active := make([]bool, len(cmds)) // range state
		for idx, line := range lines {
			lineNo, last := idx+1, idx == len(lines)-1
			deleted, quit := false, false
			for ci := range cmds {
				c := &cmds[ci]
				match := func(a sedAddr) bool {
					switch a.kind {
					case 'n':
						return lineNo == a.n
					case '$':
						return last
					case '/':
						return a.re.MatchString(line)
					}
					return true
				}
				sel := true
				switch {
				case c.addr1.kind == 0:
				case c.addr2.kind == 0:
					sel = match(c.addr1)
				default:
					if active[ci] {
						sel = true
						if match(c.addr2) || (c.addr2.kind == 'n' && lineNo >= c.addr2.n) {
							active[ci] = false
						}
					} else if match(c.addr1) {
						sel = true
						if !(c.addr2.kind == 'n' && lineNo >= c.addr2.n) && !(c.addr2.kind == '$' && last) {
							active[ci] = true
						}
					} else {
						sel = false
					}
				}
				if sel == c.negate {
					continue
				}
				switch c.op {
				case 'd':
					deleted = true
				case 'p', 'P':
					out.WriteString(line + "\n")
				case 'q':
					quit = true
				case 'y':
					rs := []rune(line)
					for k, r := range rs {
						if t, ok := c.y[r]; ok {
							rs[k] = t
						}
					}
					line = string(rs)
				case 's':
					line = sedSubst(*c, line)
					if c.pr {
						out.WriteString(line + "\n")
					}
				}
				if deleted || quit {
					break
				}
			}
			if !deleted && !quiet {
				out.WriteString(line + "\n")
			}
			if quit {
				break
			}
		}
		return out.String()
	}
	if inplace {
		for _, f := range files {
			text, ok := s.builtinInput(f, nil)
			if !ok {
				return "sed: can't read " + f + ": No such file or directory", 2
			}
			s.writeFile(f, run(text), false)
		}
		return "", 0
	}
	if len(files) == 0 {
		in := ""
		if stdin != nil {
			in = *stdin
		}
		return s.textOut(run(in))
	}
	var all strings.Builder
	for _, f := range files {
		text, ok := s.builtinInput(f, nil)
		if !ok {
			return "sed: can't read " + f + ": No such file or directory", 2
		}
		all.WriteString(run(text))
	}
	return s.textOut(all.String())
}

func containsScript(scripts []string) bool { return len(scripts) > 0 }

func sedSubst(c sedCmd, line string) string {
	var b strings.Builder
	pos, count := 0, 0
	for pos <= len(line) {
		m := c.re.FindStringSubmatchIndex(line[pos:])
		if m == nil {
			break
		}
		for k := range m {
			if m[k] >= 0 {
				m[k] += pos
			}
		}
		count++
		b.WriteString(line[pos:m[0]])
		if c.nth == 0 || count == c.nth {
			b.WriteString(sedExpand(c, line, m))
			if !c.global && c.nth == 0 || (c.nth > 0 && !c.global) {
				b.WriteString(line[m[1]:])
				return b.String()
			}
		} else {
			b.WriteString(line[m[0]:m[1]])
		}
		if m[1] == m[0] {
			if m[0] < len(line) {
				b.WriteByte(line[m[0]])
			}
			pos = m[1] + 1
		} else {
			pos = m[1]
		}
	}
	if pos <= len(line) {
		b.WriteString(line[pos:])
	}
	return b.String()
}
