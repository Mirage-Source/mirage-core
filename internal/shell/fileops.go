package shell

import (
	"path"
	"strconv"
	"strings"
	"time"
)

var binDirs = map[string]bool{
	"/bin": true, "/sbin": true, "/usr/bin": true, "/usr/sbin": true,
	"/usr/local/bin": true, "/usr/local/sbin": true,
}

// InBinDir reports whether a path-qualified command names something in a
// standard binary directory, as opposed to a file the session can create.
func InBinDir(name string) bool {
	return binDirs[path.Dir(path.Clean(name))]
}

func stripAssignments(words []string) []string {
	for len(words) > 1 && isAssignmentOnly(words[:1]) {
		words = words[1:]
	}
	return words
}

func splitFlags(args []string) (flags string, operands []string) {
	for _, a := range args {
		if len(a) > 1 && strings.HasPrefix(a, "-") {
			flags += strings.TrimLeft(a, "-")
		} else {
			operands = append(operands, a)
		}
	}
	return flags, operands
}

// runNested evaluates script text (a script file, `sh -c`) one level deeper,
// so a script that runs itself stops at maxSubstitutionDepth.
func (s *Interpreter) runNested(script string, bait *[]BaitHit, action string) (string, int) {
	if s.nesting >= maxSubstitutionDepth {
		return "", 0
	}
	s.nesting++
	defer func() { s.nesting-- }()
	return s.evalLine(script, s.nesting, bait, action)
}

func (s *Interpreter) execPath(cmd string, args []string, bait *[]BaitHit, action string, stdin *string) (string, int) {
	clean, n := s.lookup(cmd)
	if base := path.Base(clean); binDirs[path.Dir(clean)] && base != "" && IsKnownBuiltin(base) {
		return s.execBuiltin(base, args, bait, action, stdin)
	}
	switch {
	case n == nil:
		return "bash: " + cmd + ": No such file or directory", 127
	case n.Type == NodeDir:
		return "bash: " + cmd + ": Is a directory", 126
	case !strings.Contains(n.Mode, "x"):
		return "bash: " + cmd + ": Permission denied", 126
	}
	return s.runNested(s.expandHostname(n.Content), bait, action)
}

// mutable returns the session's own copy of the node at clean, so changes
// never reach the shared base filesystem.
func (s *Interpreter) mutable(clean string, n *Node) *Node {
	if o, ok := s.overlay[clean]; ok && o != nil {
		return o
	}
	cp := *n
	s.overlay[clean] = &cp
	return &cp
}

func (s *Interpreter) addChild(parentPath, base string) {
	_, parent := s.lookup(parentPath)
	if parent != nil {
		for _, c := range parent.Children {
			if c == base {
				return
			}
		}
	}
	if s.overlayChildren == nil {
		s.overlayChildren = map[string][]string{}
	}
	for _, c := range s.overlayChildren[parentPath] {
		if c == base {
			return
		}
	}
	s.overlayChildren[parentPath] = append(s.overlayChildren[parentPath], base)
}

func (s *Interpreter) remove(clean string) {
	s.overlay[clean] = nil
	prefix := clean + "/"
	for p := range s.overlay {
		if strings.HasPrefix(p, prefix) {
			s.overlay[p] = nil
		}
	}
	for p := range fs {
		if strings.HasPrefix(p, prefix) {
			s.overlay[p] = nil
		}
	}
}

func (s *Interpreter) mkdirAt(clean string) {
	s.overlay[clean] = &Node{
		Path: clean, Type: NodeDir, Mode: "drwxr-xr-x", Owner: s.Username, Group: s.Username,
		MTime: time.Now().UTC().Format("Jan _2 15:04"),
	}
	s.addChild(path.Dir(clean), path.Base(clean))
}

func joinLines(lines []string) string {
	return strings.Join(lines, "\r\n")
}

func (s *Interpreter) chmodBuiltin(args []string) (string, int) {
	var mode string
	var files []string
	for _, a := range args {
		switch {
		case a == "-R" || a == "-f" || a == "-v" || a == "-c" || a == "--recursive":
		case mode == "":
			mode = a
		default:
			files = append(files, a)
		}
	}
	if mode == "" {
		return "chmod: missing operand", 1
	}
	if len(files) == 0 {
		return "chmod: missing operand after '" + mode + "'", 1
	}
	var errs []string
	for _, f := range files {
		clean, n := s.lookup(f)
		if n == nil {
			errs = append(errs, "chmod: cannot access '"+f+"': No such file or directory")
			continue
		}
		m := s.mutable(clean, n)
		m.Mode = applyMode(m.Mode, mode)
	}
	if len(errs) > 0 {
		return joinLines(errs), 1
	}
	return "", 0
}

func applyMode(current, spec string) string {
	bits := []byte(current)
	if len(bits) != 10 {
		return current
	}
	if n, err := strconv.ParseUint(spec, 8, 32); err == nil {
		for i := 0; i < 9; i++ {
			bits[1+i] = '-'
			if n&(1<<(8-i)) != 0 {
				bits[1+i] = "rwx"[i%3]
			}
		}
		return string(bits)
	}
	for _, clause := range strings.Split(spec, ",") {
		i := strings.IndexAny(clause, "+-=")
		if i < 0 {
			continue
		}
		who, op, perms := clause[:i], clause[i], clause[i+1:]
		if who == "" || strings.Contains(who, "a") {
			who = "ugo"
		}
		for _, w := range who {
			off := map[rune]int{'u': 1, 'g': 4, 'o': 7}[w]
			if off == 0 {
				continue
			}
			for j, p := range "rwx" {
				switch {
				case op == '=':
					bits[off+j] = '-'
					if strings.ContainsRune(perms, p) {
						bits[off+j] = byte(p)
					}
				case strings.ContainsRune(perms, p) && op == '+':
					bits[off+j] = byte(p)
				case strings.ContainsRune(perms, p) && op == '-':
					bits[off+j] = '-'
				}
			}
		}
	}
	return string(bits)
}

func (s *Interpreter) chownBuiltin(cmd string, args []string) (string, int) {
	_, ops := splitFlags(args)
	if len(ops) == 0 {
		return cmd + ": missing operand", 1
	}
	if len(ops) == 1 {
		return cmd + ": missing operand after '" + ops[0] + "'", 1
	}
	var errs []string
	for _, f := range ops[1:] {
		if _, n := s.lookup(f); n == nil {
			errs = append(errs, cmd+": cannot access '"+f+"': No such file or directory")
		}
	}
	if len(errs) > 0 {
		return joinLines(errs), 1
	}
	return "", 0
}

func (s *Interpreter) rmBuiltin(args []string) (string, int) {
	flags, ops := splitFlags(args)
	force := strings.Contains(flags, "f")
	recursive := strings.ContainsAny(flags, "rR")
	if len(ops) == 0 {
		if force {
			return "", 0
		}
		return "rm: missing operand", 1
	}
	var errs []string
	for _, f := range ops {
		clean, n := s.lookup(f)
		switch {
		case n == nil:
			if !force {
				errs = append(errs, "rm: cannot remove '"+f+"': No such file or directory")
			}
		case n.Type == NodeDir && !recursive:
			errs = append(errs, "rm: cannot remove '"+f+"': Is a directory")
		default:
			s.remove(clean)
		}
	}
	if len(errs) > 0 {
		return joinLines(errs), 1
	}
	return "", 0
}

func (s *Interpreter) mkdirBuiltin(args []string) (string, int) {
	flags, ops := splitFlags(args)
	parents := strings.Contains(flags, "p")
	if len(ops) == 0 {
		return "mkdir: missing operand", 1
	}
	var errs []string
	for _, d := range ops {
		clean, n := s.lookup(d)
		if n != nil {
			if !parents || n.Type != NodeDir {
				errs = append(errs, "mkdir: cannot create directory '"+d+"': File exists")
			}
			continue
		}
		var missing []string
		for p := clean; ; p = path.Dir(p) {
			if _, pn := s.lookup(p); pn != nil {
				if pn.Type != NodeDir {
					missing = nil
				}
				break
			}
			missing = append([]string{p}, missing...)
		}
		if len(missing) == 0 || (len(missing) > 1 && !parents) {
			errs = append(errs, "mkdir: cannot create directory '"+d+"': No such file or directory")
			continue
		}
		for _, p := range missing {
			s.mkdirAt(p)
		}
	}
	if len(errs) > 0 {
		return joinLines(errs), 1
	}
	return "", 0
}

func (s *Interpreter) touchBuiltin(args []string) (string, int) {
	_, ops := splitFlags(args)
	if len(ops) == 0 {
		return "touch: missing file operand", 1
	}
	var errs []string
	for _, f := range ops {
		if _, n := s.lookup(f); n != nil {
			continue
		}
		if _, code := s.writeFile(f, "", false); code != 0 {
			errs = append(errs, "touch: cannot touch '"+f+"': No such file or directory")
		}
	}
	if len(errs) > 0 {
		return joinLines(errs), 1
	}
	return "", 0
}

func (s *Interpreter) cpBuiltin(cmd string, args []string) (string, int) {
	flags, ops := splitFlags(args)
	if len(ops) == 0 {
		return cmd + ": missing file operand", 1
	}
	if len(ops) == 1 {
		return cmd + ": missing destination file operand after '" + ops[0] + "'", 1
	}
	src, dst := ops[0], ops[1]
	srcClean, n := s.lookup(src)
	if n == nil {
		return cmd + ": cannot stat '" + src + "': No such file or directory", 1
	}
	if n.Type == NodeDir {
		if cmd == "cp" && !strings.ContainsAny(flags, "rRa") {
			return "cp: -r not specified; omitting directory '" + src + "'", 1
		}
		return "", 0
	}
	if _, dn := s.lookup(dst); dn != nil && dn.Type == NodeDir {
		dst = path.Join(dst, path.Base(srcClean))
	}
	if _, code := s.writeFile(dst, n.Content, false); code != 0 {
		return cmd + ": cannot create regular file '" + dst + "': No such file or directory", 1
	}
	dstClean, dn := s.lookup(dst)
	s.mutable(dstClean, dn).Mode = n.Mode
	if cmd == "mv" {
		s.remove(srcClean)
	}
	return "", 0
}
