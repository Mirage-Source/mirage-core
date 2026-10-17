package shell

import (
	"errors"
	iofs "io/fs"
	"path"
	"strings"
	"time"
)

// This file is the simulated filesystem as seen by a file-transfer protocol
// (the sftp subsystem) rather than by a command line. It reads and writes
// the same per-session overlay as the shell builtins, so sftp's view of a
// directory and `ls` on it can never disagree.

// ErrReadOnly is returned for writes the profile's filesystem refuses.
var ErrReadOnly = errors.New("read-only file system")

// FileInfo describes one node. Mode and MTime are in ls's own format
// ("-rw-r--r--", "Jan 12 09:11" or "Feb  7  2022").
type FileInfo struct {
	Name  string
	Dir   bool
	Mode  string
	Owner string
	Group string
	Size  int64
	MTime string
}

func (s *Interpreter) infoOf(name string, n *Node) FileInfo {
	return FileInfo{Name: name, Dir: n.Type == NodeDir, Mode: n.Mode, Owner: n.Owner, Group: n.Group, Size: s.sizeOf(n), MTime: n.MTime}
}

// visible looks up p and hides bait that is only surfaced by the deception
// policy, the same way an unprompted `cat` of it fails.
func (s *Interpreter) visible(p string) (string, *Node) {
	clean, n := s.lookup(p)
	if n != nil && n.Bait != nil && n.Bait.Hidden {
		return clean, nil
	}
	return clean, n
}

// Abs resolves p against the working directory and ~ to a clean absolute path.
func (s *Interpreter) Abs(p string) string { return s.resolvePath(p) }

// Stat follows the same rules as ls: no symlinks exist, so it is also lstat.
func (s *Interpreter) Stat(p string) (FileInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	clean, n := s.visible(p)
	if n == nil {
		return FileInfo{}, iofs.ErrNotExist
	}
	return s.infoOf(path.Base(clean), n), nil
}

// ReadDir lists a directory in ls -a order: ".", "..", then entries.
func (s *Interpreter) ReadDir(p string) ([]FileInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readDir(p)
}

func (s *Interpreter) readDir(p string) ([]FileInfo, error) {
	clean, n := s.visible(p)
	if n == nil {
		return nil, iofs.ErrNotExist
	}
	if n.Type != NodeDir {
		return nil, iofs.ErrInvalid
	}
	parent := n
	if clean != "/" {
		if _, pn := s.lookup(path.Dir(clean)); pn != nil {
			parent = pn
		}
	}
	out := []FileInfo{s.infoOf(".", n), s.infoOf("..", parent)}
	names := append(append([]string{}, n.Children...), s.overlayChildren[clean]...)
	for _, name := range names {
		if _, child := s.visible(path.Join(clean, name)); child != nil {
			out = append(out, s.infoOf(name, child))
		}
	}
	return out, nil
}

// ReadFile returns a file's content. A fake binary is padded with zeros to
// its listed size, so it downloads at the size ls and stat report. Text is
// served as written: many text nodes list their real Ubuntu size but carry
// shortened content, and NUL padding in a text file is a worse tell than
// the size mismatch.
func (s *Interpreter) ReadFile(p string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, n := s.visible(p)
	if n == nil {
		return "", iofs.ErrNotExist
	}
	if n.Type == NodeDir {
		return "", iofs.ErrInvalid
	}
	content := s.content(n)
	if pad := s.sizeOf(n) - int64(len(content)); pad > 0 && strings.HasPrefix(content, elfHeader[:4]) {
		content += strings.Repeat("\x00", int(pad))
	}
	return content, nil
}

// checkCreate reports why a new entry at clean cannot be made, or nil.
func (s *Interpreter) checkCreate(clean string) error {
	if _, parent := s.visible(path.Dir(clean)); parent == nil || parent.Type != NodeDir {
		return iofs.ErrNotExist
	}
	if s.readOnly(clean) {
		return ErrReadOnly
	}
	return nil
}

// CreateFile makes p an empty file owned by the session user, or truncates
// it when truncate is set. Existing files are otherwise left as they are.
func (s *Interpreter) CreateFile(p string, truncate bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clean, n := s.visible(p)
	if n != nil {
		if n.Type == NodeDir {
			return iofs.ErrInvalid
		}
		if s.readOnly(clean) {
			return ErrReadOnly
		}
		if truncate {
			m := s.mutable(clean, n)
			m.Content, m.Size = "", 0
		}
		return nil
	}
	if err := s.checkCreate(clean); err != nil {
		return err
	}
	s.overlay[clean] = &Node{
		Path: clean, Type: NodeFile, Mode: "-rw-r--r--", Owner: s.Username, Group: s.Username,
		MTime: time.Now().UTC().Format("Jan _2 15:04"),
	}
	s.addChild(path.Dir(clean), path.Base(clean))
	return nil
}

// SetSize records how big an uploaded file is. Its content is never kept.
func (s *Interpreter) SetSize(p string, size int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	clean, n := s.visible(p)
	if n == nil || n.Type == NodeDir {
		return
	}
	m := s.mutable(clean, n)
	m.Content, m.Size = "", size
}

func (s *Interpreter) Mkdir(p string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clean, n := s.visible(p)
	if n != nil {
		return iofs.ErrExist
	}
	if err := s.checkCreate(clean); err != nil {
		return err
	}
	s.mkdirAt(clean)
	return nil
}

// Remove deletes a file (dir false) or an empty directory (dir true).
func (s *Interpreter) Remove(p string, dir bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clean, n := s.visible(p)
	switch {
	case n == nil:
		return iofs.ErrNotExist
	case clean == "/" || s.readOnly(clean):
		return ErrReadOnly
	case dir && n.Type != NodeDir, !dir && n.Type == NodeDir:
		return iofs.ErrInvalid
	case dir:
		if entries, _ := s.readDir(clean); len(entries) > 2 {
			return iofs.ErrExist
		}
	}
	s.remove(clean)
	return nil
}

// Rename moves a file or directory. Like posix rename it replaces an
// existing file at newp.
func (s *Interpreter) Rename(oldp, newp string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	oldClean, n := s.visible(oldp)
	if n == nil {
		return iofs.ErrNotExist
	}
	newClean := s.resolvePath(newp)
	if newClean == oldClean {
		return nil
	}
	if oldClean == "/" || strings.HasPrefix(newClean, oldClean+"/") {
		return iofs.ErrInvalid
	}
	if _, dst := s.visible(newClean); dst != nil && dst.Type == NodeDir {
		return iofs.ErrExist
	}
	if err := s.checkCreate(newClean); err != nil {
		return err
	}
	if s.readOnly(oldClean) {
		return ErrReadOnly
	}
	moves := map[string]*Node{oldClean: n}
	if n.Type == NodeDir {
		s.collect(oldClean, n, moves)
	}
	s.remove(oldClean)
	for p, node := range moves {
		cp := *node
		cp.Path = newClean + strings.TrimPrefix(p, oldClean)
		s.overlay[cp.Path] = &cp
		s.addChild(path.Dir(cp.Path), path.Base(cp.Path))
	}
	return nil
}

func (s *Interpreter) collect(p string, n *Node, into map[string]*Node) {
	for _, name := range append(append([]string{}, n.Children...), s.overlayChildren[p]...) {
		cp, child := s.lookup(path.Join(p, name))
		if child == nil {
			continue
		}
		into[cp] = child
		if child.Type == NodeDir {
			s.collect(cp, child, into)
		}
	}
}

// Chmod sets the permission bits (and setuid/setgid/sticky) of p.
func (s *Interpreter) Chmod(p string, perm uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clean, n := s.visible(p)
	if n == nil {
		return iofs.ErrNotExist
	}
	if s.readOnly(clean) {
		return ErrReadOnly
	}
	s.mutable(clean, n).Mode = ModeString(n.Type == NodeDir, perm)
	return nil
}

// ModeString renders permission bits the way ls does.
func ModeString(dir bool, perm uint32) string {
	b := []byte("-rwxrwxrwx")
	if dir {
		b[0] = 'd'
	}
	for i := 0; i < 9; i++ {
		if perm&(1<<(8-i)) == 0 {
			b[i+1] = '-'
		}
	}
	special := func(i int, bit uint32, set, unset byte) {
		if perm&bit != 0 {
			if b[i] == '-' {
				b[i] = unset
			} else {
				b[i] = set
			}
		}
	}
	special(3, 0o4000, 's', 'S')
	special(6, 0o2000, 's', 'S')
	special(9, 0o1000, 't', 'T')
	return string(b)
}

// ModeBits is the inverse of ModeString, including the file-type bits.
func ModeBits(mode string) uint32 {
	if len(mode) < 10 {
		return 0o100644
	}
	var bits uint32 = 0o100000
	if mode[0] == 'd' {
		bits = 0o040000
	}
	for i := 0; i < 9; i++ {
		if c := mode[i+1]; c != '-' && c != 'S' && c != 'T' {
			bits |= 1 << (8 - i)
		}
	}
	if c := mode[3]; c == 's' || c == 'S' {
		bits |= 0o4000
	}
	if c := mode[6]; c == 's' || c == 'S' {
		bits |= 0o2000
	}
	if c := mode[9]; c == 't' || c == 'T' {
		bits |= 0o1000
	}
	return bits
}

// MTimeUnix converts an ls-style timestamp back to Unix time. A stamp
// without a year is the most recent such date not in the future, which is
// what ls means by it.
func MTimeUnix(mtime string, now time.Time) uint32 {
	if t, err := time.Parse("Jan _2  2006", mtime); err == nil {
		return uint32(t.Unix())
	}
	t, err := time.Parse("Jan _2 15:04", mtime)
	if err != nil {
		return uint32(now.Unix())
	}
	t = t.AddDate(now.UTC().Year(), 0, 0)
	if t.After(now) {
		t = t.AddDate(-1, 0, 0)
	}
	return uint32(t.Unix())
}
