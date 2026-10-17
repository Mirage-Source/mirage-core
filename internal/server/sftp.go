package server

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	iofs "io/fs"
	"path"
	"strings"
	"time"

	"github.com/mirage-source/mirage-core/internal/session"
	"github.com/mirage-source/mirage-core/internal/shell"
)

// SFTP v3 (draft-ietf-secsh-filexfer-02) server for the "sftp" subsystem,
// over the shell's simulated filesystem. Replies copy OpenSSH 8.9's
// sftp-server, measured against ubuntu:22.04 openssh-sftp-server
// 1:8.9p1-3ubuntu0.18: the same extensions, limits, status texts, 4-byte
// handles and ls-style long names. Uploads are hashed as they arrive and
// discarded, like scp.

const (
	sftpInit     = 1
	sftpVersion  = 2
	sftpOpen     = 3
	sftpClose    = 4
	sftpRead     = 5
	sftpWrite    = 6
	sftpLstat    = 7
	sftpFstat    = 8
	sftpSetstat  = 9
	sftpFsetstat = 10
	sftpOpendir  = 11
	sftpReaddir  = 12
	sftpRemove   = 13
	sftpMkdir    = 14
	sftpRmdir    = 15
	sftpRealpath = 16
	sftpStat     = 17
	sftpRename   = 18
	sftpReadlink = 19
	sftpSymlink  = 20
	sftpStatus   = 101
	sftpHandle   = 102
	sftpData     = 103
	sftpName     = 104
	sftpAttrs    = 105
	sftpExtended = 200
	sftpExtReply = 201

	sftpFlagRead  = 0x01
	sftpFlagWrite = 0x02
	sftpFlagCreat = 0x08
	sftpFlagTrunc = 0x10
	sftpFlagExcl  = 0x20

	sftpAttrSize     = 0x01
	sftpAttrUIDGID   = 0x02
	sftpAttrPerms    = 0x04
	sftpAttrACMod    = 0x08
	sftpAttrExtended = 0x80000000
)

// Status codes and the exact messages OpenSSH sends with them.
const (
	fxOK          = 0
	fxEOF         = 1
	fxNoSuchFile  = 2
	fxPermission  = 3
	fxFailure     = 4
	fxBadMessage  = 5
	fxUnsupported = 8
)

var fxMessages = map[uint32]string{
	fxOK: "Success", fxEOF: "End of file", fxNoSuchFile: "No such file",
	fxPermission: "Permission denied", fxFailure: "Failure",
	fxBadMessage: "Bad message", fxUnsupported: "Operation unsupported",
}

// Limits. sftpMaxPacket and sftpMaxReadLen are OpenSSH's own; the rest
// bound what one client can make the sensor hold or do.
const (
	sftpMaxPacket    = 256 << 10
	sftpMaxReadLen   = sftpMaxPacket - 1024
	sftpMaxHandles   = 64
	sftpMaxPath      = 4096
	sftpMaxMutations = 1024
	sftpMaxPackets   = 1 << 20
	sftpDirBatch     = 100
)

// What OpenSSH 8.9 advertises in limits@openssh.com. Open handles past
// sftpMaxHandles fail with Failure, as they would under a low ulimit.
const openSSHMaxOpenHandles = 2043

var sftpExtensions = [][2]string{
	{"posix-rename@openssh.com", "1"},
	{"statvfs@openssh.com", "2"},
	{"fstatvfs@openssh.com", "2"},
	{"hardlink@openssh.com", "1"},
	{"fsync@openssh.com", "1"},
	{"lsetstat@openssh.com", "1"},
	{"limits@openssh.com", "1"},
	{"expand-path@openssh.com", "1"},
}

var (
	errBadPacket   = errors.New("bad sftp packet")
	errPathTooLong = errors.New("sftp path too long")
)

type sftpFile struct {
	path    string
	dir     bool
	listing bool             // from OPENDIR: only READDIR and CLOSE apply
	entries []shell.FileInfo // listing: what is left to send
	read    bool
	write   bool
	content string // read handles: the file as it was at open

	// Upload state. hashing stays true while every write lands exactly at
	// next; one gap or overlap and the file is recorded without a hash.
	h       hash.Hash
	next    int64
	size    int64
	hashing bool
	capped  bool
	record  bool // created, truncated or written: worth recording
}

type sftpServer struct {
	rw        io.ReadWriter
	guard     *sessionGuard
	fs        *shell.Interpreter
	refresh   func()
	handles   map[uint32]*sftpFile
	mutations int
	inited    bool
}

// runSFTP serves one sftp subsystem until the client closes its side or
// breaks the protocol. Open write handles left at the end are recorded as
// incomplete uploads.
func runSFTP(rw io.ReadWriter, guard *sessionGuard, fs *shell.Interpreter, refresh func()) {
	s := &sftpServer{rw: rw, guard: guard, fs: fs, refresh: refresh, handles: map[uint32]*sftpFile{}}
	defer func() {
		for id := range s.handles {
			s.closeHandle(id, false)
		}
	}()
	var hdr [4]byte
	for n := 0; n < sftpMaxPackets; n++ {
		s.refresh()
		if _, err := io.ReadFull(rw, hdr[:]); err != nil {
			return
		}
		size := binary.BigEndian.Uint32(hdr[:])
		// OpenSSH treats a zero or oversized length as fatal and exits.
		if size == 0 || size > sftpMaxPacket {
			return
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(rw, buf); err != nil {
			return
		}
		if err := s.dispatch(buf); err != nil {
			return
		}
	}
}

func (s *sftpServer) dispatch(buf []byte) error {
	r := &sftpReader{b: buf[1:]}
	typ := buf[0]
	if typ == sftpInit {
		r.u32() // client version; OpenSSH answers 3 whatever it is
		if r.err != nil {
			return errBadPacket
		}
		s.inited = true
		w := new(sftpWriter).u8(sftpVersion).u32(3)
		for _, e := range sftpExtensions {
			w.str(e[0]).str(e[1])
		}
		return s.send(w)
	}
	if !s.inited {
		return errBadPacket // "Received ... before init": sftp-server exits
	}
	id := r.u32()
	if r.err != nil {
		return errBadPacket
	}
	var w *sftpWriter
	switch typ {
	case sftpOpen:
		p, flags, a := r.path(), r.u32(), r.attrs()
		if r.ok() {
			w = s.open(id, p, flags, a)
		}
	case sftpClose:
		if h := r.str(); r.ok() {
			w = s.close(id, h)
		}
	case sftpRead:
		h, off, n := r.str(), r.u64(), r.u32()
		if r.ok() {
			w = s.readFile(id, h, off, n)
		}
	case sftpWrite:
		h, off, data := r.str(), r.u64(), r.str()
		if r.ok() {
			w = s.writeFile(id, h, off, data)
		}
	case sftpLstat, sftpStat:
		if p := r.path(); r.ok() {
			w = s.stat(id, p)
		}
	case sftpFstat:
		if f := s.file(r.str()); !r.ok() {
		} else if f == nil {
			w = status(id, fxNoSuchFile)
		} else if f.listing {
			w = status(id, fxFailure)
		} else {
			w = s.stat(id, f.path)
		}
	case sftpSetstat:
		p, a := r.path(), r.attrs()
		if r.ok() {
			w = s.setstat(id, p, a)
		}
	case sftpFsetstat:
		f, a := s.file(r.str()), r.attrs()
		if !r.ok() {
		} else if f == nil {
			w = status(id, fxNoSuchFile)
		} else {
			w = s.setstat(id, f.path, a)
		}
	case sftpOpendir:
		if p := r.path(); r.ok() {
			w = s.opendir(id, p)
		}
	case sftpReaddir:
		if h := r.str(); r.ok() {
			w = s.readdir(id, h)
		}
	case sftpRemove:
		if p := r.path(); r.ok() {
			w = s.mutate(id, func() error { return s.fs.Remove(p, false) }, fxFailure) // EISDIR
		}
	case sftpRmdir:
		if p := r.path(); r.ok() {
			w = s.mutate(id, func() error { return s.fs.Remove(p, true) }, fxNoSuchFile) // ENOTDIR
		}
	case sftpMkdir:
		p, a := r.path(), r.attrs()
		if r.ok() {
			w = s.mkdir(id, p, a)
		}
	case sftpRealpath:
		if p := r.path(); r.ok() {
			w = s.realpath(id, p)
		}
	case sftpRename:
		oldp, newp := r.path(), r.path()
		if r.ok() {
			w = s.rename(id, oldp, newp, false)
		}
	case sftpReadlink:
		// No symlinks exist: readlink(2) on anything that does gives EINVAL.
		if p := r.path(); !r.ok() {
		} else if _, err := s.fs.Stat(p); err != nil {
			w = status(id, fxNoSuchFile)
		} else {
			w = status(id, fxBadMessage)
		}
	case sftpSymlink:
		r.path()
		r.path()
		w = status(id, fxFailure)
	case sftpExtended:
		w = s.extended(id, r)
	default:
		// sftp-server logs "Unknown message" and sends nothing back.
		return nil
	}
	switch {
	case errors.Is(r.err, errPathTooLong):
		w = status(id, fxBadMessage) // ENAMETOOLONG; nothing was done
	case r.err != nil:
		return errBadPacket // malformed request: fatal in sftp-server too
	}
	return s.send(w)
}

func (s *sftpServer) send(w *sftpWriter) error {
	out := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(w.b)), uint32(len(w.b)))
	_, err := s.rw.Write(append(out, w.b...))
	return err
}

func status(id uint32, code uint32) *sftpWriter {
	return new(sftpWriter).u8(sftpStatus).u32(id).u32(code).str(fxMessages[code]).str("")
}

// errStatus maps a filesystem error to the status OpenSSH would send for
// the errno behind it. invalid is the code for fs.ErrInvalid, whose errno
// depends on the call (ENOTDIR -> no such file, EISDIR -> failure, EINVAL
// -> bad message).
func errStatus(id uint32, err error, invalid uint32) *sftpWriter {
	switch {
	case err == nil:
		return status(id, fxOK)
	case errors.Is(err, iofs.ErrNotExist):
		return status(id, fxNoSuchFile)
	case errors.Is(err, iofs.ErrPermission):
		return status(id, fxPermission)
	case errors.Is(err, iofs.ErrInvalid):
		return status(id, invalid)
	default: // EEXIST, ENOTEMPTY, EROFS
		return status(id, fxFailure)
	}
}

// mutate runs a filesystem change, refusing once the session has made
// sftpMaxMutations of them so the overlay cannot grow without bound.
func (s *sftpServer) mutate(id uint32, op func() error, invalid uint32) *sftpWriter {
	if s.mutations >= sftpMaxMutations {
		return status(id, fxFailure)
	}
	s.mutations++
	return errStatus(id, op(), invalid)
}

func (s *sftpServer) file(handle string) *sftpFile {
	if len(handle) != 4 {
		return nil
	}
	return s.handles[binary.BigEndian.Uint32([]byte(handle))]
}

// newHandle takes the lowest free slot, as OpenSSH does.
func (s *sftpServer) newHandle(id uint32, f *sftpFile) *sftpWriter {
	if len(s.handles) >= sftpMaxHandles {
		return status(id, fxFailure)
	}
	var h uint32
	for s.handles[h] != nil {
		h++
	}
	s.handles[h] = f
	return new(sftpWriter).u8(sftpHandle).u32(id).str(string(binary.BigEndian.AppendUint32(nil, h)))
}

func (s *sftpServer) open(id uint32, p string, flags uint32, a sftpAttrSet) *sftpWriter {
	abs := s.fs.Abs(p)
	f := &sftpFile{path: abs, read: flags&sftpFlagRead != 0, write: flags&sftpFlagWrite != 0}
	fi, statErr := s.fs.Stat(abs)
	exists := statErr == nil

	switch {
	case flags&sftpFlagCreat != 0 && flags&sftpFlagExcl != 0 && exists:
		return status(id, fxFailure) // EEXIST
	case !exists && flags&sftpFlagCreat == 0:
		return status(id, fxNoSuchFile)
	case exists && fi.Dir && f.write:
		return status(id, fxFailure) // EISDIR
	}

	if f.write || !exists {
		if s.mutations >= sftpMaxMutations {
			return status(id, fxFailure)
		}
		s.mutations++
		if err := s.fs.CreateFile(abs, flags&sftpFlagTrunc != 0); err != nil {
			return errStatus(id, err, fxFailure)
		}
		if !exists && a.flags&sftpAttrPerms != 0 {
			s.fs.Chmod(abs, a.perm&0o7777&^0o022)
		}
		f.record = !exists || flags&sftpFlagTrunc != 0
		f.h, f.hashing = sha256.New(), true
		if exists && flags&sftpFlagTrunc == 0 {
			// Writing into an existing file: its prior bytes are unknown,
			// so no hash of the result would be honest.
			f.hashing = false
			f.size = fi.Size
		}
	}
	if f.read && exists && !fi.Dir {
		f.content, _ = s.fs.ReadFile(abs)
	}
	f.dir = exists && fi.Dir
	return s.newHandle(id, f)
}

func (s *sftpServer) close(id uint32, handle string) *sftpWriter {
	if f := s.file(handle); f != nil {
		s.closeHandle(binary.BigEndian.Uint32([]byte(handle)), true)
		return status(id, fxOK)
	}
	return status(id, fxNoSuchFile)
}

// closeHandle releases a handle; a write handle becomes a FileTransfer,
// complete only if the client closed it and every byte was hashed.
func (s *sftpServer) closeHandle(h uint32, clean bool) {
	f := s.handles[h]
	delete(s.handles, h)
	if f == nil || !f.write || !f.record {
		return
	}
	rec := session.FileTransfer{TimestampMS: time.Now().UnixMilli(), Method: session.TransferMethodSFTP, Path: f.path, Size: f.size}
	if clean && f.hashing && !f.capped && f.next == f.size {
		rec.SHA256 = hex.EncodeToString(f.h.Sum(nil))
		rec.Complete = true
	}
	s.guard.appendTransfer(rec)
}

func (s *sftpServer) readFile(id uint32, handle string, off uint64, n uint32) *sftpWriter {
	f := s.file(handle)
	switch {
	case f == nil:
		return status(id, fxNoSuchFile)
	case f.listing:
		return status(id, fxFailure)
	case !f.read:
		return status(id, fxNoSuchFile) // EBADF
	case f.dir:
		return status(id, fxFailure) // EISDIR
	case off >= uint64(len(f.content)):
		return status(id, fxEOF)
	}
	end := off + uint64(min(n, sftpMaxReadLen))
	end = min(end, uint64(len(f.content)))
	return new(sftpWriter).u8(sftpData).u32(id).str(f.content[off:end])
}

func (s *sftpServer) writeFile(id uint32, handle string, off uint64, data string) *sftpWriter {
	f := s.file(handle)
	switch {
	case f == nil:
		return status(id, fxNoSuchFile)
	case f.listing || f.dir:
		return status(id, fxFailure)
	case !f.write:
		return status(id, fxNoSuchFile) // EBADF
	}
	n := int64(len(data))
	end := int64(off) + n
	if f.capped || off > uploadMaxFileBytes || end > uploadMaxFileBytes || !s.guard.reserveUpload(n) {
		// What a full disk looks like: ENOSPC maps to a plain Failure.
		f.capped = true
		return status(id, fxFailure)
	}
	f.record = true
	if f.hashing && int64(off) == f.next {
		f.h.Write([]byte(data))
		f.next = end
	} else {
		f.hashing = false
	}
	if end > f.size {
		f.size = end
		s.fs.SetSize(f.path, f.size)
	}
	return status(id, fxOK)
}

func (s *sftpServer) stat(id uint32, p string) *sftpWriter {
	fi, err := s.fs.Stat(p)
	if err != nil {
		return errStatus(id, err, fxNoSuchFile)
	}
	w := new(sftpWriter).u8(sftpAttrs).u32(id)
	writeAttrs(w, fi)
	return w
}

func (s *sftpServer) setstat(id uint32, p string, a sftpAttrSet) *sftpWriter {
	if a.flags&(sftpAttrSize|sftpAttrPerms|sftpAttrUIDGID|sftpAttrACMod) == 0 {
		return status(id, fxOK) // nothing to do, so no lookup either
	}
	fi, err := s.fs.Stat(p)
	if err != nil {
		return errStatus(id, err, fxNoSuchFile)
	}
	return s.mutate(id, func() error {
		if a.flags&sftpAttrSize != 0 && !fi.Dir {
			s.fs.SetSize(p, int64(min(a.size, uploadMaxFileBytes)))
		}
		if a.flags&sftpAttrPerms != 0 {
			return s.fs.Chmod(p, a.perm&0o7777)
		}
		return nil
	}, fxFailure)
}

func (s *sftpServer) opendir(id uint32, p string) *sftpWriter {
	entries, err := s.fs.ReadDir(p)
	if err != nil {
		return errStatus(id, err, fxNoSuchFile) // ENOTDIR
	}
	return s.newHandle(id, &sftpFile{path: s.fs.Abs(p), dir: true, listing: true, entries: entries})
}

func (s *sftpServer) readdir(id uint32, handle string) *sftpWriter {
	f := s.file(handle)
	switch {
	case f == nil:
		return status(id, fxNoSuchFile)
	case !f.listing:
		return status(id, fxFailure)
	case len(f.entries) == 0:
		return status(id, fxEOF)
	}
	batch := f.entries[:min(len(f.entries), sftpDirBatch)]
	f.entries = f.entries[len(batch):]
	w := new(sftpWriter).u8(sftpName).u32(id).u32(uint32(len(batch)))
	for _, e := range batch {
		w.str(e.Name).str(longName(e))
		writeAttrs(w, e)
	}
	return w
}

func (s *sftpServer) mkdir(id uint32, p string, a sftpAttrSet) *sftpWriter {
	return s.mutate(id, func() error {
		if err := s.fs.Mkdir(p); err != nil {
			return err
		}
		if a.flags&sftpAttrPerms != 0 {
			s.fs.Chmod(p, a.perm&0o7777&^0o022)
		}
		return nil
	}, fxFailure)
}

// realpath resolves like OpenSSH's sftp_realpath: every component but the
// last must exist.
func (s *sftpServer) realpath(id uint32, p string) *sftpWriter {
	abs := s.fs.Abs(p)
	if _, err := s.fs.Stat(abs); err != nil {
		if parent, err := s.fs.Stat(path.Dir(abs)); err != nil || !parent.Dir {
			return status(id, fxNoSuchFile)
		}
	}
	return new(sftpWriter).u8(sftpName).u32(id).u32(1).str(abs).str(abs).u32(0)
}

// rename is SFTP v3 rename (fails if newp exists) or, with overwrite,
// posix-rename@openssh.com.
func (s *sftpServer) rename(id uint32, oldp, newp string, overwrite bool) *sftpWriter {
	if _, err := s.fs.Stat(oldp); err != nil {
		return status(id, fxNoSuchFile)
	}
	if _, err := s.fs.Stat(newp); err == nil && !overwrite {
		return status(id, fxFailure) // EEXIST from link(2)
	}
	return s.mutate(id, func() error { return s.fs.Rename(oldp, newp) }, fxBadMessage)
}

// extended handles SSH_FXP_EXTENDED. Like dispatch, it parses every
// argument before acting; on a parse error the reply is discarded.
func (s *sftpServer) extended(id uint32, r *sftpReader) *sftpWriter {
	name := r.str()
	switch name {
	case "posix-rename@openssh.com":
		if oldp, newp := r.path(), r.path(); r.ok() {
			return s.rename(id, oldp, newp, true)
		}
	case "statvfs@openssh.com":
		if p := r.path(); !r.ok() {
		} else if _, err := s.fs.Stat(p); err != nil {
			return status(id, fxNoSuchFile)
		} else {
			return statvfsReply(id)
		}
	case "fstatvfs@openssh.com", "fsync@openssh.com":
		if f := s.file(r.str()); !r.ok() {
		} else if f == nil {
			return status(id, fxNoSuchFile)
		} else if f.listing {
			return status(id, fxFailure)
		} else if name == "fsync@openssh.com" {
			return status(id, fxOK)
		} else {
			return statvfsReply(id)
		}
	case "lsetstat@openssh.com":
		if p, a := r.path(), r.attrs(); r.ok() {
			return s.setstat(id, p, a)
		}
	case "limits@openssh.com":
		return new(sftpWriter).u8(sftpExtReply).u32(id).
			u64(sftpMaxPacket).u64(sftpMaxReadLen).u64(sftpMaxReadLen).u64(openSSHMaxOpenHandles)
	case "expand-path@openssh.com":
		p := r.path()
		if !r.ok() {
			return nil
		}
		if strings.HasPrefix(p, "~") && p != "~" && !strings.HasPrefix(p, "~/") {
			return status(id, fxFailure) // ~otheruser: not resolved here
		}
		return s.realpath(id, p)
	case "hardlink@openssh.com":
		r.path()
		r.path()
		return status(id, fxFailure)
	default:
		return status(id, fxUnsupported)
	}
	return nil
}

// statvfsReply describes an 8 GiB root volume, roughly a third used.
func statvfsReply(id uint32) *sftpWriter {
	return new(sftpWriter).u8(sftpExtReply).u32(id).
		u64(4096).u64(4096).                    // bsize, frsize
		u64(2031616).u64(1302528).u64(1286144). // blocks, bfree, bavail
		u64(1032192).u64(951212).u64(951212).   // files, ffree, favail
		u64(0x8a3f1c2d5e6b7a90).                // fsid
		u64(0).u64(255)                         // flag, namemax
}

func uidOf(owner string) uint32 {
	if owner == "root" {
		return 0
	}
	return 1000
}

func writeAttrs(w *sftpWriter, fi shell.FileInfo) {
	mtime := shell.MTimeUnix(fi.MTime, time.Now())
	w.u32(sftpAttrSize | sftpAttrUIDGID | sftpAttrPerms | sftpAttrACMod).
		u64(uint64(fi.Size)).u32(uidOf(fi.Owner)).u32(uidOf(fi.Group)).
		u32(shell.ModeBits(fi.Mode)).u32(mtime).u32(mtime)
}

// longName is OpenSSH's ls_file(): strmode's 11 characters (the last a
// space), nlink, owner and group padded to 8, size to 8. nlink is 1 to
// match the shell's own ls -l.
func longName(fi shell.FileInfo) string {
	return fmt.Sprintf("%s  %3d %-8s %-8s %8d %s %s", fi.Mode, 1, fi.Owner, fi.Group, fi.Size, fi.MTime, fi.Name)
}

type sftpAttrSet struct {
	flags uint32
	size  uint64
	perm  uint32
}

// sftpReader decodes big-endian fields; any short read sets err and every
// later read returns zero values.
type sftpReader struct {
	b   []byte
	err error
}

func (r *sftpReader) take(n int) []byte {
	if r.err != nil || n < 0 || len(r.b) < n {
		r.err = errBadPacket
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *sftpReader) u32() uint32 {
	if b := r.take(4); b != nil {
		return binary.BigEndian.Uint32(b)
	}
	return 0
}

func (r *sftpReader) u64() uint64 {
	if b := r.take(8); b != nil {
		return binary.BigEndian.Uint64(b)
	}
	return 0
}

func (r *sftpReader) str() string {
	n := r.u32()
	if n > uint32(len(r.b)) {
		r.err = errBadPacket
		return ""
	}
	return string(r.take(int(n)))
}

func (r *sftpReader) ok() bool { return r.err == nil }

// path reads a path argument. One over PATH_MAX stops the request before
// it runs, so it can never become a huge key in the overlay.
func (r *sftpReader) path() string {
	p := r.str()
	if r.err == nil && len(p) > sftpMaxPath {
		r.err = errPathTooLong
		return ""
	}
	return p
}

func (r *sftpReader) attrs() sftpAttrSet {
	var a sftpAttrSet
	a.flags = r.u32()
	if a.flags&sftpAttrSize != 0 {
		a.size = r.u64()
	}
	if a.flags&sftpAttrUIDGID != 0 {
		r.u32()
		r.u32()
	}
	if a.flags&sftpAttrPerms != 0 {
		a.perm = r.u32()
	}
	if a.flags&sftpAttrACMod != 0 {
		r.u32()
		r.u32()
	}
	if a.flags&sftpAttrExtended != 0 {
		for n := r.u32(); n > 0 && r.err == nil; n-- {
			r.str()
			r.str()
		}
	}
	return a
}

type sftpWriter struct{ b []byte }

func (w *sftpWriter) u8(v byte) *sftpWriter    { w.b = append(w.b, v); return w }
func (w *sftpWriter) u32(v uint32) *sftpWriter { w.b = binary.BigEndian.AppendUint32(w.b, v); return w }
func (w *sftpWriter) u64(v uint64) *sftpWriter { w.b = binary.BigEndian.AppendUint64(w.b, v); return w }
func (w *sftpWriter) str(s string) *sftpWriter {
	w.u32(uint32(len(s)))
	w.b = append(w.b, s...)
	return w
}
