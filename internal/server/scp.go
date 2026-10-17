package server

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/mirage-source/mirage-core/internal/session"
)

// Upload caps. Content is hashed as it streams and then discarded, so these
// bound bandwidth and time spent per session, not memory.
const (
	scpMaxFileBytes    = 64 << 20
	scpMaxSessionBytes = 256 << 20
	maxFileTransfers   = 64
	scpMaxLine         = 4096
	scpMaxDepth        = 32
)

// appendTransfer records one upload, dropping it silently past the cap.
func (g *sessionGuard) appendTransfer(f session.FileTransfer) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.sess.FileTransfers) >= maxFileTransfers {
		return
	}
	f.Path = truncateBytes(f.Path, maxRejectedDetailBytes)
	g.sess.FileTransfers = append(g.sess.FileTransfers, f)
}

// scpSinkTarget reports whether an exec command is the remote end of an
// scp upload ("scp [-r] [-p] [-d] [-v] -t [--] dir") and returns dir.
// "scp -f" (download) is left to the shell.
func scpSinkTarget(cmd string) (string, bool) {
	fields := strings.Fields(cmd)
	if len(fields) == 0 || path.Base(fields[0]) != "scp" {
		return "", false
	}
	sink, target, flagsDone := false, ".", false
	for _, f := range fields[1:] {
		switch {
		case !flagsDone && f == "--":
			flagsDone = true
		case !flagsDone && strings.HasPrefix(f, "-") && len(f) > 1:
			if strings.Contains(f, "f") {
				return "", false
			}
			if strings.Contains(f, "t") {
				sink = true
			}
		default:
			target = f
		}
	}
	return target, sink
}

// scpSink speaks the receiving side of the legacy scp (rcp) protocol over
// an exec channel: it acks each record, hashes each file as it streams in
// and records it, keeping none of the content. It returns the exit status
// a real scp would.
type scpSink struct {
	r       *bufio.Reader
	w       io.Writer
	guard   *sessionGuard
	refresh func()
	total   int64
}

func runSCPSink(rw io.ReadWriter, guard *sessionGuard, target string, refresh func()) int {
	s := &scpSink{r: bufio.NewReader(rw), w: rw, guard: guard, refresh: refresh}
	dirs := []string{path.Clean(target)}
	s.w.Write([]byte{0})
	for {
		s.refresh()
		line, err := s.readLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0
			}
			return s.fail("protocol error: " + err.Error())
		}
		if line == "" {
			return s.fail("protocol error: empty record")
		}
		switch line[0] {
		case 'T': // timestamps for the next record (-p)
			s.w.Write([]byte{0})
		case 'D':
			_, _, name, err := parseSCPRecord(line)
			if err != nil {
				return s.fail("protocol error: " + err.Error())
			}
			if len(dirs) >= scpMaxDepth {
				return s.fail("protocol error: too deep")
			}
			dirs = append(dirs, path.Join(dirs[len(dirs)-1], name))
			s.w.Write([]byte{0})
		case 'E':
			if len(dirs) > 1 {
				dirs = dirs[:len(dirs)-1]
			}
			s.w.Write([]byte{0})
		case 'C':
			_, size, name, err := parseSCPRecord(line)
			if err != nil {
				return s.fail("protocol error: " + err.Error())
			}
			if code, done := s.receive(path.Join(dirs[len(dirs)-1], name), size); done {
				return code
			}
		default:
			return s.fail("protocol error: unexpected <" + strconv.Quote(line[:1]) + ">")
		}
	}
}

// receive reads one file body. done reports that the transfer ended the
// session (a cap was hit or the stream broke), with code as exit status.
func (s *scpSink) receive(p string, size int64) (code int, done bool) {
	rec := session.FileTransfer{TimestampMS: time.Now().UnixMilli(), Method: session.TransferMethodSCP, Path: p, Size: size}
	if size > scpMaxFileBytes || s.total+size > scpMaxSessionBytes {
		s.guard.appendTransfer(rec)
		// What scp prints when the disk fills: a fatal error record.
		fmt.Fprintf(s.w, "\x02scp: %s: No space left on device\n", p)
		return 1, true
	}
	s.w.Write([]byte{0})

	h := sha256.New()
	remaining := size
	buf := make([]byte, 32<<10)
	for remaining > 0 {
		s.refresh()
		n, err := s.r.Read(buf[:min(int64(len(buf)), remaining)])
		h.Write(buf[:n])
		remaining -= int64(n)
		s.total += int64(n)
		if err != nil {
			s.guard.appendTransfer(rec)
			return 1, true
		}
	}
	// The source ends each file with a status byte.
	if b, err := s.r.ReadByte(); err != nil || b != 0 {
		s.guard.appendTransfer(rec)
		return 1, true
	}
	rec.SHA256 = hex.EncodeToString(h.Sum(nil))
	rec.Complete = true
	s.guard.appendTransfer(rec)
	s.w.Write([]byte{0})
	return 0, false
}

func (s *scpSink) fail(msg string) int {
	fmt.Fprintf(s.w, "\x01scp: %s\n", msg)
	return 1
}

// readLine reads one record line without the newline, refusing lines past
// scpMaxLine so a client cannot grow it without bound.
func (s *scpSink) readLine() (string, error) {
	var b []byte
	for {
		c, err := s.r.ReadByte()
		if err != nil {
			if len(b) > 0 && errors.Is(err, io.EOF) {
				return "", io.ErrUnexpectedEOF
			}
			return "", err
		}
		if c == '\n' {
			return string(b), nil
		}
		if len(b) >= scpMaxLine {
			return "", errors.New("record too long")
		}
		b = append(b, c)
	}
}

// parseSCPRecord parses "C0644 <size> <name>" or "D0755 0 <name>".
func parseSCPRecord(line string) (mode string, size int64, name string, err error) {
	parts := strings.SplitN(line[1:], " ", 3)
	if len(parts) != 3 || len(parts[0]) != 4 {
		return "", 0, "", errors.New("bad record")
	}
	if _, err := strconv.ParseUint(parts[0], 8, 16); err != nil {
		return "", 0, "", errors.New("bad mode")
	}
	size, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil || size < 0 {
		return "", 0, "", errors.New("bad size")
	}
	name = parts[2]
	if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
		return "", 0, "", errors.New("unexpected filename: " + name)
	}
	return parts[0], size, name, nil
}
