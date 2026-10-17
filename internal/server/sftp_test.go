package server

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/mirage-source/mirage-core/internal/session"
	"github.com/mirage-source/mirage-core/internal/shell"
	"golang.org/x/crypto/ssh"
)

// sftpClient sends raw SFTP v3 packets, so tests pin the wire format
// rather than what some client library tolerates.
type sftpClient struct {
	t    *testing.T
	in   io.WriteCloser
	out  io.Reader
	sess *ssh.Session
	id   uint32
}

type pkt struct {
	b []byte
}

func (p *pkt) u8(v byte) *pkt    { p.b = append(p.b, v); return p }
func (p *pkt) u32(v uint32) *pkt { p.b = binary.BigEndian.AppendUint32(p.b, v); return p }
func (p *pkt) u64(v uint64) *pkt { p.b = binary.BigEndian.AppendUint64(p.b, v); return p }
func (p *pkt) str(s string) *pkt { p.u32(uint32(len(s))); p.b = append(p.b, s...); return p }

func startSFTP(t *testing.T, client *ssh.Client) *sftpClient {
	t.Helper()
	s, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	in, _ := s.StdinPipe()
	out, _ := s.StdoutPipe()
	if err := s.RequestSubsystem("sftp"); err != nil {
		t.Fatalf("sftp subsystem refused: %v", err)
	}
	c := &sftpClient{t: t, in: in, out: out, sess: s}
	c.raw(new(pkt).u8(sftpInit).u32(3).b)
	if typ, _ := c.recv(); typ != sftpVersion {
		t.Fatalf("got type %d, want VERSION", typ)
	}
	return c
}

func (c *sftpClient) raw(body []byte) {
	c.in.Write(binary.BigEndian.AppendUint32(nil, uint32(len(body))))
	c.in.Write(body)
}

// req sends a request with a fresh id; body is everything after the id.
func (c *sftpClient) req(typ byte, body *pkt) uint32 {
	c.id++
	c.raw(append(new(pkt).u8(typ).u32(c.id).b, body.b...))
	return c.id
}

func (c *sftpClient) recv() (byte, []byte) {
	c.t.Helper()
	var n [4]byte
	if _, err := io.ReadFull(c.out, n[:]); err != nil {
		c.t.Fatalf("reading reply: %v", err)
	}
	b := make([]byte, binary.BigEndian.Uint32(n[:]))
	if _, err := io.ReadFull(c.out, b); err != nil {
		c.t.Fatalf("reading reply: %v", err)
	}
	return b[0], b[1:]
}

// status expects a STATUS reply and returns its code and message.
func (c *sftpClient) status() (uint32, string) {
	c.t.Helper()
	typ, b := c.recv()
	if typ != sftpStatus {
		c.t.Fatalf("got type %d %q, want STATUS", typ, b)
	}
	code := binary.BigEndian.Uint32(b[4:])
	n := binary.BigEndian.Uint32(b[8:])
	return code, string(b[12 : 12+n])
}

func (c *sftpClient) expectOK() {
	c.t.Helper()
	if code, msg := c.status(); code != 0 {
		c.t.Fatalf("status %d %q, want Success", code, msg)
	}
}

func (c *sftpClient) handle() string {
	c.t.Helper()
	typ, b := c.recv()
	if typ != sftpHandle {
		c.t.Fatalf("got type %d %q, want HANDLE", typ, b)
	}
	n := binary.BigEndian.Uint32(b[4:])
	return string(b[8 : 8+n])
}

func (c *sftpClient) open(path string, flags uint32) string {
	c.t.Helper()
	c.req(sftpOpen, new(pkt).str(path).u32(flags).u32(0))
	return c.handle()
}

func (c *sftpClient) write(h string, off uint64, data string) {
	c.req(sftpWrite, new(pkt).str(h).u64(off).str(data))
}

func (c *sftpClient) close() {
	c.in.Close()
	c.sess.Wait()
}

const wCreatTrunc = sftpFlagWrite | sftpFlagCreat | sftpFlagTrunc

// Captured from ubuntu:22.04 openssh-sftp-server 1:8.9p1-3ubuntu0.18.
const openssh89Version = "\x02\x00\x00\x00\x03" +
	"\x00\x00\x00\x18posix-rename@openssh.com\x00\x00\x00\x011" +
	"\x00\x00\x00\x13statvfs@openssh.com\x00\x00\x00\x012" +
	"\x00\x00\x00\x14fstatvfs@openssh.com\x00\x00\x00\x012" +
	"\x00\x00\x00\x14hardlink@openssh.com\x00\x00\x00\x011" +
	"\x00\x00\x00\x11fsync@openssh.com\x00\x00\x00\x011" +
	"\x00\x00\x00\x14lsetstat@openssh.com\x00\x00\x00\x011" +
	"\x00\x00\x00\x12limits@openssh.com\x00\x00\x00\x011" +
	"\x00\x00\x00\x17expand-path@openssh.com\x00\x00\x00\x011"

func TestSFTPVersionMatchesOpenSSH89(t *testing.T) {
	client, finish := dialRecordingSensor(t)
	s, _ := client.NewSession()
	in, _ := s.StdinPipe()
	out, _ := s.StdoutPipe()
	if err := s.RequestSubsystem("sftp"); err != nil {
		t.Fatal(err)
	}
	c := &sftpClient{t: t, in: in, out: out, sess: s}
	c.raw(new(pkt).u8(sftpInit).u32(3).b)
	typ, body := c.recv()
	if got := string(append([]byte{typ}, body...)); got != openssh89Version {
		t.Errorf("VERSION differs from OpenSSH 8.9:\n got %q\nwant %q", got, openssh89Version)
	}
	c.close()
	if s := finish(); len(s.RejectedRequests) != 0 {
		t.Errorf("accepted sftp still logged as rejected: %+v", s.RejectedRequests)
	}
}

func TestSFTPUploadIsHashedNotKept(t *testing.T) {
	client, finish := dialRecordingSensor(t)
	c := startSFTP(t, client)
	payload := "\x7fELF\x02\x01\x01 fake mirai payload, sent in three writes"
	h := c.open("/tmp/x86", wCreatTrunc)
	c.write(h, 0, payload[:10])
	c.expectOK()
	c.write(h, 10, payload[10:20])
	c.expectOK()
	c.write(h, 20, payload[20:])
	c.expectOK()
	c.req(sftpFsetstat, new(pkt).str(h).u32(sftpAttrPerms).u32(0o755))
	c.expectOK()
	c.req(sftpClose, new(pkt).str(h))
	c.expectOK()

	// The upload is visible to stat with its size and new mode.
	c.req(sftpStat, new(pkt).str("/tmp/x86"))
	typ, b := c.recv()
	if typ != sftpAttrs {
		t.Fatalf("stat: type %d", typ)
	}
	if size := binary.BigEndian.Uint64(b[8:]); size != uint64(len(payload)) {
		t.Errorf("stat size = %d", size)
	}
	if perm := binary.BigEndian.Uint32(b[24:]); perm != 0o100755 {
		t.Errorf("stat perm = %o", perm)
	}
	c.close()
	s := finish()

	if len(s.FileTransfers) != 1 {
		t.Fatalf("transfers = %+v", s.FileTransfers)
	}
	f := s.FileTransfers[0]
	if f.Method != session.TransferMethodSFTP || f.Path != "/tmp/x86" || f.Size != int64(len(payload)) || f.SHA256 != sum([]byte(payload)) || !f.Complete {
		t.Errorf("got %+v", f)
	}
}

func TestSFTPOutOfOrderWriteIsRecordedWithoutHash(t *testing.T) {
	client, finish := dialRecordingSensor(t)
	c := startSFTP(t, client)
	h := c.open("/tmp/sparse", wCreatTrunc)
	c.write(h, 0, "abc")
	c.expectOK()
	c.write(h, 10, "xyz") // a gap: the client still sees success
	c.expectOK()
	c.req(sftpClose, new(pkt).str(h))
	c.expectOK()
	c.close()
	s := finish()

	if len(s.FileTransfers) != 1 {
		t.Fatalf("transfers = %+v", s.FileTransfers)
	}
	if f := s.FileTransfers[0]; f.Complete || f.SHA256 != "" || f.Size != 13 {
		t.Errorf("got %+v; want size 13, no hash, incomplete", f)
	}
}

func TestSFTPUploadPastCapIsRefused(t *testing.T) {
	client, finish := dialRecordingSensor(t)
	c := startSFTP(t, client)
	h := c.open("/tmp/big", wCreatTrunc)
	c.write(h, 0, "ok")
	c.expectOK()
	// A write that would cross the per-file cap fails the way a full disk
	// does, without the server reading any further.
	c.write(h, uploadMaxFileBytes-1, "xx")
	if code, msg := c.status(); code != 4 || msg != "Failure" {
		t.Errorf("got %d %q, want 4 Failure", code, msg)
	}
	c.req(sftpClose, new(pkt).str(h))
	c.expectOK()
	c.close()
	s := finish()

	if len(s.FileTransfers) != 1 || s.FileTransfers[0].Complete || s.FileTransfers[0].SHA256 != "" {
		t.Errorf("transfers = %+v", s.FileTransfers)
	}
}

func TestSFTPDroppedUploadIsRecordedIncomplete(t *testing.T) {
	client, finish := dialRecordingSensor(t)
	c := startSFTP(t, client)
	h := c.open("/tmp/cut", wCreatTrunc)
	c.write(h, 0, "partial")
	c.expectOK()
	c.close() // no CLOSE packet
	s := finish()

	if len(s.FileTransfers) != 1 {
		t.Fatalf("transfers = %+v", s.FileTransfers)
	}
	if f := s.FileTransfers[0]; f.Complete || f.SHA256 != "" || f.Size != 7 || f.Path != "/tmp/cut" {
		t.Errorf("got %+v", f)
	}
}

// Status codes and texts measured against OpenSSH 8.9's sftp-server.
func TestSFTPErrorsMatchOpenSSH(t *testing.T) {
	client, finish := dialRecordingSensor(t)
	c := startSFTP(t, client)
	cases := []struct {
		name string
		typ  byte
		body *pkt
		code uint32
		msg  string
	}{
		{"stat missing", sftpStat, new(pkt).str("/nope"), 2, "No such file"},
		{"realpath missing parent", sftpRealpath, new(pkt).str("/nope/x"), 2, "No such file"},
		{"open missing dir", sftpOpen, new(pkt).str("/nope/x").u32(wCreatTrunc).u32(0), 2, "No such file"},
		{"open dir for write", sftpOpen, new(pkt).str("/tmp").u32(wCreatTrunc).u32(0), 4, "Failure"},
		{"opendir on file", sftpOpendir, new(pkt).str("/etc/passwd"), 2, "No such file"},
		{"mkdir existing", sftpMkdir, new(pkt).str("/tmp").u32(0), 4, "Failure"},
		{"remove missing", sftpRemove, new(pkt).str("/nope"), 2, "No such file"},
		{"close bogus handle", sftpClose, new(pkt).str("zzzz"), 2, "No such file"},
		{"readlink missing", sftpReadlink, new(pkt).str("/nope"), 2, "No such file"},
		{"setstat no flags on missing", sftpSetstat, new(pkt).str("/tmp/nope").u32(0), 0, "Success"},
		{"unknown extension", sftpExtended, new(pkt).str("bogus@x"), 8, "Operation unsupported"},
	}
	for _, tc := range cases {
		c.req(tc.typ, tc.body)
		if code, msg := c.status(); code != tc.code || msg != tc.msg {
			t.Errorf("%s: got %d %q, want %d %q", tc.name, code, msg, tc.code, tc.msg)
		}
	}
	c.close()
	finish()
}

func TestSFTPUnknownTypeGetsNoReply(t *testing.T) {
	client, finish := dialRecordingSensor(t)
	c := startSFTP(t, client)
	c.req(99, new(pkt))
	id := c.req(sftpStat, new(pkt).str("/nope"))
	typ, b := c.recv()
	// The first reply is the stat's: type 99 was dropped silently.
	if typ != sftpStatus || binary.BigEndian.Uint32(b) != id {
		t.Errorf("got type %d id %d, want STATUS for id %d", typ, binary.BigEndian.Uint32(b), id)
	}
	c.close()
	finish()
}

func TestSFTPRealpathAndReaddir(t *testing.T) {
	client, finish := dialRecordingSensor(t)
	c := startSFTP(t, client)

	// "." is the login user's home, as under sshd.
	c.req(sftpRealpath, new(pkt).str("."))
	typ, b := c.recv()
	if typ != sftpName || !bytes.Contains(b, []byte("/root")) {
		t.Errorf("realpath . = %d %q", typ, b)
	}
	c.req(sftpExtended, new(pkt).str("expand-path@openssh.com").str("~/x"))
	if typ, b := c.recv(); typ != sftpName || !bytes.Contains(b, []byte("/root/x")) {
		t.Errorf("expand-path = %d %q", typ, b)
	}

	h := c.open("/tmp/drop", wCreatTrunc)
	c.write(h, 0, "12345")
	c.expectOK()
	c.req(sftpClose, new(pkt).str(h))
	c.expectOK()

	c.req(sftpOpendir, new(pkt).str("/tmp"))
	dh := c.handle()
	c.req(sftpReaddir, new(pkt).str(dh))
	typ, b = c.recv()
	if typ != sftpName {
		t.Fatalf("readdir type %d", typ)
	}
	// OpenSSH's ls_file layout: mode, nlink, owner and group padded to 8,
	// size to 8.
	if !bytes.Contains(b, []byte("-rw-r--r--    1 root     root            5 ")) {
		t.Errorf("longname not in OpenSSH format: %q", b)
	}
	c.req(sftpReaddir, new(pkt).str(dh))
	if code, msg := c.status(); code != 1 || msg != "End of file" {
		t.Errorf("second readdir: %d %q", code, msg)
	}
	c.close()
	finish()
}

func TestSFTPDownloadServesFakeContent(t *testing.T) {
	client, finish := dialRecordingSensor(t)
	c := startSFTP(t, client)
	h := c.open("/etc/passwd", sftpFlagRead)
	c.req(sftpRead, new(pkt).str(h).u64(0).u32(32768))
	typ, b := c.recv()
	if typ != sftpData || !bytes.Contains(b, []byte("root:x:0:0")) {
		t.Errorf("read = %d %q", typ, b)
	}
	c.req(sftpRead, new(pkt).str(h).u64(1<<20).u32(10))
	if code, msg := c.status(); code != 1 || msg != "End of file" {
		t.Errorf("read past EOF: %d %q", code, msg)
	}
	c.close()
	finish()
}

func TestSFTPOversizedPacketEndsSubsystem(t *testing.T) {
	client, finish := dialRecordingSensor(t)
	c := startSFTP(t, client)
	c.in.Write(binary.BigEndian.AppendUint32(nil, sftpMaxPacket+1))
	done := make(chan error, 1)
	go func() { done <- c.sess.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("subsystem kept running after an oversized length")
	}
	finish()
}

func TestOtherSubsystemsStillRefused(t *testing.T) {
	client, finish := dialRecordingSensor(t)
	sshSess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sshSess.RequestSubsystem("netconf"); err == nil {
		t.Error("netconf subsystem must be refused")
	}
	s := finish()
	if len(s.RejectedRequests) != 1 || s.RejectedRequests[0].Kind != session.RejectedKindSubsystem || s.RejectedRequests[0].Type != "netconf" {
		t.Errorf("rejected = %+v", s.RejectedRequests)
	}
}

// FuzzSFTPServer feeds arbitrary bytes as a client stream. The server must
// never panic and must stop when the input ends.
func FuzzSFTPServer(f *testing.F) {
	f.Add(new(pkt).u32(5).u8(sftpInit).u32(3).b)
	open := new(pkt).u8(sftpOpen).u32(1).str("/tmp/a").u32(wCreatTrunc).u32(sftpAttrPerms | sftpAttrSize).u64(1).u32(0o644).b
	write := new(pkt).u8(sftpWrite).u32(2).str("\x00\x00\x00\x00").u64(0).str("hi").b
	var seed []byte
	for _, b := range [][]byte{new(pkt).u8(sftpInit).u32(3).b, open, write} {
		seed = append(binary.BigEndian.AppendUint32(seed, uint32(len(b))), b...)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		guard := &sessionGuard{sess: &session.Session{}}
		rw := struct {
			io.Reader
			io.Writer
		}{bytes.NewReader(data), io.Discard}
		runSFTP(rw, guard, shell.NewInterpreter("root"), func() {})
	})
}
