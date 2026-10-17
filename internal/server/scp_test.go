package server

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/mirage-source/mirage-core/internal/session"
	"golang.org/x/crypto/ssh"
)

// scpClient drives the source side of the legacy scp protocol over one
// exec channel, the way libssh2-based bots upload.
type scpClient struct {
	t    *testing.T
	in   io.WriteCloser
	out  *bufio.Reader
	sess *ssh.Session
}

func startSCP(t *testing.T, client *ssh.Client, cmd string) *scpClient {
	t.Helper()
	s, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	in, _ := s.StdinPipe()
	out, _ := s.StdoutPipe()
	if err := s.Start(cmd); err != nil {
		t.Fatal(err)
	}
	c := &scpClient{t: t, in: in, out: bufio.NewReader(out), sess: s}
	c.ack() // the sink speaks first
	return c
}

func (c *scpClient) ack() {
	c.t.Helper()
	b, err := c.out.ReadByte()
	if err != nil || b != 0 {
		rest, _ := c.out.ReadString('\n')
		c.t.Fatalf("expected ack, got %q %q (%v)", b, rest, err)
	}
}

func (c *scpClient) send(line string) { c.in.Write([]byte(line)) }

func (c *scpClient) file(name string, data []byte) {
	c.send(fmt.Sprintf("C0755 %d %s\n", len(data), name))
	c.ack()
	c.in.Write(data)
	c.in.Write([]byte{0})
	c.ack()
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestSCPUploadIsHashedNotKept(t *testing.T) {
	client, finish := dialRecordingSensor(t)
	payload := []byte("\x7fELF\x02\x01\x01 fake mirai payload")
	c := startSCP(t, client, "scp -t /tmp")
	c.file("x86", payload)
	c.in.Close()
	if err := c.sess.Wait(); err != nil {
		t.Errorf("scp exit: %v", err)
	}
	s := finish()

	if len(s.FileTransfers) != 1 {
		t.Fatalf("transfers = %+v", s.FileTransfers)
	}
	f := s.FileTransfers[0]
	if f.Method != session.TransferMethodSCP || f.Path != "/tmp/x86" || f.Size != int64(len(payload)) || f.SHA256 != sum(payload) || !f.Complete {
		t.Errorf("got %+v", f)
	}
	// The command itself is still logged like any exec.
	if len(s.Commands) != 1 || s.Commands[0].ParsedCommand != "scp" {
		t.Errorf("commands = %+v", parsedCommands(s))
	}
}

func TestSCPRecursiveUploadWithTimestamps(t *testing.T) {
	client, finish := dialRecordingSensor(t)
	c := startSCP(t, client, "scp -r -p -t /var/tmp")
	c.send("T1700000000 0 1700000000 0\n")
	c.ack()
	c.send("D0755 0 kit\n")
	c.ack()
	c.file("a.sh", []byte("echo a"))
	c.send("D0755 0 bin\n")
	c.ack()
	c.file("b", []byte("bbb"))
	c.send("E\n")
	c.ack()
	c.send("E\n")
	c.ack()
	c.in.Close()
	c.sess.Wait()
	s := finish()

	var paths []string
	for _, f := range s.FileTransfers {
		paths = append(paths, f.Path)
	}
	if strings.Join(paths, ",") != "/var/tmp/kit/a.sh,/var/tmp/kit/bin/b" {
		t.Errorf("paths = %v", paths)
	}
}

func TestSCPOversizedFileIsCutOff(t *testing.T) {
	client, finish := dialRecordingSensor(t)
	c := startSCP(t, client, "scp -t /tmp")
	c.send(fmt.Sprintf("C0644 %d big\n", scpMaxFileBytes+1))
	// Refused before any data moves, with scp's own disk-full error.
	if b, _ := c.out.ReadByte(); b != 2 {
		t.Errorf("got %q, want fatal error byte 0x02", b)
	}
	c.in.Close()
	c.sess.Wait()
	s := finish()

	if len(s.FileTransfers) != 1 {
		t.Fatalf("transfers = %+v", s.FileTransfers)
	}
	if f := s.FileTransfers[0]; f.Complete || f.Size != scpMaxFileBytes+1 || f.SHA256 != "" {
		t.Errorf("got %+v; want declared size, no hash, incomplete", f)
	}
}

func TestSCPProtocolErrorDoesNotHang(t *testing.T) {
	client, finish := dialRecordingSensor(t)
	c := startSCP(t, client, "scp -t /tmp")
	c.send("C0644 notanumber x\n")
	b, _ := c.out.ReadByte()
	if b != 1 {
		t.Errorf("got %q, want scp warning byte 0x01", b)
	}
	c.in.Close()
	c.sess.Wait()
	finish()
}

func TestNonSinkSCPStillGoesToTheShell(t *testing.T) {
	if _, ok := scpSinkTarget("scp -f /etc/passwd"); ok {
		t.Error("scp -f (download) treated as an upload sink")
	}
	if dir, ok := scpSinkTarget("scp -v -r -t -- /root/.ssh"); !ok || dir != "/root/.ssh" {
		t.Errorf("got %q, %v", dir, ok)
	}
	if _, ok := scpSinkTarget("echo scp -t /tmp"); ok {
		t.Error("non-scp command treated as scp")
	}
}
