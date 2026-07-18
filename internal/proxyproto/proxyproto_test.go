package proxyproto

import (
	"io"
	"net"
	"testing"
	"time"
)

// tcpPipe returns a connected client/server *net.TCPConn pair over real
// loopback TCP, so RemoteAddr() on either side is a genuine *net.TCPAddr --
// unlike net.Pipe(), whose endpoints don't implement that, and this package
// specifically cares about TCPAddr fallback behavior.
func tcpPipe(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	acceptCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		acceptCh <- c
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	select {
	case server = <-acceptCh:
	case err := <-errCh:
		t.Fatalf("accept: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for accept")
	}
	return client, server
}

func TestValidHeaderParses(t *testing.T) {
	client, server := tcpPipe(t)
	defer client.Close()
	defer server.Close()

	go func() {
		client.Write([]byte("PROXY TCP4 203.0.113.5 198.51.100.1 41000 22\r\nhello"))
	}()

	c := Wrap(server)

	addr, dstRaw, found := c.RealRemoteAddr()
	if !found {
		t.Fatalf("expected header to be found")
	}
	if addr.IP.String() != "203.0.113.5" || addr.Port != 41000 {
		t.Fatalf("got addr %v, want 203.0.113.5:41000", addr)
	}
	if dstRaw != "198.51.100.1" {
		t.Fatalf("got dst-ip field %q, want %q", dstRaw, "198.51.100.1")
	}

	// The payload after the header line must still come through untouched
	// on subsequent reads -- the header itself is never handed to the caller.
	buf := make([]byte, 5)
	n, err := io.ReadFull(c, buf)
	if err != nil {
		t.Fatalf("read after header: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("got payload %q, want %q", buf[:n], "hello")
	}
}

func TestMissingHeaderFallsBackToRealPeerAddress(t *testing.T) {
	client, server := tcpPipe(t)
	defer client.Close()
	defer server.Close()

	payload := "SSH-2.0-OpenSSH_8.9\r\n"
	go func() {
		client.Write([]byte(payload))
	}()

	c := Wrap(server)

	addr, dstRaw, found := c.RealRemoteAddr()
	if found {
		t.Fatalf("expected no header to be found, got addr=%v dstRaw=%q", addr, dstRaw)
	}
	if addr != nil {
		t.Fatalf("expected nil addr when not found, got %v", addr)
	}

	// Real fallback address is whatever the caller reads off the wrapped
	// conn directly -- this package doesn't invent one when nothing was
	// found, it just doesn't consume anything so the real value round-trips.
	realAddr, ok := server.RemoteAddr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected *net.TCPAddr from real loopback conn")
	}
	if realAddr.IP.String() != "127.0.0.1" {
		t.Fatalf("sanity check failed: %v", realAddr)
	}

	// And the payload -- including the leading "PROXY"-shaped-looking-but-
	// isn't bytes -- must come through completely unconsumed.
	buf := make([]byte, len(payload))
	n, err := io.ReadFull(c, buf)
	if err != nil {
		t.Fatalf("read after non-header: %v", err)
	}
	if string(buf[:n]) != payload {
		t.Fatalf("got %q, want %q", buf[:n], payload)
	}
}

func TestMalformedProxyLineFallsBackSafely(t *testing.T) {
	client, server := tcpPipe(t)
	defer client.Close()
	defer server.Close()

	// Starts with "PROXY " (so it passes the cheap prefix check) but isn't a
	// valid TCP4 line -- must not be treated as found, and must not corrupt
	// the byte stream for whatever tries to parse it next.
	payload := "PROXY UNKNOWN\r\nnext"
	go func() {
		client.Write([]byte(payload))
	}()

	c := Wrap(server)

	_, _, found := c.RealRemoteAddr()
	if found {
		t.Fatalf("expected malformed/unsupported PROXY line to not be treated as found")
	}

	buf := make([]byte, len(payload))
	n, err := io.ReadFull(c, buf)
	if err != nil {
		t.Fatalf("read after malformed header: %v", err)
	}
	if string(buf[:n]) != payload {
		t.Fatalf("got %q, want %q (bytes must be untouched)", buf[:n], payload)
	}
}

// trickleConn wraps a net.Conn but hands back at most one byte per Read
// call, regardless of the caller's buffer size -- simulating a slow/
// fragmented TCP delivery where the whole header doesn't arrive in one
// underlying Read.
type trickleConn struct {
	net.Conn
}

func (t trickleConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	one := b[:1]
	return t.Conn.Read(one)
}

func TestTrickledReadsStillParse(t *testing.T) {
	client, server := tcpPipe(t)
	defer client.Close()
	defer server.Close()

	go func() {
		client.Write([]byte("PROXY TCP4 203.0.113.5 198.51.100.1 41000 22\r\nhello"))
	}()

	c := Wrap(trickleConn{server})

	addr, dstRaw, found := c.RealRemoteAddr()
	if !found {
		t.Fatalf("expected header to be found even with byte-at-a-time delivery")
	}
	if addr.IP.String() != "203.0.113.5" || addr.Port != 41000 {
		t.Fatalf("got addr %v, want 203.0.113.5:41000", addr)
	}
	if dstRaw != "198.51.100.1" {
		t.Fatalf("got dst-ip field %q, want %q", dstRaw, "198.51.100.1")
	}

	buf := make([]byte, 5)
	n, err := io.ReadFull(c, buf)
	if err != nil {
		t.Fatalf("read after header: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("got payload %q, want %q", buf[:n], "hello")
	}
}
