package server

import (
	"io"
	"net"
	"testing"

	"github.com/mirage-source/mirage-core/internal/proxyproto"
)

func loopbackPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		ch <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-ch
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

func mustTrust(t *testing.T, enabled bool, peers string) proxyTrust {
	t.Helper()
	p, err := parseProxyTrust(enabled, peers)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const forged = "PROXY TCP4 203.0.113.66 198.51.100.1 4444 22\r\n"

func TestForgedHeaderFromUnlistedPeerIsIgnored(t *testing.T) {
	client, server := loopbackPair(t)
	go client.Write([]byte(forged))

	conn := mustTrust(t, true, "10.8.0.0/24, 192.0.2.7").wrap(server)
	if _, ok := conn.(*proxyproto.Conn); ok {
		t.Fatal("connection from 127.0.0.1 was trusted with an allowlist that excludes it")
	}
	// The header bytes reach the protocol handler untouched, where they are
	// just a malformed banner or login line.
	buf := make([]byte, len(forged))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != forged {
		t.Fatalf("read %q, %v", buf, err)
	}
}

func TestHeaderFromListedPeerIsHonoured(t *testing.T) {
	client, server := loopbackPair(t)
	go client.Write([]byte(forged))

	pp, ok := mustTrust(t, true, "127.0.0.1").wrap(server).(*proxyproto.Conn)
	if !ok {
		t.Fatal("listed peer not trusted")
	}
	if a, _, found := pp.RealRemoteAddr(); !found || a.IP.String() != "203.0.113.66" {
		t.Fatalf("got %v, %v", a, found)
	}
}

func TestTrustDisabledNeverWraps(t *testing.T) {
	_, server := loopbackPair(t)
	if _, ok := mustTrust(t, false, "127.0.0.1").wrap(server).(*proxyproto.Conn); ok {
		t.Fatal("wrapped with trust disabled")
	}
}

func TestEmptyAllowlistKeepsTrustAllBehaviour(t *testing.T) {
	_, server := loopbackPair(t)
	if _, ok := mustTrust(t, true, "").wrap(server).(*proxyproto.Conn); !ok {
		t.Fatal("enabled with no allowlist should trust every peer, as before")
	}
}

func TestBadAllowlistEntryIsAnError(t *testing.T) {
	if _, err := parseProxyTrust(true, "10.0.0.0/8, not-an-ip"); err == nil {
		t.Fatal("expected an error for a malformed entry")
	}
}

func TestIPv6PeerAllowlist(t *testing.T) {
	p := mustTrust(t, true, "fd00::/8")
	if !p.allows(&net.TCPAddr{IP: net.ParseIP("fd00::1")}) || p.allows(&net.TCPAddr{IP: net.ParseIP("2001:db8::1")}) {
		t.Fatal("IPv6 CIDR matching is wrong")
	}
}
