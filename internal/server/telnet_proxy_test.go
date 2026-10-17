package server

import (
	"net"
	"testing"

	"github.com/mirage-source/mirage-core/internal/proxyproto"
	"github.com/mirage-source/mirage-core/internal/session"
)

// startTelnetProxyHarness is startTelnetHarness with the listener-side
// connection wrapped the way StartTelnet wraps it when
// TELNET_TRUST_PROXY_PROTOCOL is on.
func startTelnetProxyHarness(t *testing.T, cfg telnetConfig) *telnetHarness {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	h := &telnetHarness{t: t, done: make(chan struct{})}
	h.guard = &sessionGuard{sess: newTelnetSession()}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		pp := proxyproto.Wrap(conn)
		handleTelnet(pp, cfg, h.guard)
		pp.Close()
		close(h.done)
	}()

	h.client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.client.Close() })
	return h
}

func loginAndExit(h *telnetHarness) *session.Session {
	h.readUntil("login: ")
	h.send([]byte("root\r\n"))
	h.readUntil("Password: ")
	h.send([]byte("xc3511\r\n"))
	h.readUntil("# ")
	h.send([]byte("exit\r\n"))
	h.readUntil("logout")
	return h.wait()
}

func TestTelnetTrustedProxyHeaderSetsRealSource(t *testing.T) {
	h := startTelnetProxyHarness(t, testTelnetConfig())
	// The shim writes the header the moment it connects, before reading.
	h.send([]byte("PROXY TCP4 203.0.113.9 198.51.100.7 51515 2323\r\n"))
	s := loginAndExit(h)

	if s.Network.ClientIP != "203.0.113.9" || s.Network.ClientPort != 51515 {
		t.Errorf("client = %s:%d, want 203.0.113.9:51515", s.Network.ClientIP, s.Network.ClientPort)
	}
	if s.Network.IngressSource != session.IngressSourceProxied {
		t.Errorf("ingress = %q, want proxied", s.Network.IngressSource)
	}
	if s.Network.ProxyNodeID != "198.51.100.7" {
		t.Errorf("proxy node = %q", s.Network.ProxyNodeID)
	}
	// The header line must never surface as a username.
	if len(s.AuthAttempts) != 1 || s.AuthAttempts[0].Username != "root" {
		t.Errorf("auth attempts = %+v", s.AuthAttempts)
	}
}

func TestTelnetTrustedListenerWithoutHeaderFallsBackToPeer(t *testing.T) {
	h := startTelnetProxyHarness(t, testTelnetConfig())
	// A raw bot that waits for "login:" must not stall on header detection.
	s := loginAndExit(h)

	if s.Network.ClientIP != "127.0.0.1" || s.Network.IngressSource != session.IngressSourceDirect || s.Network.ProxyNodeID != "" {
		t.Errorf("network = %+v, want direct 127.0.0.1", s.Network)
	}
}

func TestTelnetUntrustedListenerIgnoresProxyHeader(t *testing.T) {
	h := startTelnetHarness(t, testTelnetConfig())
	h.readUntil("login: ")
	h.send([]byte("PROXY TCP4 203.0.113.9 198.51.100.7 51515 2323\r\n"))
	h.readUntil("Password: ")
	h.send([]byte("x\r\n"))
	h.client.Close()
	s := h.wait()

	if s.Network.ClientIP != "127.0.0.1" || s.Network.IngressSource != session.IngressSourceDirect {
		t.Errorf("network = %+v, want the header ignored", s.Network)
	}
}
