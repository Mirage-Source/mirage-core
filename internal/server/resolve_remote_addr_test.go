package server

import (
	"net"
	"testing"

	"github.com/mirage-source/mirage-core/internal/proxyproto"
	"github.com/mirage-source/mirage-core/internal/session"
)

// resolveRemoteAddr is the only place that decides what ends up in
// Network.ClientIP/ClientPort/IngressSource/ProxyNodeID for a connection, so
// it's tested directly here rather than only indirectly through the
// higher-level accept loop.

func TestResolveRemoteAddrNilProxyConnUsesFallback(t *testing.T) {
	fallback := &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4444}

	addr, ingress, nodeID := resolveRemoteAddr(nil, fallback)
	if addr == nil || addr.String() != fallback.String() {
		t.Fatalf("got addr %v, want %v", addr, fallback)
	}
	if ingress != session.IngressSourceDirect {
		t.Fatalf("got ingress %q, want %q", ingress, session.IngressSourceDirect)
	}
	if nodeID != "" {
		t.Fatalf("got nodeID %q, want empty", nodeID)
	}
}

func TestResolveRemoteAddrNilProxyConnNonTCPFallback(t *testing.T) {
	// A non-TCP net.Addr (shouldn't happen for a real listener, but
	// resolveRemoteAddr must degrade safely rather than panic).
	fallback := &net.UnixAddr{Name: "not-tcp", Net: "unix"}

	addr, ingress, nodeID := resolveRemoteAddr(nil, fallback)
	if addr != nil {
		t.Fatalf("got addr %v, want nil", addr)
	}
	if ingress != session.IngressSourceDirect {
		t.Fatalf("got ingress %q, want %q", ingress, session.IngressSourceDirect)
	}
	if nodeID != "" {
		t.Fatalf("got nodeID %q, want empty", nodeID)
	}
}

func TestResolveRemoteAddrProxyHeaderFoundOverridesFallback(t *testing.T) {
	client, srv := net.Pipe()
	defer client.Close()
	defer srv.Close()

	go func() {
		client.Write([]byte("PROXY TCP4 198.51.100.7 sensor-7 33333 22\r\n"))
	}()

	pp := proxyproto.Wrap(srv)
	fallback := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 55}

	addr, ingress, nodeID := resolveRemoteAddr(pp, fallback)
	if addr == nil || addr.IP.String() != "198.51.100.7" || addr.Port != 33333 {
		t.Fatalf("got addr %v, want 198.51.100.7:33333", addr)
	}
	if ingress != session.IngressSourceProxied {
		t.Fatalf("got ingress %q, want %q", ingress, session.IngressSourceProxied)
	}
	if nodeID != "sensor-7" {
		t.Fatalf("got nodeID %q, want %q", nodeID, "sensor-7")
	}
}

func TestResolveRemoteAddrProxyConnNoHeaderFallsBackToRealPeer(t *testing.T) {
	client, srv := net.Pipe()
	defer client.Close()
	defer srv.Close()

	go func() {
		client.Write([]byte("SSH-2.0-OpenSSH_8.9\r\n"))
	}()

	pp := proxyproto.Wrap(srv)
	fallback := &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 66}

	addr, ingress, nodeID := resolveRemoteAddr(pp, fallback)
	if addr == nil || addr.String() != fallback.String() {
		t.Fatalf("got addr %v, want %v", addr, fallback)
	}
	if ingress != session.IngressSourceDirect {
		t.Fatalf("got ingress %q, want %q", ingress, session.IngressSourceDirect)
	}
	if nodeID != "" {
		t.Fatalf("got nodeID %q, want empty", nodeID)
	}
}
