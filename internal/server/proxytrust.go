package server

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/mirage-source/mirage-core/internal/proxyproto"
)

// proxyTrust decides, per connection, whether a PROXY header is believed.
// Trusting headers from every peer lets anyone who reaches the port claim
// any source IP, so peers can be limited to the relay's addresses.
type proxyTrust struct {
	enabled bool
	peers   []*net.IPNet // empty: every peer is trusted (the pre-allowlist behaviour)
}

// loadProxyTrust reads the sensor's own enable flag and the shared
// PROXY_TRUSTED_PEERS allowlist. A malformed allowlist is fatal: silently
// dropping an entry could leave the relay untrusted or, worse, widen trust.
func loadProxyTrust(flagEnv string) proxyTrust {
	p, err := parseProxyTrust(envBool(flagEnv, false), os.Getenv("PROXY_TRUSTED_PEERS"))
	if err != nil {
		log.Fatalf("PROXY_TRUSTED_PEERS: %v", err)
	}
	switch {
	case !p.enabled:
	case len(p.peers) == 0:
		log.Printf("WARNING: %s=true with no PROXY_TRUSTED_PEERS: any client can forge its source IP", flagEnv)
	default:
		log.Printf("%s=true; trusting PROXY headers only from %v", flagEnv, p.peers)
	}
	return p
}

// parseProxyTrust parses a comma-separated list of IPs and CIDRs.
func parseProxyTrust(enabled bool, peers string) (proxyTrust, error) {
	p := proxyTrust{enabled: enabled}
	for _, raw := range strings.Split(peers, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				return proxyTrust{}, fmt.Errorf("invalid IP %q", entry)
			}
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			entry = fmt.Sprintf("%s/%d", entry, bits)
		}
		_, n, err := net.ParseCIDR(entry)
		if err != nil {
			return proxyTrust{}, fmt.Errorf("invalid CIDR %q", entry)
		}
		p.peers = append(p.peers, n)
	}
	return p, nil
}

func (p proxyTrust) allows(addr net.Addr) bool {
	if !p.enabled {
		return false
	}
	if len(p.peers) == 0 {
		return true
	}
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return false
	}
	for _, n := range p.peers {
		if n.Contains(tcp.IP) {
			return true
		}
	}
	return false
}

// wrap returns conn wrapped in a *proxyproto.Conn when its peer may send a
// header, and conn unchanged otherwise. Wrap does no I/O, so this never
// blocks the accept loop.
func (p proxyTrust) wrap(conn net.Conn) net.Conn {
	if p.allows(conn.RemoteAddr()) {
		return proxyproto.Wrap(conn)
	}
	return conn
}
