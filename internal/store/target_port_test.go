package store_test

import (
	"testing"

	"github.com/mirage-source/mirage-core/internal/session"
	"github.com/mirage-source/mirage-core/internal/store"
)

func TestTargetPortPersists(t *testing.T) {
	db := connect(t)
	proxied := newSession(session.ProtocolSSH, "198.51.100.51", "root", "root", "echo")
	proxied.Network.SSHClientBanner = "SSH-2.0-target-port-test"
	proxied.Network.IngressSource = session.IngressSourceProxied
	proxied.Network.ProxyNodeID = "node-1"
	proxied.Network.TargetPort = 2222
	proxied.Network.HASSH = "ec7378c1a92f5a8dde7e8b7a1ddf33d1"
	proxied.Network.HASSHAlgorithms = "curve25519-sha256;aes128-ctr;hmac-sha2-256;none"
	direct := newSession(session.ProtocolSSH, "198.51.100.52", "root", "root", "echo")
	direct.Network.SSHClientBanner = "SSH-2.0-target-port-test"

	for _, s := range []*session.Session{proxied, direct} {
		if err := store.SaveSession(db, s); err != nil {
			t.Fatal(err)
		}
	}
	var got *int
	db.QueryRow(`SELECT target_port FROM sessions WHERE session_id = $1`, proxied.SessionID).Scan(&got)
	if got == nil || *got != 2222 {
		t.Errorf("proxied target_port = %v, want 2222", got)
	}
	var hassh, algos string
	db.QueryRow(`SELECT hassh, hassh_algorithms FROM sessions WHERE session_id = $1`, proxied.SessionID).Scan(&hassh, &algos)
	if hassh != proxied.Network.HASSH || algos != proxied.Network.HASSHAlgorithms {
		t.Errorf("hassh = %q / %q", hassh, algos)
	}
	got = nil
	db.QueryRow(`SELECT target_port FROM sessions WHERE session_id = $1`, direct.SessionID).Scan(&got)
	if got != nil {
		t.Errorf("direct target_port = %d, want NULL (unknown, not port 0)", *got)
	}
}
