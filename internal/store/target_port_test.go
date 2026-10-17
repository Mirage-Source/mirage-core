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
	got = nil
	db.QueryRow(`SELECT target_port FROM sessions WHERE session_id = $1`, direct.SessionID).Scan(&got)
	if got != nil {
		t.Errorf("direct target_port = %d, want NULL (unknown, not port 0)", *got)
	}
}
