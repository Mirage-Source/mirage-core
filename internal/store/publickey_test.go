package store_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/mirage-source/mirage-core/internal/session"
	"github.com/mirage-source/mirage-core/internal/store"
	"github.com/mirage-source/mirage-core/internal/validity"
)

const (
	offeredKey  = "ssh-ed25519 SHA256:publickey-isolation-test"
	kbdPassword = "kbd-interactive-test-pass"
)

// keySession is an SSH session whose client offered offeredKey n times
// (one row per key per connection in production; n just makes it outrank
// every real password) before failing.
func keySession(ip string, n int) *session.Session {
	s := newSession(session.ProtocolSSH, ip, "root", "unused", "echo")
	s.Network.SSHClientBanner = "SSH-2.0-publickey-test"
	s.AuthAttempts = nil
	now := time.Now().UnixMilli()
	for i := 0; i < n; i++ {
		s.AuthAttempts = append(s.AuthAttempts, session.AuthAttempt{
			TimestampMS: now + int64(i), Method: session.AuthMethodPublicKey,
			Username: "root", Credential: offeredKey, Success: false,
		})
	}
	return s
}

func TestPublicKeyAttemptsStayOutOfPasswordStats(t *testing.T) {
	db := connect(t)
	ips := []string{"198.51.100.31", "198.51.100.32", "198.51.100.33"}
	for _, ip := range ips {
		if err := store.SaveSession(db, keySession(ip, 500)); err != nil {
			t.Fatalf("saving: %v", err)
		}
	}

	kbd := keySession("198.51.100.34", 0)
	for i := 0; i < 500; i++ {
		kbd.AuthAttempts = append(kbd.AuthAttempts, session.AuthAttempt{
			TimestampMS: kbd.Timing.StartMS + int64(i), Method: session.AuthMethodKeyboardInteractive,
			Username: "root", Credential: kbdPassword,
		})
	}
	if err := store.SaveSession(db, kbd); err != nil {
		t.Fatal(err)
	}

	stats, err := store.GetStats(db, session.ProtocolSSH)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range stats.TopPasswords {
		if p.Password == offeredKey {
			t.Errorf("key fingerprint in TopPasswords")
		}
	}
	foundKbd := false
	for _, p := range stats.TopPasswords {
		foundKbd = foundKbd || p.Password == kbdPassword
	}
	if !foundKbd {
		t.Errorf("keyboard-interactive answer missing from TopPasswords")
	}
	for _, c := range stats.TopCredentials {
		if c.Password == offeredKey {
			t.Errorf("key fingerprint in TopCredentials")
		}
	}

	// The same key from several IPs in one window is exactly what the
	// coordinated-IP view exists to surface, so keys stay in that one.
	found := false
	for _, g := range stats.CoordinatedIPs {
		found = found || g.Credential == offeredKey
	}
	if !found {
		t.Errorf("shared key across %d IPs missing from CoordinatedIPs", len(ips))
	}

	_, pairs, err := validity.FetchCampaignInputs(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range ips {
		for p := range pairs[ip] {
			if p.Credential == offeredKey {
				t.Errorf("%s: key fingerprint in campaign credential pairs: %s", ip, fmt.Sprint(p))
			}
		}
	}
}
