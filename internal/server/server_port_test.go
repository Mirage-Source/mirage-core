package server

import (
	"database/sql"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/mirage-source/mirage-core/internal/fleet"
	"github.com/mirage-source/mirage-core/internal/session"
)

// runOneConnection serves exactly one SSH connection with a real client and returns the
// session as handleConnection left it, plus the port the listener was bound to.
func runOneConnection(t *testing.T, password string) (*session.Session, int, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	db, err := sql.Open("postgres", "host=127.0.0.1 port=1 user=none dbname=none sslmode=disable") // saves fail; irrelevant here
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	sess := &session.Session{
		SessionID:  uuid.New().String(),
		Protocol:   session.ProtocolSSH,
		Outcome:    session.OutcomeActive,
		BaitEvents: []session.BaitEvent{},
		Timing:     session.Timing{StartMS: time.Now().UnixMilli()},
	}
	cfg := newSSHServerConfig(sess, nil, sshAuthConfig{
		weakCreds: map[string]struct{}{"root:root": {}},
		authDelay: func(string, bool) time.Duration { return 0 },
	}, testSigner(t))
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		handleConnection(c, cfg, &sessionGuard{sess: sess}, db, 5*time.Second, 5*time.Second, nil, fleet.NewClient("", "", time.Second, nil))
	}()

	client, dialErr := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if client != nil {
		client.Close()
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server side did not finish")
	}
	return sess, ln.Addr().(*net.TCPAddr).Port, dialErr
}

// server_port used to be written only after a successful handshake, so it was 0 on exactly the
// sessions that ended auth_failed and the listener's port otherwise: the outcome label leaked into
// a feature. Every session records the port it was accepted on, whatever happens next.
func TestServerPortDoesNotDependOnTheOutcome(t *testing.T) {
	rejected, portA, err := runOneConnection(t, "wrong-password")
	if err == nil {
		t.Fatal("a wrong password must fail the handshake")
	}
	accepted, portB, err := runOneConnection(t, "root")
	if err != nil {
		t.Fatal(err)
	}
	if rejected.Outcome != session.OutcomeAuthFailed {
		t.Fatalf("rejected session outcome = %q, want auth_failed", rejected.Outcome)
	}
	if rejected.Network.ServerPort != portA {
		t.Errorf("auth_failed server_port = %d, want the listener port %d", rejected.Network.ServerPort, portA)
	}
	if accepted.Network.ServerPort != portB {
		t.Errorf("accepted server_port = %d, want the listener port %d", accepted.Network.ServerPort, portB)
	}
}
