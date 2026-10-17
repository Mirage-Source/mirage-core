package server

import (
	"database/sql"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mirage-source/mirage-core/internal/fleet"
	"github.com/mirage-source/mirage-core/internal/session"
	"golang.org/x/crypto/ssh"
)

// dialRecordingSensor runs one connection through handleConnection and
// returns a logged-in client plus a func that closes it and hands back the
// session once the server side has finished.
func dialRecordingSensor(t *testing.T) (*ssh.Client, func() *session.Session) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	db, err := sql.Open("postgres", "host=127.0.0.1 port=1 user=none dbname=none sslmode=disable")
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
		authDelay: func() time.Duration { return 0 },
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

	client, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password("root")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client, func() *session.Session {
		client.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("server side did not finish")
		}
		return sess
	}
}

func TestDirectTCPIPIsRecordedWithItsTarget(t *testing.T) {
	client, finish := dialRecordingSensor(t)

	// What `ssh -W smtp.example.com:25` or a proxy-checking bot sends.
	if _, err := client.Dial("tcp", "smtp.example.com:25"); err == nil {
		t.Fatal("forwarding must stay refused")
	}
	s := finish()

	if len(s.RejectedRequests) != 1 {
		t.Fatalf("rejected requests = %+v", s.RejectedRequests)
	}
	r := s.RejectedRequests[0]
	if r.Kind != session.RejectedKindChannel || r.Type != "direct-tcpip" || r.Detail != "smtp.example.com:25" || r.TimestampMS == 0 {
		t.Errorf("got %+v", r)
	}
}

func TestUnknownChannelTypeIsRecorded(t *testing.T) {
	client, finish := dialRecordingSensor(t)
	if _, _, err := client.OpenChannel("x11", []byte("junk")); err == nil {
		t.Fatal("x11 channel must be refused")
	}
	s := finish()

	if len(s.RejectedRequests) != 1 || s.RejectedRequests[0].Type != "x11" || s.RejectedRequests[0].Detail != "" {
		t.Errorf("rejected requests = %+v", s.RejectedRequests)
	}
}

func TestSFTPSubsystemIsRecordedAndRefused(t *testing.T) {
	client, finish := dialRecordingSensor(t)
	sshSess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sshSess.RequestSubsystem("sftp"); err == nil {
		t.Error("sftp subsystem must be refused")
	}
	s := finish()

	if len(s.RejectedRequests) != 1 {
		t.Fatalf("rejected requests = %+v", s.RejectedRequests)
	}
	if r := s.RejectedRequests[0]; r.Kind != session.RejectedKindSubsystem || r.Type != "sftp" {
		t.Errorf("got %+v", r)
	}
}

// Refused channels cost the server nothing, so nothing limited them. Once
// each one is stored, an uncapped list would let one connection grow the
// session without bound.
func TestRejectedRequestsAreCappedAndTruncated(t *testing.T) {
	client, finish := dialRecordingSensor(t)
	longHost := strings.Repeat("a", 5000)
	for i := 0; i < maxRejectedRequests+50; i++ {
		client.Dial("tcp", net.JoinHostPort(longHost, "80"))
	}
	s := finish()

	if len(s.RejectedRequests) != maxRejectedRequests {
		t.Errorf("stored %d, want cap %d", len(s.RejectedRequests), maxRejectedRequests)
	}
	if d := s.RejectedRequests[0].Detail; len(d) > maxRejectedDetailBytes {
		t.Errorf("detail is %d bytes, want at most %d", len(d), maxRejectedDetailBytes)
	}
}
