package server

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/mirage-source/mirage-core/internal/fleet"
	"github.com/mirage-source/mirage-core/internal/session"
	"golang.org/x/crypto/ssh"
)

// A session that keeps sending commands must stay writable past idleTimeout.
// Regression test: handleConnection used to set a write deadline once and
// never refresh it, so every session died idleTimeout after the handshake no
// matter how active it was, and was recorded as connection_reset with a
// truncated duration.
func TestWritesSurviveAnActiveSessionPastIdleTimeout(t *testing.T) {
	const idleTimeout = 700 * time.Millisecond
	const commands = 5
	const gap = 250 * time.Millisecond // 5 * 250ms = 1.25s, well past idleTimeout

	addr := startDeadlineTestSensor(t, idleTimeout)

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password("root")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dialing test sensor: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("opening session: %v", err)
	}
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("starting shell: %v", err)
	}

	lines := make(chan string, 64)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(stdout)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()

	start := time.Now()
	for i := 0; i < commands; i++ {
		time.Sleep(gap)
		want := fmt.Sprintf("marker-%d", i)
		if _, err := fmt.Fprintf(stdin, "echo %s\n", want); err != nil {
			t.Fatalf("command %d: client could not write after %v: %v", i, time.Since(start), err)
		}
		if err := awaitLine(lines, want, 2*time.Second); err != nil {
			t.Fatalf("command %d after %v: %v", i, time.Since(start).Round(10*time.Millisecond), err)
		}
	}

	if elapsed := time.Since(start); elapsed < idleTimeout {
		t.Fatalf("test finished in %v, which never crossed idleTimeout %v", elapsed, idleTimeout)
	}
}

// The other half of the same fix: refreshing deadlines on activity must not
// stop an idle connection being dropped.
func TestIdleSessionStillTimesOut(t *testing.T) {
	const idleTimeout = 400 * time.Millisecond

	addr := startDeadlineTestSensor(t, idleTimeout)

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password("root")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dialing test sensor: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("opening session: %v", err)
	}
	if _, err := sess.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("starting shell: %v", err)
	}

	done := make(chan struct{})
	go func() { sess.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("an idle session was never dropped; the idle timeout is not firing")
	}
}

// awaitLine waits for the shell's response to one command, ignoring the
// server's character echo of the command itself.
func awaitLine(lines <-chan string, want string, timeout time.Duration) error {
	deadline := time.After(timeout)
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				return fmt.Errorf("server stopped writing before %q arrived (write deadline was not refreshed)", want)
			}
			if strings.TrimSpace(stripPrompt(line)) == want {
				return nil
			}
		case <-deadline:
			return fmt.Errorf("no %q within %v", want, timeout)
		}
	}
}

// The prompt carries no newline, so it shares a line with what follows it.
func stripPrompt(line string) string {
	if i := strings.LastIndex(line, "$ "); i >= 0 {
		return line[i+2:]
	}
	if i := strings.LastIndex(line, "# "); i >= 0 {
		return line[i+2:]
	}
	return line
}

// startDeadlineTestSensor runs handleConnection against a real TCP listener,
// bypassing Start (which log.Fatals without a host key file and a live
// Postgres). The DB handle is deliberately unreachable: SaveSession's failure
// is logged, not fatal, and this test is about the connection, not the store.
func startDeadlineTestSensor(t *testing.T, idleTimeout time.Duration) string {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "deadline-test")
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.ParsePrivateKey(pem.EncodeToMemory(block))
	if err != nil {
		t.Fatal(err)
	}

	config := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() == "root" && string(password) == "root" {
				return nil, nil
			}
			return nil, fmt.Errorf("invalid credentials")
		},
	}
	config.AddHostKey(hostKey)

	db, err := sql.Open("postgres", "host=127.0.0.1 port=1 user=none dbname=none sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			guard := &sessionGuard{sess: &session.Session{
				SessionID:  uuid.New().String(),
				Protocol:   session.ProtocolSSH,
				Outcome:    session.OutcomeActive,
				BaitEvents: []session.BaitEvent{},
				Timing:     session.Timing{StartMS: time.Now().UnixMilli()},
			}}
			// Disabled fleet client: no baseURL/apiKey makes every method a no-op.
			go handleConnection(conn, config, guard, db, idleTimeout, 5*time.Second, nil, fleet.NewClient("", "", time.Second, nil))
		}
	}()

	return listener.Addr().String()
}
