package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/ssh"
)

// TestEndToEndSSHSessionPersistsToDatabase drives the real thing end to end:
// a real TCP listener started by Start (the exact function cmd/mirage/main.go
// calls), a real golang.org/x/crypto/ssh client dialing it and authenticating
// with a weak credential, a real interactive shell session, and a real
// Postgres row read back afterward -- the class of bug unit tests of the
// pieces (internal/shell, internal/store in isolation) cannot catch, e.g. the
// exec-vs-shell channel-type dispatch in handleSessionRequests.
//
// Skipped unless MIRAGE_E2E_TEST is set, since Start fatals the whole test
// binary (log.Fatal, not a returned error) on any setup problem -- reading
// config/hostkey, connecting to Postgres, binding the listener. That's
// correct behavior for a real server process, but means this test must only
// run in an environment (see .github/workflows/go-tests.yml's e2e-test job)
// where every one of those prerequisites is known-good: a reachable, fully
// migrated Postgres via DB_HOST/DB_PORT/DB_USER/DB_PASSWORD/DB_NAME. A
// default `go test ./...` run skips this harmlessly.
func TestEndToEndSSHSessionPersistsToDatabase(t *testing.T) {
	if os.Getenv("MIRAGE_E2E_TEST") == "" {
		t.Skip("set MIRAGE_E2E_TEST=1 against a reachable, migrated Postgres to run this test (see .github/workflows/go-tests.yml's e2e-test job)")
	}

	db := connectTestDB(t)
	addr, testUser, testPass := startTestSensor(t, "127.0.0.1:32222")

	config := &ssh.ClientConfig{
		User:            testUser,
		Auth:            []ssh.AuthMethod{ssh.Password(testPass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		t.Fatalf("dialing real sensor: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("opening session: %v", err)
	}
	defer sess.Close()

	if err := sess.RequestPty("xterm", 40, 120, ssh.TerminalModes{}); err != nil {
		t.Fatalf("requesting pty: %v", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("starting shell: %v", err)
	}

	const marker = "e2e-marker-file"
	fmt.Fprintf(stdin, "echo %s\n", marker)
	fmt.Fprintf(stdin, "whoami\n")
	fmt.Fprintf(stdin, "exit\n")

	done := make(chan struct{})
	go func() { sess.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("session did not finish within 10s")
	}
	client.Close()

	// Start's own handleChannels->finalize only runs once every channel on
	// the connection has finished and the goroutine has had a chance to
	// call SaveSession -- give that a moment to land rather than racing it.
	var (
		clientIP     string
		commandCount int
	)
	deadline := time.Now().Add(5 * time.Second)
	for {
		row := db.QueryRow(
			`SELECT client_ip, command_count FROM sessions
			 WHERE client_ip = '127.0.0.1' AND command_count > 0
			 ORDER BY start_ms DESC LIMIT 1`,
		)
		err := row.Scan(&clientIP, &commandCount)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no session row appeared in Postgres within 5s: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	if clientIP != "127.0.0.1" {
		t.Errorf("client_ip = %q, want 127.0.0.1", clientIP)
	}
	if commandCount < 2 {
		t.Errorf("command_count = %d, want at least 2 (echo, whoami)", commandCount)
	}

	var rawInputB64, parsedCommand string
	err = db.QueryRow(
		`SELECT raw_input_b64, parsed_command FROM commands
		 WHERE session_id = (
		     SELECT session_id FROM sessions
		     WHERE client_ip = '127.0.0.1' AND command_count > 0
		     ORDER BY start_ms DESC LIMIT 1
		 ) AND parsed_command = 'echo'
		 LIMIT 1`,
	).Scan(&rawInputB64, &parsedCommand)
	if err != nil {
		t.Fatalf("expected an 'echo' command row: %v", err)
	}
	if parsedCommand != "echo" {
		t.Errorf("parsed_command = %q, want \"echo\"", parsedCommand)
	}
}

func connectTestDB(t *testing.T) *sql.DB {
	t.Helper()
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"),
	)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		t.Fatalf("opening test DB: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("pinging test DB (is it migrated and reachable? DB_HOST=%q DB_PORT=%q): %v",
			os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// startTestSensor sets up a throwaway config/ dir (hostkey + one weak
// credential), chdirs into it (Start reads "config/hostkey" as a relative
// path, unconditionally), and starts a real Start(addr) in the background.
// Returns the address plus the one credential it seeded, once the listener
// is confirmed up.
func startTestSensor(t *testing.T, addr string) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeThrowawayHostKey(t, filepath.Join(dir, "config", "hostkey"))
	const testUser, testPass = "e2euser", "e2epass"
	if err := os.WriteFile(
		filepath.Join(dir, "config", "weak_credentials.txt"),
		[]byte(testUser+":"+testPass+"\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	go Start(addr)
	waitForListener(t, addr)
	return addr, testUser, testPass
}

func writeThrowawayHostKey(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "e2e-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := (&net.Dialer{Timeout: 200 * time.Millisecond}).Dial("tcp", addr)
		if err == nil {
			conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("sensor never started listening on %s within 5s: %v", addr, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
