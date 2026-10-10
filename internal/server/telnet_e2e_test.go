package server

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEndToEndTelnetSessionPersistsToDatabase(t *testing.T) {
	if os.Getenv("MIRAGE_E2E_TEST") == "" {
		t.Skip("set MIRAGE_E2E_TEST=1 against a reachable, migrated Postgres to run this test (see .github/workflows/go-tests.yml's e2e-test job)")
	}
	db := connectTestDB(t)

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config", "telnet_weak_credentials.txt"), []byte("root:e2e-telnet-pass\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	testStart := time.Now().UnixMilli()
	const addr = "127.0.0.1:32323"
	go StartTelnet(addr)
	waitForListener(t, addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("root\r\ne2e-telnet-pass\r\n/bin/busybox E2EPROBE\r\nexit\r\n"))
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 4096)
	for {
		if _, err := conn.Read(buf); err != nil {
			break
		}
	}
	conn.Close()

	var sessionID string
	var commandCount int
	var banner string
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := db.QueryRow(`
			SELECT session_id, command_count, ssh_client_banner FROM sessions
			WHERE protocol = 'telnet' AND client_ip = '127.0.0.1' AND start_ms >= $1
			ORDER BY start_ms DESC LIMIT 1`, testStart).Scan(&sessionID, &commandCount, &banner)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no telnet session row within 5s: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if commandCount != 2 || banner != "" {
		t.Errorf("command_count = %d, banner = %q; want 2, \"\"", commandCount, banner)
	}

	var response string
	if err := db.QueryRow(`
		SELECT response_text FROM commands
		WHERE session_id = $1 AND parsed_command = 'busybox'`, sessionID).Scan(&response); err != nil {
		t.Fatalf("busybox command row: %v", err)
	}
	if response != "E2EPROBE: applet not found" {
		t.Errorf("stored response = %q", response)
	}

	var negotiated bool
	if err := db.QueryRow(`SELECT negotiated FROM telnet_session_meta WHERE session_id = $1`, sessionID).Scan(&negotiated); err != nil {
		t.Fatalf("telnet_session_meta row: %v", err)
	}
	if negotiated {
		t.Error("negotiated = true for a raw-socket client")
	}

	var heartbeats int
	db.QueryRow(`SELECT COUNT(*) FROM sensor_heartbeats WHERE sensor_id = 'telnet'`).Scan(&heartbeats)
	if heartbeats == 0 {
		t.Error("no heartbeat row for sensor_id 'telnet'")
	}
}
