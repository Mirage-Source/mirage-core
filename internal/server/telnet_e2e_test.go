package server

import (
	"bytes"
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

// The most common Mirai architecture probe returns an ELF header full of NUL
// bytes. The attacker must receive it on the wire and the session must still
// reach Postgres; before the fix it was dropped with pq 22P05.
func TestEndToEndTelnetELFProbeSessionPersists(t *testing.T) {
	if os.Getenv("MIRAGE_E2E_TEST") == "" {
		t.Skip("set MIRAGE_E2E_TEST=1 against a reachable, migrated Postgres to run this test")
	}
	db := connectTestDB(t)

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config", "telnet_weak_credentials.txt"), []byte("root:elf-probe-pass\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	testStart := time.Now().UnixMilli()
	const addr = "127.0.0.1:32324"
	go StartTelnet(addr)
	waitForListener(t, addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("root\r\nelf-probe-pass\r\n/bin/busybox cat /proc/self/exe || cat /proc/self/exe\r\nexit\r\n"))
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var wire []byte
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		wire = append(wire, buf[:n]...)
		if err != nil {
			break
		}
	}
	conn.Close()
	// ELF32, little-endian, then e_machine 0x28 (ARM) at offset 18: the DVR's armv7l.
	i := bytes.Index(wire, []byte("\x7fELF\x01\x01\x01\x00"))
	if i < 0 || len(wire) < i+20 || wire[i+18] != 0x28 {
		t.Errorf("attacker did not receive the ARM ELF header; wire = %q", wire)
	}

	var commandCount int
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := db.QueryRow(`
			SELECT command_count FROM sessions
			WHERE protocol = 'telnet' AND client_ip = '127.0.0.1' AND start_ms >= $1
			  AND session_document::text LIKE '%proc/self/exe%'
			ORDER BY start_ms DESC LIMIT 1`, testStart).Scan(&commandCount)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ELF-probe session never reached Postgres: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if commandCount != 2 {
		t.Errorf("command_count = %d, want 2", commandCount)
	}
}
