package server

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/mirage-source/mirage-core/internal/session"
)

func payload(t *testing.T, s *session.Session) []byte {
	t.Helper()
	if s.Telnet == nil {
		t.Fatal("no telnet meta")
	}
	b, err := base64.StdEncoding.DecodeString(s.Telnet.ForeignPayloadB64)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestForeignClientKeepsItsWholeFirstPayload(t *testing.T) {
	h := startTelnetHarness(t, testTelnetConfig())
	req := "GET /cgi-bin/luci HTTP/1.1\r\nHost: 198.51.100.9\r\nUser-Agent: zgrab/0.x\r\n\r\n"
	h.readUntil("login: ")
	h.send([]byte(req))
	h.readUntil("Password: ")
	h.client.Close()
	s := h.wait()

	if got := payload(t, s); !bytes.Equal(got, []byte(req)) {
		t.Errorf("payload = %q, want the full request", got)
	}
}

// A TLS ClientHello has no line ending to wait for and carries 0xFF bytes
// the telnet negotiator would otherwise consume as IAC.
func TestBinaryProbeWithoutNewlineIsRecorded(t *testing.T) {
	h := startTelnetHarness(t, testTelnetConfig())
	hello := []byte{0x16, 0x03, 0x01, 0x00, 0xa5, 0x01, 0x00, 0x00, 0xa1, 0x03, 0x03, 0xff, 0xfb, 0x01, 0xfe}
	h.readUntil("login: ")
	h.send(hello)
	h.client.Close()
	s := h.wait()

	if s.Outcome != session.OutcomeProtocolMismatch || !shouldPersistTelnet(h.guard) {
		t.Errorf("outcome = %q, persist = %v", s.Outcome, shouldPersistTelnet(h.guard))
	}
	if got := payload(t, s); !bytes.Equal(got, hello) {
		t.Errorf("payload = % x, want % x", got, hello)
	}
}

func TestTelnetClientStoresNoPayload(t *testing.T) {
	h := startTelnetHarness(t, testTelnetConfig())
	s := loginAndExit(h)
	if s.Telnet.ForeignPayloadB64 != "" {
		t.Errorf("payload stored for an ordinary login: %q", s.Telnet.ForeignPayloadB64)
	}
}

func TestForeignPayloadIsCapped(t *testing.T) {
	h := startTelnetHarness(t, testTelnetConfig())
	h.readUntil("login: ")
	h.send(append([]byte("POST / HTTP/1.1\r\n"), bytes.Repeat([]byte("A"), 3*foreignPayloadMax)...))
	h.client.Close()
	s := h.wait()
	if got := payload(t, s); len(got) != foreignPayloadMax {
		t.Errorf("payload is %d bytes, want %d", len(got), foreignPayloadMax)
	}
}
