package store_test

import (
	"testing"

	"github.com/mirage-source/mirage-core/internal/session"
	"github.com/mirage-source/mirage-core/internal/store"
)

func TestTelnetForeignPayloadPersists(t *testing.T) {
	db := connect(t)
	s := newSession(session.ProtocolTelnet, "198.51.100.61", "x", "y", "echo")
	s.AuthAttempts = nil
	s.Commands = nil
	s.Outcome = session.OutcomeProtocolMismatch
	s.Telnet = &session.TelnetMeta{ClientOptions: []int{}, ForeignProtocolLine: "GET / HTTP/1.1", ForeignPayloadB64: "R0VUIC8gSFRUUC8xLjENCg0K"}
	if err := store.SaveSession(db, s); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := db.QueryRow(`SELECT foreign_payload_b64 FROM telnet_session_meta WHERE session_id = $1`, s.SessionID).Scan(&got); err != nil || got != s.Telnet.ForeignPayloadB64 {
		t.Errorf("got %q, %v", got, err)
	}
}
