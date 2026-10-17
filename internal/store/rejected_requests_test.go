package store_test

import (
	"encoding/json"
	"testing"

	"github.com/mirage-source/mirage-core/internal/session"
	"github.com/mirage-source/mirage-core/internal/store"
)

func TestRejectedRequestsPersist(t *testing.T) {
	db := connect(t)
	s := newSession(session.ProtocolSSH, "198.51.100.41", "root", "root", "echo")
	s.Network.SSHClientBanner = "SSH-2.0-rejected-test"
	s.RejectedRequests = []session.RejectedRequest{
		{TimestampMS: s.Timing.StartMS, Kind: session.RejectedKindChannel, Type: "direct-tcpip", Detail: "smtp.example.com:25"},
		// Client-supplied text: NUL must not abort the whole session insert.
		{TimestampMS: s.Timing.StartMS + 1, Kind: session.RejectedKindSubsystem, Type: "sftp\x00"},
	}
	if err := store.SaveSession(db, s); err != nil {
		t.Fatalf("saving: %v", err)
	}

	rows, err := db.Query(`SELECT kind, type, detail FROM rejected_requests WHERE session_id = $1 ORDER BY timestamp_ms`, s.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got [][3]string
	for rows.Next() {
		var r [3]string
		if err := rows.Scan(&r[0], &r[1], &r[2]); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
	}
	if len(got) != 2 || got[0] != [3]string{"channel", "direct-tcpip", "smtp.example.com:25"} || got[1][0] != "subsystem" {
		t.Errorf("rows = %q", got)
	}
}

func TestSessionWithoutRejectedRequestsHasNoKey(t *testing.T) {
	db := connect(t)
	s := newSession(session.ProtocolSSH, "198.51.100.42", "root", "root", "echo")
	s.Network.SSHClientBanner = "SSH-2.0-rejected-test"
	if err := store.SaveSession(db, s); err != nil {
		t.Fatal(err)
	}
	var doc []byte
	db.QueryRow(`SELECT session_document FROM sessions WHERE session_id = $1`, s.SessionID).Scan(&doc)
	var m map[string]json.RawMessage
	json.Unmarshal(doc, &m)
	if _, ok := m["rejected_requests"]; ok {
		t.Error("session_document gained a rejected_requests key; unchanged sessions must keep their old shape")
	}
}
