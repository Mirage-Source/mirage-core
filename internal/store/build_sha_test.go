package store_test

import (
	"encoding/json"
	"testing"

	"github.com/mirage-source/mirage-core/internal/session"
	"github.com/mirage-source/mirage-core/internal/store"
)

// build_sha is the only per-row record of which code produced a session (node_id
// is the emulated OS, schema_version is shared by every build of an era).
func TestBuildSHAPersistsAndIsExported(t *testing.T) {
	db := connect(t)
	stamped := newSession(session.ProtocolSSH, "198.51.100.61", "root", "root", "echo")
	stamped.BuildSHA = "abc1234-dirty"
	unstamped := newSession(session.ProtocolSSH, "198.51.100.62", "root", "root", "echo")
	// the store tests share one database, and TestValidityChecksAreSSHOnly asserts no SSH
	// session has an empty banner, so every SSH fixture needs one
	stamped.Network.SSHClientBanner = "SSH-2.0-build-sha-test"
	unstamped.Network.SSHClientBanner = "SSH-2.0-build-sha-test"
	for _, s := range []*session.Session{stamped, unstamped} {
		if err := store.SaveSession(db, s); err != nil {
			t.Fatal(err)
		}
	}

	var col string
	if err := db.QueryRow(`SELECT build_sha FROM sessions WHERE session_id = $1`, stamped.SessionID).Scan(&col); err != nil {
		t.Fatal(err)
	}
	if col != "abc1234-dirty" {
		t.Errorf("column build_sha = %q, want abc1234-dirty", col)
	}
	// A row that never had a stamp is '', which is different from the loud "unknown"
	// an unstamped build writes: '' means "written before schema 1.2".
	if err := db.QueryRow(`SELECT build_sha FROM sessions WHERE session_id = $1`, unstamped.SessionID).Scan(&col); err != nil {
		t.Fatal(err)
	}
	if col != "" {
		t.Errorf("unstamped column = %q, want empty", col)
	}

	var doc []byte
	if err := db.QueryRow(`SELECT session_document FROM sessions WHERE session_id = $1`, stamped.SessionID).Scan(&doc); err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		BuildSHA string `json:"build_sha"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil || parsed.BuildSHA != "abc1234-dirty" {
		t.Errorf("session_document build_sha = %q (err %v)", parsed.BuildSHA, err)
	}

	export, err := store.GetExportPage(db, session.ProtocolSSH, "", 10000)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, s := range export.Sessions {
		seen[s.SessionID] = s.BuildSHA
	}
	if v, ok := seen[stamped.SessionID]; !ok || v != "abc1234-dirty" {
		t.Errorf("export build_sha = %q (present %v), want abc1234-dirty", v, ok)
	}
	if v, ok := seen[unstamped.SessionID]; !ok || v != "" {
		t.Errorf("export unstamped build_sha = %q (present %v), want empty", v, ok)
	}
}
