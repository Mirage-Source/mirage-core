package store_test

import (
	"testing"

	"github.com/mirage-source/mirage-core/internal/session"
	"github.com/mirage-source/mirage-core/internal/store"
)

func TestFileTransfersPersist(t *testing.T) {
	db := connect(t)
	s := newSession(session.ProtocolSSH, "198.51.100.71", "root", "root", "scp")
	s.Network.SSHClientBanner = "SSH-2.0-transfer-test"
	s.FileTransfers = []session.FileTransfer{
		{TimestampMS: s.Timing.StartMS, Method: session.TransferMethodSCP, Path: "/tmp/x86", Size: 3, SHA256: "abc", Complete: true},
		{TimestampMS: s.Timing.StartMS + 1, Method: session.TransferMethodSFTP, Path: "/tmp/big", Size: 99, Complete: false},
	}
	if err := store.SaveSession(db, s); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(`SELECT method, path, size, sha256, complete FROM file_transfers WHERE session_id = $1 ORDER BY timestamp_ms`, s.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []session.FileTransfer
	for rows.Next() {
		var f session.FileTransfer
		var sha *string
		if err := rows.Scan(&f.Method, &f.Path, &f.Size, &sha, &f.Complete); err != nil {
			t.Fatal(err)
		}
		if sha != nil {
			f.SHA256 = *sha
		}
		got = append(got, f)
	}
	if len(got) != 2 || got[0].SHA256 != "abc" || !got[0].Complete || got[1].SHA256 != "" || got[1].Complete || got[1].Size != 99 {
		t.Errorf("rows = %+v", got)
	}
}
