package store_test

import (
	"database/sql"
	"errors"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mirage-source/mirage-core/internal/session"
	"github.com/mirage-source/mirage-core/internal/store"
	"github.com/mirage-source/mirage-core/internal/validity"
)

const (
	sshIP      = "198.51.100.10"
	telnetIP   = "198.51.100.20"
	telnetUser = "telnet-only-user"
	telnetPass = "telnet-only-pass"
)

func connect(t *testing.T) *sql.DB {
	t.Helper()
	if os.Getenv("MIRAGE_E2E_TEST") == "" {
		t.Skip("set MIRAGE_E2E_TEST=1 against a reachable, migrated Postgres to run this test")
	}
	db, err := store.Connect()
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func newSession(protocol session.Protocol, ip, user, pass, cmd string) *session.Session {
	now := time.Now().UnixMilli()
	end := now + 1000
	dur := int64(1000)
	resp := ""
	code := 0
	return &session.Session{
		SessionID:     uuid.New().String(),
		SchemaVersion: "1.1",
		NodeID:        "Ubuntu",
		Protocol:      protocol,
		Network:       session.Network{ClientIP: ip, ClientPort: 40000, ServerPort: 23, IngressSource: session.IngressSourceDirect},
		Timing:        session.Timing{StartMS: now, EndMS: &end, DurationMS: &dur},
		Outcome:       session.OutcomeCleanDisconnect,
		AuthAttempts: []session.AuthAttempt{{
			TimestampMS: now, Method: session.AuthMethodPassword,
			Username: user, Credential: pass, Success: true,
		}},
		Commands: []session.Command{{
			EventID: uuid.New().String(), TimestampMS: now,
			RawInputB64: "ZWNobw==", ParsedCommand: cmd, ParsedArgs: []string{},
			WorkingDirectory: "/root", Response: &resp, ExitCode: &code,
			ResponseSource: session.ResponseSourceHardcoded,
		}},
		BaitEvents: []session.BaitEvent{},
	}
}

func seed(t *testing.T, db *sql.DB) (sshSess, telnetSess *session.Session) {
	t.Helper()
	sshSess = newSession(session.ProtocolSSH, sshIP, "ssh-user", "ssh-pass", "echo")
	sshSess.Network.SSHClientBanner = "SSH-2.0-isolation-test"
	telnetSess = newSession(session.ProtocolTelnet, telnetIP, telnetUser, telnetPass, "telnet-only-cmd")
	telnetSess.Telnet = &session.TelnetMeta{
		Negotiated:    true,
		ClientOptions: []int{24, 31},
		TerminalType:  "XTERM",
		WindowWidth:   80,
		WindowHeight:  24,
	}
	for _, s := range []*session.Session{sshSess, telnetSess} {
		if err := store.SaveSession(db, s); err != nil {
			t.Fatalf("saving %s session: %v", s.Protocol, err)
		}
	}
	return sshSess, telnetSess
}

func countSSH(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE protocol = 'ssh'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestTelnetMetaPersistsAndSSHDocumentHasNoTelnetKey(t *testing.T) {
	db := connect(t)
	sshSess, telnetSess := seed(t, db)

	var negotiated bool
	var termType string
	var w, h int
	var opts string
	err := db.QueryRow(`
		SELECT negotiated, client_options::text, terminal_type, window_width, window_height
		FROM telnet_session_meta WHERE session_id = $1`, telnetSess.SessionID,
	).Scan(&negotiated, &opts, &termType, &w, &h)
	if err != nil {
		t.Fatalf("reading telnet_session_meta: %v", err)
	}
	if !negotiated || opts != "{24,31}" || termType != "XTERM" || w != 80 || h != 24 {
		t.Errorf("meta = (%v, %s, %q, %d, %d), want (true, {24,31}, XTERM, 80, 24)", negotiated, opts, termType, w, h)
	}

	var sshMetaRows int
	db.QueryRow(`SELECT COUNT(*) FROM telnet_session_meta WHERE session_id = $1`, sshSess.SessionID).Scan(&sshMetaRows)
	if sshMetaRows != 0 {
		t.Errorf("SSH session got a telnet_session_meta row")
	}

	var doc []byte
	db.QueryRow(`SELECT session_document FROM sessions WHERE session_id = $1`, sshSess.SessionID).Scan(&doc)
	var m map[string]json.RawMessage
	json.Unmarshal(doc, &m)
	if _, ok := m["telnet"]; ok {
		t.Errorf("SSH session_document has a \"telnet\" key; SSH documents must be unchanged")
	}
}

func TestDashboardStatsAreSSHOnly(t *testing.T) {
	db := connect(t)
	seed(t, db)

	stats, err := store.GetStats(db, session.ProtocolSSH)
	if err != nil {
		t.Fatal(err)
	}
	if want := countSSH(t, db); int(stats.TotalSessions) != want {
		t.Errorf("TotalSessions = %d, want %d (SSH only)", stats.TotalSessions, want)
	}
	for _, ip := range stats.TopIPs {
		if ip.IP == telnetIP {
			t.Errorf("telnet IP in TopIPs")
		}
	}
	for _, u := range stats.TopUsernames {
		if u.Username == telnetUser {
			t.Errorf("telnet username in TopUsernames")
		}
	}
	for _, p := range stats.TopPasswords {
		if p.Password == telnetPass {
			t.Errorf("telnet password in TopPasswords")
		}
	}
	for _, c := range stats.TopCredentials {
		if c.Username == telnetUser {
			t.Errorf("telnet credential in TopCredentials")
		}
	}
	for _, g := range stats.CoordinatedIPs {
		if g.Username == telnetUser {
			t.Errorf("telnet credential in CoordinatedIPs")
		}
	}
}

func TestSessionListAndExportsAreSSHOnly(t *testing.T) {
	db := connect(t)
	sshSess, telnetSess := seed(t, db)

	list, err := store.GetSessions(db, session.ProtocolSSH, 10000, 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := countSSH(t, db); int(list.Total) != want {
		t.Errorf("GetSessions Total = %d, want %d", list.Total, want)
	}
	foundSSH := false
	for _, s := range list.Sessions {
		if s.SessionID == telnetSess.SessionID {
			t.Errorf("telnet session in GetSessions")
		}
		foundSSH = foundSSH || s.SessionID == sshSess.SessionID
	}
	if !foundSSH {
		t.Errorf("SSH session missing from GetSessions")
	}

	export, err := store.GetExportPage(db, session.ProtocolSSH, "", 10000)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range export.Sessions {
		if s.SessionID == telnetSess.SessionID {
			t.Errorf("telnet session in session export")
		}
	}

	cmds, err := store.GetCommandExport(db, session.ProtocolSSH, "", 10000)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cmds.Commands {
		if c.SessionID == telnetSess.SessionID {
			t.Errorf("telnet command in command export")
		}
	}
}

func TestLookupByIDStillFindsTelnet(t *testing.T) {
	db := connect(t)
	_, telnetSess := seed(t, db)

	got, err := store.GetSessionByID(db, telnetSess.SessionID)
	if err != nil {
		t.Fatalf("GetSessionByID(telnet): %v", err)
	}
	if got.Protocol != session.ProtocolTelnet || got.Telnet == nil || got.Telnet.TerminalType != "XTERM" {
		t.Errorf("GetSessionByID = protocol %q, telnet %+v", got.Protocol, got.Telnet)
	}
}

func TestValidityChecksAreSSHOnly(t *testing.T) {
	db := connect(t)
	seed(t, db)

	all, _, err := validity.ComputeAggregateStats(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := countSSH(t, db); int(all.TotalSessions) != want {
		t.Errorf("ComputeAggregateStats total = %d, want %d", all.TotalSessions, want)
	}

	counts, pairs, err := validity.FetchCampaignInputs(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := counts[telnetIP]; ok {
		t.Errorf("telnet IP in campaign session counts")
	}
	if _, ok := pairs[telnetIP]; ok {
		t.Errorf("telnet IP in campaign credential pairs")
	}

	from, to := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	for _, f := range validity.WatchedFields {
		got, err := validity.FetchFieldCounts(db, f, from, to)
		if err != nil {
			t.Fatalf("FetchFieldCounts(%s.%s): %v", f.Table, f.Column, err)
		}
		if f == validity.FieldSessionsSSHBanner {
			if _, ok := got[""]; ok {
				t.Errorf("empty (telnet) banner counted in ssh_client_banner cardinality")
			}
		}
	}

	var sshAttempts int
	db.QueryRow(`
		SELECT COUNT(*) FROM auth_attempts a JOIN sessions s USING (session_id)
		WHERE s.protocol = 'ssh' AND a.timestamp_ms >= $1`,
		time.Now().AddDate(0, 0, -7).UnixMilli()).Scan(&sshAttempts)
	series, err := validity.FetchDailyAuthSuccessRate(db, 7)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, d := range series {
		total += d.N
	}
	if total != sshAttempts {
		t.Errorf("daily auth attempts = %d, want %d (SSH only)", total, sshAttempts)
	}
}

func TestPythonReadersFilterProtocol(t *testing.T) {
	for _, path := range []string{"../../bridge/db.py", "../../ml/mirage/reid/real_db.py"} {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), "protocol = 'ssh'") {
			t.Errorf("%s: no protocol = 'ssh' filter on its sessions queries", path)
		}
	}
}

func TestTelnetViewReturnsOnlyTelnet(t *testing.T) {
	db := connect(t)
	sshSess, telnetSess := seed(t, db)

	var telnetCount int
	db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE protocol = 'telnet'`).Scan(&telnetCount)

	stats, err := store.GetStats(db, session.ProtocolTelnet)
	if err != nil {
		t.Fatal(err)
	}
	if int(stats.TotalSessions) != telnetCount {
		t.Errorf("telnet TotalSessions = %d, want %d", stats.TotalSessions, telnetCount)
	}
	foundUser := false
	for _, u := range stats.TopUsernames {
		if u.Username == "ssh-user" {
			t.Error("SSH username in telnet TopUsernames")
		}
		foundUser = foundUser || u.Username == telnetUser
	}
	if !foundUser {
		t.Error("telnet username missing from telnet TopUsernames")
	}

	list, err := store.GetSessions(db, session.ProtocolTelnet, 10000, 0)
	if err != nil {
		t.Fatal(err)
	}
	if int(list.Total) != telnetCount {
		t.Errorf("telnet GetSessions Total = %d, want %d", list.Total, telnetCount)
	}
	found := false
	for _, s := range list.Sessions {
		if s.SessionID == sshSess.SessionID {
			t.Error("SSH session in telnet GetSessions")
		}
		found = found || s.SessionID == telnetSess.SessionID
	}
	if !found {
		t.Error("telnet session missing from telnet GetSessions")
	}

	export, err := store.GetExportPage(db, session.ProtocolTelnet, "", 10000)
	if err != nil {
		t.Fatal(err)
	}
	found = false
	for _, s := range export.Sessions {
		if s.SessionID == sshSess.SessionID {
			t.Error("SSH session in telnet export")
		}
		found = found || s.SessionID == telnetSess.SessionID
	}
	if !found {
		t.Error("telnet session missing from telnet export")
	}

	cmds, err := store.GetCommandExport(db, session.ProtocolTelnet, "", 10000)
	if err != nil {
		t.Fatal(err)
	}
	found = false
	for _, c := range cmds.Commands {
		if c.SessionID == sshSess.SessionID {
			t.Error("SSH command in telnet command export")
		}
		found = found || c.SessionID == telnetSess.SessionID
	}
	if !found {
		t.Error("telnet command missing from telnet command export")
	}
}

func TestStoreRejectsUnknownProtocol(t *testing.T) {
	db := connect(t)
	if _, err := store.GetStats(db, session.Protocol("ssh' OR '1'='1")); !errors.Is(err, store.ErrInvalidProtocol) {
		t.Errorf("GetStats with bogus protocol: err = %v, want ErrInvalidProtocol", err)
	}
	if _, err := store.GetSessions(db, "rdp", 10, 0); !errors.Is(err, store.ErrInvalidProtocol) {
		t.Errorf("GetSessions with bogus protocol: err = %v", err)
	}
}
