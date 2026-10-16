package server

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mirage-source/mirage-core/internal/session"
	"github.com/mirage-source/mirage-core/internal/telnet"
)

func testTelnetConfig() telnetConfig {
	return telnetConfig{
		weakCreds:        map[string]struct{}{"root:xc3511": {}},
		loginTimeout:     5 * time.Second,
		idleTimeout:      5 * time.Second,
		maxLoginAttempts: 3,
		authDelay:        func() time.Duration { return 0 },
	}
}

type telnetHarness struct {
	t      *testing.T
	client net.Conn
	guard  *sessionGuard
	done   chan struct{}
	seen   []byte
	pos    int
}

func startTelnetHarness(t *testing.T, cfg telnetConfig) *telnetHarness {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	h := &telnetHarness{t: t, done: make(chan struct{})}
	h.guard = &sessionGuard{sess: newTelnetSession()}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handleTelnet(conn, cfg, h.guard)
		conn.Close()
		close(h.done)
	}()

	h.client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.client.Close() })
	return h
}

func (h *telnetHarness) readUntil(marker string) []byte {
	h.t.Helper()
	h.client.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := h.pos
	buf := make([]byte, 4096)
	for {
		if i := bytes.Index(h.seen[start:], []byte(marker)); i >= 0 {
			h.pos = start + i + len(marker)
			return h.seen[start:h.pos]
		}
		n, err := h.client.Read(buf)
		h.seen = append(h.seen, buf[:n]...)
		if err != nil {
			h.t.Fatalf("waiting for %q: %v; got %q", marker, err, h.seen[start:])
		}
	}
}

func (h *telnetHarness) send(b []byte) {
	h.t.Helper()
	if _, err := h.client.Write(b); err != nil {
		h.t.Fatal(err)
	}
}

func (h *telnetHarness) wait() *session.Session {
	h.t.Helper()
	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		h.t.Fatal("handler did not finish")
	}
	return h.guard.sess
}

func parsedCommands(s *session.Session) []string {
	var out []string
	for _, c := range s.Commands {
		out = append(out, c.ParsedCommand)
	}
	return out
}

func TestTelnetRawSocketBotLogsInAndRunsBusyboxProbe(t *testing.T) {
	h := startTelnetHarness(t, testTelnetConfig())
	h.readUntil("login: ")
	h.send([]byte("root\r\n"))
	h.readUntil("Password: ")
	h.send([]byte("xc3511\r\n"))
	h.readUntil("# ")
	h.send([]byte("/bin/busybox ECCHI\r\n"))
	if out := h.readUntil("# "); !bytes.Contains(out, []byte("ECCHI: applet not found\r\n")) {
		t.Errorf("busybox probe output = %q", out)
	}
	h.send([]byte("exit\r\n"))
	h.readUntil("logout")
	s := h.wait()

	if s.Protocol != session.ProtocolTelnet {
		t.Errorf("protocol = %q", s.Protocol)
	}
	if s.Outcome != session.OutcomeCleanDisconnect {
		t.Errorf("outcome = %q", s.Outcome)
	}
	if len(s.AuthAttempts) != 1 || !s.AuthAttempts[0].Success || s.AuthAttempts[0].Username != "root" || s.AuthAttempts[0].Credential != "xc3511" {
		t.Errorf("auth attempts = %+v", s.AuthAttempts)
	}
	if got := parsedCommands(s); len(got) != 2 || got[0] != "busybox" || got[1] != "exit" {
		t.Errorf("commands = %v", got)
	}
	if s.Network.ClientIP != "127.0.0.1" || s.Network.ServerPort == 0 {
		t.Errorf("network = %+v", s.Network)
	}
	if s.Telnet == nil || s.Telnet.Negotiated {
		t.Errorf("telnet meta = %+v, want non-nil with Negotiated=false", s.Telnet)
	}
}

func TestTelnetPipelinedBotKeepsEveryLineInOrder(t *testing.T) {
	h := startTelnetHarness(t, testTelnetConfig())
	h.send([]byte("root\r\nxc3511\r\nenable\r\nsystem\r\nshell\r\nsh\r\n/bin/busybox ECCHI\r\nexit\r\n"))
	h.readUntil("logout")
	s := h.wait()

	want := []string{"enable", "system", "shell", "sh", "busybox", "exit"}
	if got := parsedCommands(s); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("commands = %v, want %v", got, want)
	}
}

func TestTelnetFailedLoginsEndSessionAsAuthFailed(t *testing.T) {
	h := startTelnetHarness(t, testTelnetConfig())
	for i := 0; i < 3; i++ {
		h.readUntil("login: ")
		h.send([]byte("admin\r\n"))
		h.readUntil("Password: ")
		h.send([]byte("wrong\r\n"))
		h.readUntil("Login incorrect")
	}
	s := h.wait()
	if s.Outcome != session.OutcomeAuthFailed {
		t.Errorf("outcome = %q", s.Outcome)
	}
	if len(s.AuthAttempts) != 3 {
		t.Errorf("auth attempts = %d, want 3", len(s.AuthAttempts))
	}
	if len(s.Commands) != 0 {
		t.Errorf("commands recorded without login: %v", parsedCommands(s))
	}
}

func TestTelnetEmptyUsernameRepromptsWithoutCountingAnAttempt(t *testing.T) {
	h := startTelnetHarness(t, testTelnetConfig())
	h.readUntil("login: ")
	h.send([]byte("\r\n"))
	h.readUntil("login: ")
	h.send([]byte("root\r\nxc3511\r\nexit\r\n"))
	h.readUntil("logout")
	if s := h.wait(); len(s.AuthAttempts) != 1 {
		t.Errorf("auth attempts = %d, want 1", len(s.AuthAttempts))
	}
}

func TestTelnetRealClientNegotiationIsRecordedAndPasswordNotEchoed(t *testing.T) {
	h := startTelnetHarness(t, testTelnetConfig())
	h.send([]byte{
		telnet.IAC, telnet.WILL, telnet.OptTTYPE,
		telnet.IAC, telnet.WILL, telnet.OptNAWS,
		telnet.IAC, telnet.SB, telnet.OptNAWS, 0, 120, 0, 40, telnet.IAC, telnet.SE,
	})
	h.readUntil(string([]byte{telnet.IAC, telnet.SB, telnet.OptTTYPE, 1, telnet.IAC, telnet.SE}))
	h.send(append(append([]byte{telnet.IAC, telnet.SB, telnet.OptTTYPE, 0}, "XTERM-256COLOR"...), telnet.IAC, telnet.SE))
	h.send([]byte("root\r\n"))
	h.readUntil("Password: ")
	h.send([]byte("xc3511\r\n"))
	afterPassword := h.readUntil("# ")
	if bytes.Contains(afterPassword, []byte("xc3511")) {
		t.Errorf("password echoed back: %q", afterPassword)
	}
	h.send([]byte("exit\r\n"))
	s := h.wait()

	m := s.Telnet
	if m == nil || !m.Negotiated || m.TerminalType != "XTERM-256COLOR" || m.WindowWidth != 120 || m.WindowHeight != 40 {
		t.Errorf("telnet meta = %+v", m)
	}
	if len(m.ClientOptions) != 2 || m.ClientOptions[0] != int(telnet.OptTTYPE) || m.ClientOptions[1] != int(telnet.OptNAWS) {
		t.Errorf("client options = %v", m.ClientOptions)
	}
}

func TestTelnetOutputEscapesIACAndUsesCRLF(t *testing.T) {
	h := startTelnetHarness(t, testTelnetConfig())
	h.send([]byte("root\r\nxc3511\r\n"))
	h.readUntil("# ")
	h.send([]byte("echo a"))
	h.send([]byte{telnet.IAC, telnet.IAC})
	h.send([]byte("b\r\n"))
	out := h.readUntil("# ")
	if !bytes.Contains(out, []byte{'a', telnet.IAC, telnet.IAC, 'b', '\r', '\n'}) {
		t.Errorf("0xFF in output not escaped as IAC IAC: %q", out)
	}
	h.send([]byte("uname -a\r\n"))
	out = h.readUntil("# ")
	if bytes.Contains(bytes.ReplaceAll(out, []byte("\r\n"), nil), []byte("\n")) {
		t.Errorf("bare LF in output: %q", out)
	}
	h.send([]byte("exit\r\n"))
	h.wait()
}

func TestTelnetIdleTimeout(t *testing.T) {
	cfg := testTelnetConfig()
	cfg.idleTimeout = 200 * time.Millisecond
	h := startTelnetHarness(t, cfg)
	h.send([]byte("root\r\nxc3511\r\n"))
	h.readUntil("# ")
	if s := h.wait(); s.Outcome != session.OutcomeTimeout {
		t.Errorf("outcome = %q, want timeout", s.Outcome)
	}
}

func TestTelnetLoginTimeout(t *testing.T) {
	cfg := testTelnetConfig()
	cfg.loginTimeout = 200 * time.Millisecond
	h := startTelnetHarness(t, cfg)
	h.readUntil("login: ")
	h.send([]byte("root\r\n"))
	if s := h.wait(); len(s.AuthAttempts) != 0 || s.Outcome != session.OutcomeTimeout {
		t.Errorf("attempts = %d, outcome = %q; want 0, timeout", len(s.AuthAttempts), s.Outcome)
	}
}

func TestTelnetOverlongLineIsTruncatedToMaxInput(t *testing.T) {
	h := startTelnetHarness(t, testTelnetConfig())
	h.send([]byte("root\r\nxc3511\r\n"))
	h.readUntil("# ")
	h.send([]byte("echo " + strings.Repeat("A", 10000) + "\r\n"))
	h.readUntil("# ")
	h.send([]byte("exit\r\n"))
	s := h.wait()
	if len(s.Commands) == 0 {
		t.Fatal("no commands")
	}
	if n := len(s.Commands[0].ParsedCommand) + len(strings.Join(s.Commands[0].ParsedArgs, " ")) + 1; n > MaxInput {
		t.Errorf("recorded line is %d bytes, cap is %d", n, MaxInput)
	}
}

func TestShouldPersistTelnetOnlyAfterAnAuthAttempt(t *testing.T) {
	g := &sessionGuard{sess: newTelnetSession()}
	if shouldPersistTelnet(g) {
		t.Error("connection with no auth attempt would be persisted")
	}
	g.sess.AuthAttempts = append(g.sess.AuthAttempts, session.AuthAttempt{Username: "root"})
	if !shouldPersistTelnet(g) {
		t.Error("connection with an auth attempt would not be persisted")
	}
}

func TestBundledTelnetCredentialsAreMiraisTable(t *testing.T) {
	creds := loadWeakCredentials("../../config/telnet_weak_credentials.txt")
	if len(creds) != 61 {
		t.Errorf("loaded %d pairs, want 61", len(creds))
	}
	for _, c := range []string{"root:xc3511", "root:vizxv", "root:888888", "root:xmhdipc", "root:juantech", "root:", "admin:", "Administrator:meinsm", "admin:4321"} {
		if _, ok := creds[c]; !ok {
			t.Errorf("missing %q", c)
		}
	}
	ssh := loadWeakCredentials("../../config/weak_credentials.txt")
	if _, ok := ssh["root:xc3511"]; ok {
		t.Error("Mirai-only credential leaked into the SSH list")
	}
}

func TestTelnetEmptyPasswordLogin(t *testing.T) {
	cfg := testTelnetConfig()
	cfg.weakCreds = map[string]struct{}{"root:": {}}
	h := startTelnetHarness(t, cfg)
	h.send([]byte("root\r\n\r\nexit\r\n"))
	h.readUntil("logout")
	if s := h.wait(); len(s.AuthAttempts) != 1 || !s.AuthAttempts[0].Success {
		t.Errorf("auth attempts = %+v", s.AuthAttempts)
	}
}

func TestForeignProtocolLineDetection(t *testing.T) {
	for line, want := range map[string]bool{
		"GET / HTTP/1.0":             true,
		"GET / HTTP/1.1":             true,
		"OPTIONS sip:nm SIP/2.0":     true,
		"DESCRIBE rtsp://x RTSP/1.0": true,
		"SSH-2.0-Go":                 true,
		"\x16\x03\x01\x02\x00\x01":   true,
		"\xff\xfe":                   true,
		"root":                       false,
		"admin":                      false,
		"Administrator":              false,
		"support":                    false,
		"user name":                  false,
		"GET":                        false,
	} {
		if got := isForeignProtocolLine(line); got != want {
			t.Errorf("isForeignProtocolLine(%q) = %v, want %v", line, got, want)
		}
	}
}

// An HTTP scanner on port 23 gets the same login dialogue a real telnetd
// gives it, but its request and header lines are not credential attempts.
func TestTelnetHTTPScannerIsNotRecordedAsCredentials(t *testing.T) {
	h := startTelnetHarness(t, testTelnetConfig())
	h.readUntil("login: ")
	h.send([]byte("GET / HTTP/1.0\r\n"))
	h.readUntil("Password: ")
	h.send([]byte("Host: 198.51.100.9\r\n"))
	h.readUntil("Login incorrect")
	h.readUntil("login: ")
	h.client.Close()
	s := h.wait()

	if len(s.AuthAttempts) != 0 {
		t.Errorf("auth attempts = %+v, want none", s.AuthAttempts)
	}
	if s.Outcome != session.OutcomeProtocolMismatch {
		t.Errorf("outcome = %q, want %q", s.Outcome, session.OutcomeProtocolMismatch)
	}
	if s.Telnet == nil || s.Telnet.ForeignProtocolLine != "GET / HTTP/1.0" {
		t.Errorf("telnet meta = %+v, want the request line kept", s.Telnet)
	}
	if !shouldPersistTelnet(h.guard) {
		t.Error("protocol-mismatch session would not be persisted")
	}
}

// A scanner that sends one request line and hangs up never reaches a
// password; the scan must still be kept.
func TestTelnetSingleLineScannerIsStillPersisted(t *testing.T) {
	h := startTelnetHarness(t, testTelnetConfig())
	h.readUntil("login: ")
	h.send([]byte("GET / HTTP/1.1\r\n"))
	h.readUntil("Password: ")
	h.client.Close()
	s := h.wait()
	if !shouldPersistTelnet(h.guard) || s.Outcome != session.OutcomeProtocolMismatch || len(s.AuthAttempts) != 0 {
		t.Errorf("persist=%v outcome=%q attempts=%d, want true, protocol_mismatch, 0",
			shouldPersistTelnet(h.guard), s.Outcome, len(s.AuthAttempts))
	}
}

// The telnet sensor is the DVR end to end: no Ubuntu banner or welcome,
// the device's own login prompt and an ash prompt after login.
func TestTelnetPresentsTheDVR(t *testing.T) {
	h := startTelnetHarness(t, testTelnetConfig())
	pre := h.readUntil("LocalHost login: ")
	h.send([]byte("root\r\nxc3511\r\n"))
	h.readUntil("Password: ")
	post := h.readUntil("# ")
	h.send([]byte("uname -m\r\nenable\r\nexit\r\n"))
	rest := h.readUntil("logout")
	h.wait()
	all := string(pre) + string(post) + string(rest)
	if strings.Contains(all, "Ubuntu") || strings.Contains(all, "Welcome") {
		t.Errorf("wire shows the Ubuntu identity: %q", all)
	}
	if !strings.Contains(string(rest), "armv7l") || !strings.Contains(string(rest), "-sh: enable: not found") {
		t.Errorf("after login = %q, want armv7l and ash errors", rest)
	}
}
