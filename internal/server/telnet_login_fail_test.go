package server

import (
	"bytes"
	"testing"
	"time"
)

// Measured 2026-10-17 against busybox:1.36 telnetd -l /bin/login: after a
// wrong password the client gets "\r\n" at once (the tty echoing the
// newline), then nothing for 3.00s, then "Login incorrect\r\n" and the next
// prompt -- the same for every username.
func TestFailedTelnetLoginMatchesBusyBox(t *testing.T) {
	if busyboxLoginFailDelay != 3*time.Second {
		t.Errorf("fail delay = %v, want BusyBox's fixed 3s", busyboxLoginFailDelay)
	}

	cfg := testTelnetConfig()
	cfg.authDelay = func() time.Duration { return 0 }
	h := startTelnetHarness(t, cfg)
	h.readUntil("login: ")
	h.send([]byte("root\r\n"))
	h.readUntil("Password: ")
	h.send([]byte("wrong\r\n"))
	got := h.readUntil("login: ")
	want := []byte("\r\nLogin incorrect\r\n")
	if !bytes.HasPrefix(got, want) {
		t.Errorf("after a wrong password got %q, want prefix %q", got, want)
	}
}
