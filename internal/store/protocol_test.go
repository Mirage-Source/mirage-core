package store

import (
	"errors"
	"testing"

	"github.com/mirage-source/mirage-core/internal/session"
)

func TestParseProtocol(t *testing.T) {
	for raw, want := range map[string]session.Protocol{"": session.ProtocolSSH, "ssh": session.ProtocolSSH, "telnet": session.ProtocolTelnet} {
		got, err := ParseProtocol(raw)
		if err != nil || got != want {
			t.Errorf("ParseProtocol(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"SSH", "rdp", "ssh' --", " telnet"} {
		if _, err := ParseProtocol(raw); !errors.Is(err, ErrInvalidProtocol) {
			t.Errorf("ParseProtocol(%q) err = %v, want ErrInvalidProtocol", raw, err)
		}
	}
}
