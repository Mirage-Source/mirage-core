package store

import (
	"encoding/json"
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

func TestEmptyStatsSerialiseListsAsArrays(t *testing.T) {
	b, err := json.Marshal(newStats())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	json.Unmarshal(b, &m)
	for _, k := range []string{"top_ips", "top_usernames", "top_passwords", "top_credentials", "ssh_banners", "coordinated_ips", "hourly_distribution"} {
		if string(m[k]) != "[]" {
			t.Errorf("%s = %s, want []", k, m[k])
		}
	}
}
