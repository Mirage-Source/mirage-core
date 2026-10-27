package server

import (
	"testing"

	"github.com/mirage-source/mirage-core/internal/buildinfo"
	"github.com/mirage-source/mirage-core/internal/session"
)

// Both sensors stamp the build onto every session they create. node_id and
// schema_version never told builds apart, so build_sha is the only record of which
// code produced a row.
func TestNewSessionsCarryBuildIdentity(t *testing.T) {
	ssh := newSSHSession()
	telnet := newTelnetSession()
	for name, s := range map[string]*session.Session{"ssh": &ssh, "telnet": telnet} {
		if s.SchemaVersion != "1.2" {
			t.Errorf("%s: schema_version = %q, want 1.2", name, s.SchemaVersion)
		}
		if s.BuildSHA != buildinfo.Commit {
			t.Errorf("%s: build_sha = %q, want the linked-in commit %q", name, s.BuildSHA, buildinfo.Commit)
		}
		if s.NodeID != "Ubuntu" {
			t.Errorf("%s: node_id = %q, want Ubuntu (the emulated OS, unchanged)", name, s.NodeID)
		}
	}
	if ssh.Protocol != session.ProtocolSSH || telnet.Protocol != session.ProtocolTelnet {
		t.Errorf("protocols = %q, %q", ssh.Protocol, telnet.Protocol)
	}
	if ssh.Outcome != session.OutcomeActive || len(ssh.BaitEvents) != 0 || ssh.BaitEvents == nil || ssh.Timing.StartMS == 0 {
		t.Errorf("ssh session lost its initial state: %+v", ssh)
	}
}
