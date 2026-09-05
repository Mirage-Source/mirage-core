package shell

import (
	"strconv"
	"strings"
	"testing"
)

// Coverage for the audit finding: "ps/netstat/uname/kernel string are static
// and identical across every session -- a patient attacker running the same
// recon twice will catch it." Kernel version is deliberately excluded (see
// TestUnameKernelVersionStaysIdenticalAcrossSessions) -- real hosts booted
// from the same image legitimately share it; what should vary is anything
// host-specific: uptime, PIDs, process start times.

func pidOf(psOut, marker string) string {
	for _, line := range strings.Split(psOut, "\r\n") {
		if strings.Contains(line, marker) {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				return fields[1]
			}
		}
	}
	return ""
}

func TestPsPidsVaryPerSession(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		s := NewInterpreter("ubuntu")
		out, code, _ := s.Run("ps aux")
		if code != 0 {
			t.Fatalf("ps aux failed: %s", out)
		}
		pid := pidOf(out, "sshd")
		if pid == "" {
			t.Fatalf("no sshd row found in ps output: %s", out)
		}
		seen[pid] = true
	}
	if len(seen) < 2 {
		t.Errorf("sshd PID never varied across 8 sessions: %v", seen)
	}
}

func TestPsInitPidStaysOne(t *testing.T) {
	s := NewInterpreter("ubuntu")
	out, _, _ := s.Run("ps aux")
	if pidOf(out, "/sbin/init") != "1" {
		t.Errorf("init should always be PID 1, got ps output: %s", out)
	}
}

func TestPsAndNetstatAgreeOnPidsWithinSession(t *testing.T) {
	s := NewInterpreter("ubuntu")
	psOut, _, _ := s.Run("ps aux")
	netOut, _, _ := s.Run("netstat -tulpn")

	sshdPID := pidOf(psOut, "sshd")
	gunicornPID := pidOf(psOut, "gunicorn")
	nginxPID := pidOf(psOut, "nginx: master")

	for _, pid := range []string{sshdPID, gunicornPID, nginxPID} {
		if pid == "" {
			t.Fatalf("could not find expected process in ps output: %s", psOut)
		}
		if !strings.Contains(netOut, "/"+pid+" ") && !strings.Contains(netOut, pid+"/") {
			t.Errorf("netstat output doesn't reference ps's PID %s for a shared process; ps=%q net=%q", pid, psOut, netOut)
		}
	}
}

func TestProcUptimeVariesPerSessionAndParses(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		s := NewInterpreter("ubuntu")
		out, code, _ := s.Run("cat /proc/uptime")
		if code != 0 {
			t.Fatalf("cat /proc/uptime failed: %s", out)
		}
		fields := strings.Fields(out)
		if len(fields) != 2 {
			t.Fatalf("/proc/uptime should have exactly two fields, got: %q", out)
		}
		if _, err := strconv.ParseFloat(fields[0], 64); err != nil {
			t.Fatalf("/proc/uptime first field not a float: %q", out)
		}
		seen[fields[0]] = true
	}
	if len(seen) < 2 {
		t.Errorf("/proc/uptime never varied across 5 sessions: %v", seen)
	}
}

func TestUnameKernelVersionStaysIdenticalAcrossSessions(t *testing.T) {
	a := NewInterpreter("ubuntu")
	b := NewInterpreter("ubuntu")
	outA, _, _ := a.Run("uname -r")
	outB, _, _ := b.Run("uname -r")
	if outA != outB {
		t.Errorf("kernel release should be identical across sessions (same AMI/image), got %q vs %q", outA, outB)
	}
}
