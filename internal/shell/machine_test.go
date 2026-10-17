package shell

import (
	"strings"
	"sync"
	"testing"
)

// Every exec on a real box is a new bash on the same machine: files and the
// hostname persist across them, cwd and shell variables do not.
func TestProcessesShareTheirMachine(t *testing.T) {
	m := NewMachine(Ubuntu)
	a, b := m.NewInterpreter("root"), m.NewInterpreter("root")

	a.Run("echo hi > /tmp/.probe; cd /tmp; X=1")
	if out, _, _ := b.Run("cat /tmp/.probe"); strings.TrimSpace(out) != "hi" {
		t.Errorf("file written by one process: other sees %q", out)
	}
	if out, _, _ := b.Run("pwd; echo \"[$X]\""); out != "/root\r\n[]" {
		t.Errorf("cwd/vars leaked between processes: %q", out)
	}
	ha, _, _ := a.Run("hostname")
	hb, _, _ := b.Run("cat /etc/hostname")
	if ha != strings.TrimSpace(hb) || ha == "" {
		t.Errorf("hostname %q vs /etc/hostname %q", ha, hb)
	}
	if NewInterpreter("root").Hostname == "" {
		t.Error("NewInterpreter must still give a working machine")
	}
}

// Channels on one connection run concurrently; run with -race.
func TestMachineIsSafeForConcurrentProcesses(t *testing.T) {
	m := NewMachine(Ubuntu)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := m.NewInterpreter("root")
			for j := 0; j < 50; j++ {
				p.Run("echo x >> /tmp/log; mkdir -p /tmp/d; ls /tmp")
				p.CreateFile("/tmp/up", true)
				p.Stat("/tmp/up")
			}
		}()
	}
	wg.Wait()
	out, _, _ := m.NewInterpreter("root").Run("wc -l /tmp/log")
	if !strings.HasPrefix(out, "400 ") {
		t.Errorf("wc -l = %q, want 400 lines", out)
	}
}
