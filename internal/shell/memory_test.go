package shell

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func execOut(t *testing.T, p *Interpreter, cmd string) string {
	t.Helper()
	out, errOut, code, _ := p.RunExec(cmd)
	if code != 0 {
		t.Fatalf("%q: exit %d, %q", cmd, code, errOut)
	}
	return out
}

func meminfoField(t *testing.T, meminfo, name string) int64 {
	t.Helper()
	for _, l := range strings.Split(meminfo, "\n") {
		if rest, ok := strings.CutPrefix(l, name+":"); ok {
			n, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(rest), " kB"), 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
	}
	t.Fatalf("no %s in meminfo", name)
	return 0
}

// free reads /proc/meminfo (procps 3.3.17): total, used = total - free -
// buffers - cache, buff/cache = Buffers + Cached + SReclaimable. Column
// layout measured on 22.04.
func TestFreeAgreesWithMeminfo(t *testing.T) {
	p := NewMachine(Ubuntu).NewInterpreter("root")
	mi := execOut(t, p, "cat /proc/meminfo")
	free := execOut(t, p, "free")
	lines := strings.Split(strings.TrimSuffix(free, "\n"), "\n")
	if len(lines) != 3 || lines[0] != "               total        used        free      shared  buff/cache   available" {
		t.Fatalf("free = %q", free)
	}
	if lines[2] != "Swap:              0           0           0" {
		t.Errorf("swap line %q (EC2 images have no swap)", lines[2])
	}
	f := strings.Fields(lines[1])
	if len(lines[1]) != 80 || f[0] != "Mem:" || len(f) != 7 {
		t.Fatalf("mem line %q", lines[1])
	}
	total := meminfoField(t, mi, "MemTotal")
	if f[1] != strconv.FormatInt(total, 10) {
		t.Errorf("free total %s, MemTotal %d", f[1], total)
	}
	// Free memory moves between reads, as on a live box, but within a band.
	used, _ := strconv.ParseInt(f[2], 10, 64)
	if used <= 0 || used >= total {
		t.Errorf("used %d of %d", used, total)
	}
	if got := strings.TrimSpace(execOut(t, p, "free -k | grep Mem | head -1")); !strings.HasPrefix(got, "Mem:") {
		t.Errorf("free -k: %q", got)
	}
	if got := execOut(t, p, "free -m"); !strings.Contains(got, strconv.FormatInt(total/1024, 10)) {
		t.Errorf("free -m total should be %d MiB: %q", total/1024, got)
	}
	if got := execOut(t, p, "free -h"); !strings.Contains(got, "Mi") || !strings.Contains(got, "0B") {
		t.Errorf("free -h: %q", got)
	}
}

// Field order and names are 5.15's fs/proc/meminfo.c (the kernel uname
// reports), not a newer kernel's.
func TestMeminfoHas515Fields(t *testing.T) {
	mi := execOut(t, NewMachine(Ubuntu).NewInterpreter("root"), "cat /proc/meminfo")
	var names []string
	for _, l := range strings.Split(strings.TrimSuffix(mi, "\n"), "\n") {
		name, _, _ := strings.Cut(l, ":")
		names = append(names, name)
	}
	if strings.Join(names[:5], ",") != "MemTotal,MemFree,MemAvailable,Buffers,Cached" || names[len(names)-1] != "DirectMap1G" {
		t.Errorf("fields %v", names)
	}
	for _, newer := range []string{"Zswap", "SecPageTables", "Unaccepted"} {
		if strings.Contains(mi, newer) {
			t.Errorf("%s is not in 5.15", newer)
		}
	}
}

func TestNprocMatchesCpuinfo(t *testing.T) {
	p := NewMachine(Ubuntu).NewInterpreter("root")
	if n, c := execOut(t, p, "nproc"), execOut(t, p, "grep -c ^processor /proc/cpuinfo"); n != c {
		t.Errorf("nproc %q, cpuinfo %q", n, c)
	}
}

// /proc/uptime is read live, so it advances during a session.
func TestProcUptimeAdvances(t *testing.T) {
	m := NewMachine(Ubuntu)
	p := m.NewInterpreter("root")
	first := execOut(t, p, "cat /proc/uptime")
	m.BootTime = m.BootTime.Add(-time.Hour)
	second := execOut(t, p, "cat /proc/uptime")
	a, _ := strconv.ParseFloat(strings.Fields(first)[0], 64)
	b, _ := strconv.ParseFloat(strings.Fields(second)[0], 64)
	if b-a < 3599 || b-a > 3601 {
		t.Errorf("uptime %v then %v", a, b)
	}
}
