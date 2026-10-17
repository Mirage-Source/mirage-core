package shell

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// memTotalKB is a 1 GiB EC2 instance's MemTotal under the 5.15 aws kernel
// (what the kernel keeps for itself is not counted). Every box of a type
// reports the same total, so it is fixed rather than drawn per machine.
const memTotalKB = 980300

// memBase is one machine's memory picture; each read drifts a little from
// it, as free memory and page cache do on a live box.
type memBase struct {
	free, buffers, cached, sreclaim, sunreclaim, shmem int64
}

func newMemBase() memBase {
	r := func(lo, hi int64) int64 { return lo + rand.Int63n(hi-lo) }
	return memBase{
		free:       r(70000, 160000),
		buffers:    r(18000, 42000),
		cached:     r(380000, 520000),
		sreclaim:   r(38000, 62000),
		sunreclaim: r(30000, 40000),
		shmem:      r(900, 2600),
	}
}

type memInfo struct {
	total, free, avail, buffers, cached, sreclaim, sunreclaim, shmem int64
}

func (s *Interpreter) memSnapshot() memInfo {
	b := s.mem
	m := memInfo{
		total:      memTotalKB,
		free:       b.free + rand.Int63n(4001) - 2000,
		buffers:    b.buffers + rand.Int63n(41) - 20,
		cached:     b.cached + rand.Int63n(1001) - 500,
		sreclaim:   b.sreclaim,
		sunreclaim: b.sunreclaim,
		shmem:      b.shmem,
	}
	// MemAvailable: free plus what reclaim could give back, less the
	// low watermarks; always under free + buffers + cache.
	m.avail = m.free + m.buffers + m.cached + m.sreclaim - m.shmem - 41000
	return m
}

// meminfoContent is /proc/meminfo in 5.15's fs/proc/meminfo.c order and
// layout: each name padded to 16 columns, the value to 8, then " kB".
func (s *Interpreter) meminfoContent() string {
	m := s.memSnapshot()
	used := m.total - m.free - m.buffers - m.cached - m.sreclaim
	anon := used - m.sreclaim - m.sunreclaim - 9000
	activeFile := m.cached * 45 / 100
	inactiveFile := m.cached + m.buffers - activeFile
	rows := []struct {
		name string
		kb   int64
		unit bool
	}{
		{"MemTotal", m.total, true}, {"MemFree", m.free, true}, {"MemAvailable", m.avail, true},
		{"Buffers", m.buffers, true}, {"Cached", m.cached, true}, {"SwapCached", 0, true},
		{"Active", anon/50 + activeFile, true}, {"Inactive", anon + inactiveFile - anon/50, true},
		{"Active(anon)", anon / 50, true}, {"Inactive(anon)", anon - anon/50, true},
		{"Active(file)", activeFile, true}, {"Inactive(file)", inactiveFile, true},
		{"Unevictable", 27480, true}, {"Mlocked", 27480, true},
		{"SwapTotal", 0, true}, {"SwapFree", 0, true},
		{"Dirty", 60 + rand.Int63n(400), true}, {"Writeback", 0, true},
		{"AnonPages", anon, true}, {"Mapped", 152000 + m.cached/40, true}, {"Shmem", m.shmem, true},
		{"KReclaimable", m.sreclaim, true}, {"Slab", m.sreclaim + m.sunreclaim, true},
		{"SReclaimable", m.sreclaim, true}, {"SUnreclaim", m.sunreclaim, true},
		{"KernelStack", 2240, true}, {"PageTables", 3120, true},
		{"NFS_Unstable", 0, true}, {"Bounce", 0, true}, {"WritebackTmp", 0, true},
		{"CommitLimit", m.total / 2, true}, {"Committed_AS", 870000 + anon/4, true},
		{"VmallocTotal", 34359738367, true}, {"VmallocUsed", 13900, true}, {"VmallocChunk", 0, true},
		{"Percpu", 592, true},
	}
	var b strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&b, "%-16s%8d kB\n", r.name+":", r.kb)
	}
	b.WriteString("HardwareCorrupted:     0 kB\n")
	for _, name := range []string{"AnonHugePages", "ShmemHugePages", "ShmemPmdMapped", "FileHugePages", "FilePmdMapped", "CmaTotal", "CmaFree"} {
		fmt.Fprintf(&b, "%-16s%8d kB\n", name+":", 0)
	}
	for _, name := range []string{"HugePages_Total", "HugePages_Free", "HugePages_Rsvd", "HugePages_Surp"} {
		fmt.Fprintf(&b, "%-16s%8d\n", name+":", 0)
	}
	fmt.Fprintf(&b, "%-16s%8d kB\n", "Hugepagesize:", 2048)
	fmt.Fprintf(&b, "%-16s%8d kB\n", "Hugetlb:", 0)
	fmt.Fprintf(&b, "%-16s%8d kB\n", "DirectMap4k:", 88064)
	fmt.Fprintf(&b, "%-16s%8d kB\n", "DirectMap2M:", 960512)
	fmt.Fprintf(&b, "%-16s%8d kB\n", "DirectMap1G:", 0)
	return b.String()
}

// freeBuiltin is procps-ng 3.3.17's free: cache is Cached + SReclaimable,
// used is what the rest leaves, layout measured on 22.04.
func (s *Interpreter) freeBuiltin(args []string) (string, int) {
	unit := byte('k')
	for _, a := range args {
		switch a {
		case "-b", "--bytes":
			unit = 'b'
		case "-k", "--kibi":
			unit = 'k'
		case "-m", "--mebi":
			unit = 'm'
		case "-g", "--gibi":
			unit = 'g'
		case "-h", "--human":
			unit = 'h'
		default:
			if a != "-w" && a != "--wide" && a != "-l" && a != "-t" {
				return fmt.Sprintf("free: invalid option -- '%s'\r\n\r\nUsage:\r\n free [options]", strings.TrimLeft(a, "-")), 1
			}
		}
	}
	m := s.memSnapshot()
	cache := m.cached + m.sreclaim
	used := m.total - m.free - cache - m.buffers
	f := func(kb int64) string { return scaleSize(kb, unit) }
	return fmt.Sprintf("%-8s%12s %11s %11s %11s %11s %11s\r\n", "", "total", "used", "free", "shared", "buff/cache", "available") +
		fmt.Sprintf("%-8s%12s %11s %11s %11s %11s %11s\r\n", "Mem:", f(m.total), f(used), f(m.free), f(m.shmem), f(m.buffers+cache), f(m.avail)) +
		fmt.Sprintf("%-8s%12s %11s %11s", "Swap:", f(0), f(0), f(0)), 0
}

// scaleSize renders kB in free's units: integer division for -b/-k/-m/-g;
// -h picks the first unit under 1024 and shows one decimal below 10.
func scaleSize(kb int64, unit byte) string {
	switch unit {
	case 'b':
		return fmt.Sprint(kb * 1024)
	case 'm':
		return fmt.Sprint(kb / 1024)
	case 'g':
		return fmt.Sprint(kb / (1024 * 1024))
	case 'h':
		if kb == 0 {
			return "0B"
		}
		v := float64(kb)
		for _, u := range []string{"Ki", "Mi", "Gi", "Ti"} {
			if v < 1024 {
				if v < 10 {
					return fmt.Sprintf("%.1f%s", v, u)
				}
				return fmt.Sprintf("%d%s", int64(v), u)
			}
			v /= 1024
		}
		return fmt.Sprintf("%dPi", int64(v))
	}
	return fmt.Sprint(kb)
}

// nprocBuiltin counts the processors /proc/cpuinfo lists, so the two can
// never disagree.
func (s *Interpreter) nprocBuiltin() (string, int) {
	n := 0
	if _, node := s.lookup("/proc/cpuinfo"); node != nil {
		for _, l := range strings.Split(s.content(node), "\n") {
			if strings.HasPrefix(l, "processor") {
				n++
			}
		}
	}
	return fmt.Sprint(max(n, 1)), 0
}

// uptimeContent is /proc/uptime read now: seconds since boot, then idle
// seconds summed over CPUs (a fixed share of uptime per machine).
func (s *Interpreter) uptimeContent() string {
	up := time.Since(s.BootTime).Seconds()
	return fmt.Sprintf("%.2f %.2f\n", up, up*s.idleRatio)
}
