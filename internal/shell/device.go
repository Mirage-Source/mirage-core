package shell

import (
	"fmt"
	"strings"
)

// DVR is the telnet sensor's identity: a XiongMai-style DVR on a HiSilicon
// Hi3520DV400 (Cortex-A7, armv7l) running BusyBox 1.20.2 ash, logged in as
// root with home /. Mirai-family bots, which make up nearly all telnet
// traffic, open with device-console words and choose their payload from
// uname and ELF headers, so every surface here describes that one device.
// The factory hostname is the same on every unit, so it is not randomised.
var DVR = &Profile{
	fs:           dvrFS,
	hostname:     func() string { return "LocalHost" },
	sysname:      "Linux",
	release:      "3.10.0",
	version:      "#1 SMP Thu Mar 8 15:40:28 CST 2018",
	machine:      "armv7l",
	busyboxUname: true,
	msgs: shellMsgs{
		notFound:    "-sh: %s: not found",
		execMissing: "-sh: %s: not found",
		execIsDir:   "-sh: %s: Permission denied",
		execPerm:    "-sh: %s: Permission denied",
		createNoDir: "-sh: can't create %s: nonexistent directory",
		createIsDir: "-sh: can't create %s: Is a directory",
		openMissing: "-sh: can't open %s: no such file",
		syntaxEOF:   "-sh: syntax error: unexpected end of file",
		syntaxToken: `-sh: syntax error: unexpected "%s"`,
		createRO:    "-sh: can't create %s: Read-only file system",
	},
	// The tmpfs and jffs2 mounts in /proc/mounts; / is squashfs.
	writable:      []string{"/tmp", "/var", "/dev", "/mnt/mtd"},
	allRoot:       true,
	home:          "/",
	busybox:       true,
	busyboxBanner: "BusyBox v1.20.2 (2018-03-08 15:32:11 CST) multi-call binary.",
	prompt:        func(*Interpreter) string { return "# " },
	ps:            dvrPS,
}

// elf32ARMHeader is the 52-byte ELF32 header of a little-endian ARM EABI5
// executable, as on a BusyBox built with the HiSilicon soft-float toolchain.
// `dd bs=52 count=1` reads exactly this much.
const elf32ARMHeader = "\x7fELF\x01\x01\x01\x00" + "\x00\x00\x00\x00\x00\x00\x00\x00" + // e_ident
	"\x02\x00" + "\x28\x00" + "\x01\x00\x00\x00" + // ET_EXEC, EM_ARM, EV_CURRENT
	"\xd8\xc1\x00\x00" + // e_entry
	"\x34\x00\x00\x00" + // e_phoff
	"\x10\x0f\x0d\x00" + // e_shoff
	"\x00\x02\x00\x05" + // e_flags: EABI5, soft-float
	"\x34\x00" + "\x20\x00" + "\x07\x00" + // e_ehsize, e_phentsize, e_phnum
	"\x28\x00" + "\x1a\x00" + "\x19\x00" // e_shentsize, e_shnum, e_shstrndx

// dvrApplets are the /bin entries, all links to busybox on a real image.
var dvrApplets = []string{
	"ash", "busybox", "cat", "chmod", "cp", "date", "dd", "df", "dmesg", "echo",
	"ftpget", "grep", "hostname", "kill", "ln", "ls", "mkdir", "mount", "mv",
	"ping", "ps", "pwd", "rm", "sed", "sh", "sleep", "tftp", "touch", "umount",
	"uname", "vi", "wget",
}

func armBinary(size int64) *Node {
	return &Node{Type: NodeFile, Mode: "-rwxr-xr-x", Owner: "root", Group: "root", MTime: "Mar  8  2018", Size: size, Content: elf32ARMHeader}
}

func armLink() *Node {
	n := armBinary(7)
	n.Mode = "lrwxrwxrwx"
	return n
}

func dvrDir(children ...string) *Node {
	return &Node{Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "Mar  8  2018", Total: 0, Children: children}
}

func dvrFile(mode, content string) *Node {
	return &Node{Type: NodeFile, Mode: mode, Owner: "root", Group: "root", MTime: "Mar  8  2018", Content: content}
}

var dvrFS = func() map[string]*Node {
	m := map[string]*Node{
		"/":               dvrDir("bin", "dev", "etc", "home", "lib", "linuxrc", "mnt", "proc", "root", "sbin", "sys", "tmp", "usr", "var"),
		"/bin":            dvrDir(dvrApplets...),
		"/linuxrc":        armLink(),
		"/dev":            dvrDir("console", "null", "shm", "tty", "ttyAMA0", "urandom", "watchdog", "zero"),
		"/dev/shm":        dvrDir(),
		"/etc":            dvrDir("group", "hosts", "init.d", "inittab", "passwd", "profile", "shadow"),
		"/etc/group":      dvrFile("-rw-r--r--", "root:x:0:\n"),
		"/etc/hosts":      dvrFile("-rw-r--r--", "127.0.0.1\tlocalhost\n"),
		"/etc/init.d":     dvrDir("rcS"),
		"/etc/init.d/rcS": dvrFile("-rwxr-xr-x", "#! /bin/sh\n\nmount -a\nmkdir -p /var/run /var/tmp\ntelnetd &\n/usr/bin/Sofia &\n"),
		"/etc/inittab":    dvrFile("-rw-r--r--", "::sysinit:/etc/init.d/rcS\n::respawn:-/bin/sh\n::restart:/sbin/init\n"),
		"/etc/passwd":     dvrFile("-rw-r--r--", "root:x:0:0:root:/:/bin/sh\n"),
		"/etc/profile":    dvrFile("-rw-r--r--", "export PATH=/bin:/sbin:/usr/bin:/usr/sbin\nexport PS1='# '\n"),
		"/etc/shadow": {
			Type: NodeFile, Mode: "-rw-------", Owner: "root", Group: "root", MTime: "Mar  8  2018",
			Content: "root:$1$OYvRjwfm$7d5U2gW1sDfHgW/tWy3Xh0:17598:0:99999:7:::\n",
			Bait:    &BaitInfo{BaitID: "etc-shadow", BaitType: "shadow"},
		},
		"/home":    dvrDir(),
		"/lib":     dvrDir(),
		"/mnt":     dvrDir("mtd"),
		"/mnt/mtd": dvrDir(),
		"/proc":    dvrDir("cpuinfo", "meminfo", "mounts", "self", "uptime", "version"),
		"/proc/cpuinfo": dvrFile("-r--r--r--", strings.Join([]string{
			"processor\t: 0",
			"model name\t: ARMv7 Processor rev 5 (v7l)",
			"BogoMIPS\t: 1196.03",
			"Features\t: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm",
			"CPU implementer\t: 0x41",
			"CPU architecture: 7",
			"CPU variant\t: 0x0",
			"CPU part\t: 0xc07",
			"CPU revision\t: 5",
			"",
			"Hardware\t: hi3520dv400",
			"Revision\t: 0000",
			"Serial\t\t: 0000000000000000",
		}, "\n")),
		"/proc/meminfo": dvrFile("-r--r--r--", "MemTotal:         177208 kB\nMemFree:           61436 kB\nBuffers:               0 kB\nCached:            39960 kB\n"),
		"/proc/mounts": dvrFile("-r--r--r--", strings.Join([]string{
			"rootfs / squashfs ro,relatime 0 0",
			"proc /proc proc rw,relatime 0 0",
			"sysfs /sys sysfs rw,relatime 0 0",
			"tmpfs /dev tmpfs rw,relatime 0 0",
			"tmpfs /dev/shm tmpfs rw,relatime 0 0",
			"tmpfs /var tmpfs rw,relatime 0 0",
			"tmpfs /tmp tmpfs rw,relatime 0 0",
			"/dev/mtdblock3 /mnt/mtd jffs2 rw,relatime 0 0",
		}, "\n")),
		"/proc/self":     dvrDir("exe"),
		"/proc/self/exe": armBinary(1103360),
		"/proc/version": dvrFile("-r--r--r--",
			"Linux version 3.10.0 (root@localhost) (gcc version 4.9.4 20150629 (prerelease) (Hisilicon_v500_20170922) ) #1 SMP Thu Mar 8 15:40:28 CST 2018"),
		"/root":             dvrDir(),
		"/sbin":             dvrDir("ifconfig", "init", "reboot", "route"),
		"/sys":              dvrDir(),
		"/tmp":              dvrDir(),
		"/usr":              dvrDir("bin", "sbin"),
		"/usr/bin":          dvrDir("Sofia"),
		"/usr/sbin":         dvrDir("telnetd"),
		"/var":              dvrDir("log", "run", "tmp"),
		"/var/log":          dvrDir(),
		"/var/run":          dvrDir(),
		"/var/tmp":          dvrDir(),
		"/usr/bin/Sofia":    armBinary(4893144),
		"/usr/sbin/telnetd": armLink(),
	}
	for _, a := range dvrApplets {
		m["/bin/"+a] = armLink()
	}
	m["/bin/busybox"] = armBinary(1103360)
	for _, d := range []string{"console", "null", "tty", "ttyAMA0", "urandom", "watchdog", "zero"} {
		m["/dev/"+d] = dvrFile("crw-rw-rw-", "")
	}
	for _, b := range []string{"ifconfig", "init", "reboot", "route"} {
		m["/sbin/"+b] = armLink()
	}
	return m
}()

func dvrPS(s *Interpreter) string {
	rows := []string{
		"  PID USER       VSZ STAT COMMAND",
		"    1 root      1832 S    init",
		"    2 root         0 SW   [kthreadd]",
		"    3 root         0 SW   [ksoftirqd/0]",
		"    5 root         0 SW<  [kworker/0:0H]",
		"    7 root         0 SW   [rcu_preempt]",
		"  498 root      1836 S    telnetd",
		"  512 root     84020 S    /usr/bin/Sofia",
		fmt.Sprintf("%5d root      1840 S    -sh", s.pids["bash"]),
		fmt.Sprintf("%5d root      1836 R    ps", s.pids["ps"]),
	}
	return strings.Join(rows, "\r\n")
}

// dvrPingUsage is BusyBox 1.20 ping's usage text, printed with no host.
const dvrPingUsage = `

Usage: ping [OPTIONS] HOST

Send ICMP ECHO_REQUEST packets to network hosts

	-4,-6		Force IP or IPv6 name resolution
	-c CNT		Send only CNT pings
	-s SIZE		Send SIZE data bytes in packets (default:56)
	-I IFACE/IP	Use interface or IP address as source
	-W SEC		Seconds to wait for the first response (default:10)
			(after all -c CNT packets are sent)
	-w SEC		Seconds until ping exits (default:infinite)
			(can exceed -c CNT, -W SEC)
	-q		Quiet, only displays output at start
			and when finished`

// busyboxDownload fails wget, tftp and ftpget the way BusyBox does on a box
// with no route out: literal IPs time out, hostnames do not resolve.
func (s *Interpreter) busyboxDownload(cmd string, args []string) (string, int) {
	var ops []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case len(a) == 2 && a[0] == '-' && strings.ContainsRune("OPTUYrlpP", rune(a[1])):
			i++ // flag with a value
		case strings.HasPrefix(a, "-"):
		default:
			ops = append(ops, a)
		}
	}
	if len(ops) == 0 {
		return s.busyboxBannerLine() + "\n\nUsage: " + cmd + " [OPTIONS] HOST", 1
	}
	raw := ops[0]
	if cmd == "wget" {
		raw = ops[len(ops)-1]
	}
	t, ok := parseTarget(raw)
	if !ok || !t.isIP {
		host := t.host
		if !ok {
			host = raw
		}
		return cmd + ": bad address '" + host + "'", 1
	}
	refused := cmd + ": can't connect to remote host (" + t.host + "): Connection timed out"
	switch cmd {
	case "tftp":
		return "tftp: timeout", 1
	case "wget":
		hostport, _, _ := strings.Cut(t.raw[strings.Index(t.raw, "://")+3:], "/")
		return "Connecting to " + hostport + " (" + t.host + ":" + t.port + ")\r\n" + refused, 1
	}
	return refused, 1
}
