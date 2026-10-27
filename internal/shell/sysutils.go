package shell

import (
	"fmt"
	"path"
	"strings"
	"time"
)

// uptimeBuiltin prints procps-ng 3.3.17's uptime (Ubuntu 22.04) from the
// same boot time /proc/uptime uses, so the two always agree.
func (s *Interpreter) uptimeBuiltin(args []string) (string, int) {
	up := time.Since(s.BootTime)
	for _, a := range args {
		switch a {
		case "-s", "--since":
			return s.BootTime.UTC().Format("2006-01-02 15:04:05"), 0
		case "-p", "--pretty":
			return "up " + prettyUptime(up), 0
		case "-V", "--version":
			return "uptime from procps-ng 3.3.17", 0
		case "-h", "--help":
			return "\r\nUsage:\r\n uptime [options]\r\n\r\nOptions:\r\n -p, --pretty   show uptime in pretty format\r\n -h, --help     display this help and exit\r\n -s, --since    system up since\r\n -V, --version  output version information and exit\r\n\r\nFor more details see uptime(1).", 0
		}
	}
	mins := int(up.Minutes())
	days, hours, m := mins/1440, (mins%1440)/60, mins%60
	var span string
	switch {
	case days > 0:
		unit := "days"
		if days == 1 {
			unit = "day"
		}
		span = fmt.Sprintf("%d %s, %2d:%02d", days, unit, hours, m)
	case hours > 0:
		span = fmt.Sprintf("%2d:%02d", hours, m)
	default:
		span = fmt.Sprintf("%d min", m)
	}
	users := "0 users"
	if s.tty {
		users = "1 user"
	}
	// A quiet box: small load averages that depend on the machine, not the call.
	seed := 0
	for _, c := range s.Hostname {
		seed += int(c)
	}
	l1, l5, l15 := float64(seed%9)/100, float64(seed%13)/100+0.01, float64(seed%7)/100+0.02
	return fmt.Sprintf(" %s up %s,  %s,  load average: %.2f, %.2f, %.2f",
		time.Now().UTC().Format("15:04:05"), span, users, l1, l5, l15), 0
}

func prettyUptime(d time.Duration) string {
	mins := int(d.Minutes())
	weeks, days, hours, m := mins/10080, (mins%10080)/1440, (mins%1440)/60, mins%60
	var parts []string
	add := func(n int, unit string) {
		if n == 0 {
			return
		}
		if n != 1 {
			unit += "s"
		}
		parts = append(parts, fmt.Sprintf("%d %s", n, unit))
	}
	add(weeks, "week")
	add(days, "day")
	add(hours, "hour")
	add(m, "minute")
	if len(parts) == 0 {
		return "0 minutes"
	}
	return strings.Join(parts, ", ")
}

// readlinkBuiltin knows the Ubuntu 22.04 merged-/usr symlinks and /bin/sh.
func (s *Interpreter) readlinkBuiltin(args []string) (string, int) {
	canon, quiet := false, false
	var files []string
	for _, a := range args {
		switch {
		case a == "-f" || a == "-e" || a == "-m" || a == "--canonicalize":
			canon = true
		case a == "-n" || a == "-q" || a == "-s" || a == "-v":
			quiet = true
		case strings.HasPrefix(a, "-") && len(a) > 1:
		default:
			files = append(files, a)
		}
	}
	_ = quiet
	if len(files) == 0 {
		return "readlink: missing operand\r\nTry 'readlink --help' for more information.", 1
	}
	var out []string
	code := 0
	for _, f := range files {
		abs := f
		if !strings.HasPrefix(abs, "/") {
			abs = path.Join(s.Cwd, f)
		}
		abs = path.Clean(abs)
		resolved := abs
		for _, p := range []string{"/bin", "/sbin", "/lib", "/lib64"} {
			if abs == p || strings.HasPrefix(abs, p+"/") {
				resolved = "/usr" + abs
				break
			}
		}
		link := resolved != abs || abs == "/usr/bin/sh" || abs == "/bin/sh"
		if resolved == "/usr/bin/sh" {
			resolved = "/usr/bin/dash"
		}
		if _, n := s.lookup(abs); n == nil && !canon {
			code = 1
			continue
		}
		switch {
		case canon:
			if _, n := s.lookup(abs); n == nil && !strings.HasPrefix(abs, "/") {
				code = 1
				continue
			}
			out = append(out, resolved)
		case link:
			switch abs {
			case "/bin", "/sbin", "/lib", "/lib64":
				out = append(out, "usr"+abs)
			case "/bin/sh":
				out = append(out, "dash")
			}
		default:
			code = 1
		}
	}
	return strings.Join(out, "\r\n"), code
}

// chattrBuiltin: root changing attributes on an ext4 file prints nothing.
func (s *Interpreter) chattrBuiltin(args []string) (string, int) {
	var files []string
	sawMode := false
	for _, a := range args {
		switch {
		case a == "-R" || a == "-V" || a == "-f" || strings.HasPrefix(a, "-v") && false:
		case !sawMode && len(a) > 1 && (a[0] == '+' || a[0] == '-' || a[0] == '='):
			sawMode = true
		default:
			files = append(files, a)
		}
	}
	if !sawMode || len(files) == 0 {
		return "Usage: chattr [-pRVf] [-+=aAcCdDeijPsStTu] [-v version] files...", 1
	}
	var errs []string
	for _, f := range files {
		if _, n := s.lookup(f); n == nil {
			errs = append(errs, "chattr: No such file or directory while trying to stat "+f)
		}
	}
	if len(errs) > 0 {
		return strings.Join(errs, "\r\n"), 1
	}
	return "", 0
}

// sudoBuiltin runs the command: this honeypot's users have passwordless sudo
// (the EC2 default) and the shell has no other users to become.
func (s *Interpreter) sudoBuiltin(args []string, bait *[]BaitHit, action string, stdin *string) (string, int) {
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			i++
			goto run
		case a == "-u" || a == "-g" || a == "-h" && false || a == "-p" || a == "-C" || a == "-D" || a == "-R" || a == "-r" || a == "-t" || a == "-U":
			i++
		case a == "-l" || a == "-ll":
			host := s.Hostname
			return fmt.Sprintf("Matching Defaults entries for %s on %s:\r\n    env_reset, mail_badpass,\r\n    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin,\r\n    use_pty\r\n\r\nUser %s may run the following commands on %s:\r\n    (ALL : ALL) ALL\r\n    (ALL) NOPASSWD: ALL", s.Username, host, s.Username, host), 0
		case a == "-V":
			return "Sudo version 1.9.9\r\nSudoers policy plugin version 1.9.9\r\nSudoers file grammar version 48\r\nSudoers I/O plugin version 1.9.9\r\nSudoers audit plugin version 1.9.9", 0
		case strings.HasPrefix(a, "-"):
		default:
			goto run
		}
	}
run:
	if i >= len(args) {
		return "usage: sudo -h | -K | -k | -V\r\nusage: sudo -v [-ABkNnS] [-g group] [-h host] [-p prompt] [-u user]\r\nusage: sudo -l [-ABkNnS] [-g group] [-h host] [-p prompt] [-U user] [-u user] [command [arg ...]]\r\nusage: sudo [-ABbEHKkPS] [-r role] [-t type] [-C num] [-D directory] [-g group] [-h host] [-p prompt] [-R directory] [-T timeout] [-u user] [VAR=value] [-i | -s] [<command>]\r\nusage: sudo -e [-ABkNnS] [-r role] [-t type] [-C num] [-D directory] [-g group] [-h host] [-p prompt] [-R directory] [-T timeout] [-u user] file ...", 1
	}
	return s.execBuiltin(args[i], args[i+1:], bait, action, stdin)
}
