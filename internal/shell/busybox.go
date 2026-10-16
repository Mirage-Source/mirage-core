package shell

import (
	_ "embed"
	"path"
	"strings"
)

//go:embed busybox_usage.txt
var busyboxUsageRaw string

var busyboxUsage = strings.TrimRight(busyboxUsageRaw, "\n")

var emulatedApplets = map[string]bool{
	"echo": true, "cat": true, "ls": true, "grep": true, "head": true,
	"tail": true, "wc": true, "which": true, "find": true, "ps": true,
	"netstat": true, "uname": true, "hostname": true, "id": true,
	"whoami": true, "pwd": true, "test": true, "[": true,
	"dd": true, "more": true, "ping": true, "su": true,
	"wget": true, "tftp": true, "ftpget": true,
}

func (s *Interpreter) busyboxBannerLine() string {
	if s.profile.busyboxBanner != "" {
		return s.profile.busyboxBanner
	}
	line, _, _ := strings.Cut(busyboxUsage, "\n")
	return line
}

func hasOperand(args []string) bool {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return true
		}
	}
	return false
}

var realApplets = map[string]bool{
	"chmod": true, "rm": true,
	"cp": true, "mv": true, "mkdir": true, "sh": true, "kill": true,
	"nc": true, "sleep": true, "touch": true, "chown": true,
	"ln": true, "mount": true, "sed": true, "awk": true, "tar": true,
}

func (s *Interpreter) busyboxBuiltin(cmd string, args []string, bait *[]BaitHit, action string, stdin *string) (out string, code int, ok bool) {
	switch {
	case cmd == "sh", cmd == "su": // su: the shell is already root
		return "", 0, true
	case cmd == "ping" && !hasOperand(args):
		return s.busyboxBannerLine() + dvrPingUsage, 1, true
	case cmd == "wget", cmd == "tftp", cmd == "ftpget":
		out, code := s.busyboxDownload(cmd, args)
		return out, code, true
	case cmd == "hostname" && hasOperand(args):
		s.Hostname = args[len(args)-1]
		return "", 0, true
	}
	if path.Base(cmd) != "busybox" {
		return "", 0, false
	}
	if len(args) == 0 {
		return s.busyboxBannerLine() + busyboxUsage[strings.Index(busyboxUsage, "\n"):], 0, true
	}
	applet := args[0]
	switch {
	case emulatedApplets[applet]:
		out, code = s.execBuiltin(applet, args[1:], bait, action, stdin)
		return out, code, true
	case realApplets[applet]:
		return "", 0, true
	default:
		return applet + ": applet not found", 127, true
	}
}
