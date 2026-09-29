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
}

var realApplets = map[string]bool{
	"wget": true, "tftp": true, "ftpget": true, "chmod": true, "rm": true,
	"cp": true, "mv": true, "mkdir": true, "sh": true, "kill": true,
	"dd": true, "nc": true, "sleep": true, "touch": true, "chown": true,
	"ln": true, "mount": true, "sed": true, "awk": true, "tar": true,
}

func (s *Interpreter) busyboxBuiltin(cmd string, args []string, bait *[]BaitHit, action string, stdin *string) (out string, code int, ok bool) {
	if cmd == "sh" {
		return "", 0, true
	}
	if path.Base(cmd) != "busybox" {
		return "", 0, false
	}
	if len(args) == 0 {
		return busyboxUsage, 0, true
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
