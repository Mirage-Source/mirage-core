package shell

import (
	"strings"
	"testing"
)

const aptHead = "Reading package lists...\nBuilding dependency tree...\nReading state information...\n"

// Measured on 22.04's apt 2.4 as root over exec without a pty. This box has
// no working DNS (as wget and curl report), so it can install nothing:
// packages it has are already newest, anything else is not found -- never a
// fake install, which is the SANS ISC 32878 tell.
func TestAptGetLikeAptWithoutNetwork(t *testing.T) {
	for _, tc := range []struct {
		cmd, stdout, stderr string
		code                int
	}{
		{"apt-get install -y qzxvbnmlkjh", aptHead, "E: Unable to locate package qzxvbnmlkjh\n", 100},
		{"apt install -y qzxvbnmlkjh", aptHead, "\nWARNING: apt does not have a stable CLI interface. Use with caution in scripts.\n\nE: Unable to locate package qzxvbnmlkjh\n", 100},
		{"apt-get install", aptHead + "0 upgraded, 0 newly installed, 0 to remove and 47 not upgraded.\n", "", 0},
	} {
		p := NewMachine(Ubuntu).NewInterpreter("root")
		p.aptNotUpgraded = 47
		out, errOut, code, _ := p.RunExec(tc.cmd)
		if out != tc.stdout || errOut != tc.stderr || code != tc.code {
			t.Errorf("%s:\n got  out=%q err=%q code=%d\n want out=%q err=%q code=%d", tc.cmd, out, errOut, code, tc.stdout, tc.stderr, tc.code)
		}
	}

	p := NewMachine(Ubuntu).NewInterpreter("root")
	out, _, code, _ := p.RunExec("apt-get install -y curl")
	if code != 0 || !strings.Contains(out, "curl is already the newest version (") {
		t.Errorf("installed package: %q %d", out, code)
	}
	out, errOut, code, _ := p.RunExec("apt-get update")
	if code != 0 || !strings.HasPrefix(out, "Ign:1 http://us-east-1.ec2.archive.ubuntu.com/ubuntu jammy InRelease\n") ||
		!strings.HasSuffix(errOut, "W: Some index files failed to download. They have been ignored, or old ones used instead.\n") ||
		!strings.Contains(out, "  Temporary failure resolving 'security.ubuntu.com'\n") {
		t.Errorf("update:\n%s\n%s", out, errOut)
	}
	if out, _, code, _ := p.RunExec("apt-get"); code != 1 || !strings.HasPrefix(out, "apt 2.4.10 (amd64)\nUsage: apt-get [options] command\n") {
		t.Errorf("usage: %q %d", out, code)
	}
	_, errOut, code, _ = NewMachine(Ubuntu).NewInterpreter("ubuntu").RunExec("apt-get install -y nmap")
	if code != 100 || errOut != "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\nE: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?\n" {
		t.Errorf("non-root: %q %d", errOut, code)
	}
}
