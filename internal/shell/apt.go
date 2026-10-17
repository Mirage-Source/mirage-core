package shell

import (
	"fmt"
	"strings"
)

// aptInstalled is what this box already has, at the versions 22.04.3 shipped
// (openssh-server matches the SSH banner).
var aptInstalled = map[string]string{
	"bash": "5.1-6ubuntu1", "coreutils": "8.32-4.1ubuntu1", "curl": "7.81.0-1ubuntu1.13",
	"wget": "1.21.2-2ubuntu1", "perl": "5.34.0-3ubuntu1.2", "python3": "3.10.6-1~22.04",
	"git": "1:2.34.1-1ubuntu1.10", "nginx": "1.18.0-6ubuntu14.4", "openssh-server": "1:8.9p1-3ubuntu0.6",
	"openssh-client": "1:8.9p1-3ubuntu0.6", "sudo": "1.9.9-1ubuntu2.4", "tar": "1.34+dfsg-1ubuntu0.1.22.04.1",
	"gzip": "1.10-4ubuntu4.1", "cron": "3.0pl1-137ubuntu3", "nano": "6.2-1", "vim": "2:8.2.3995-1ubuntu2.11",
	"mawk": "1.3.4.20200120-3", "dash": "0.5.11+git20210903+057cd650a4ed-3build1", "apt": "2.4.10",
}

const aptMirror = "us-east-1.ec2.archive.ubuntu.com"

const aptGetUsage = `apt 2.4.10 (amd64)
Usage: apt-get [options] command
       apt-get [options] install|remove pkg1 [pkg2 ...]
       apt-get [options] source pkg1 [pkg2 ...]

apt-get is a command line interface for retrieval of packages
and information about them from authenticated sources and
for installation, upgrade and removal of packages together
with their dependencies.

Most used commands:
  update - Retrieve new lists of packages
  upgrade - Perform an upgrade
  install - Install new packages (pkg is libc6 not libc6.deb)
  reinstall - Reinstall packages (pkg is libc6 not libc6.deb)
  remove - Remove packages
  purge - Remove packages and config files
  autoremove - Remove automatically all unused packages
  dist-upgrade - Distribution upgrade, see apt-get(8)
  dselect-upgrade - Follow dselect selections
  build-dep - Configure build-dependencies for source packages
  satisfy - Satisfy dependency strings
  clean - Erase downloaded archive files
  autoclean - Erase old downloaded archive files
  check - Verify that there are no broken dependencies
  source - Download source archives
  download - Download the binary package into the current directory
  changelog - Download and display the changelog for the given package

See apt-get(8) for more information about the available commands.
Configuration options and syntax is detailed in apt.conf(5).
Information about how to configure sources can be found in sources.list(5).
Package and version choices can be expressed via apt_preferences(5).
Security details are available in apt-secure(8).
                                        This APT has Super Cow Powers.`

const aptUsage = `apt 2.4.10 (amd64)
Usage: apt [options] command

apt is a commandline package manager and provides commands for
searching and managing as well as querying information about packages.
It provides the same functionality as the specialized APT tools,
like apt-get and apt-cache, but enables options more suitable for
interactive use by default.

Most used commands:
  list - list packages based on package names
  search - search in package descriptions
  show - show package details
  install - install packages
  reinstall - reinstall packages
  remove - remove packages
  autoremove - Remove automatically all unused packages
  update - update list of available packages
  upgrade - upgrade the system by installing/upgrading packages
  full-upgrade - upgrade the system by removing/installing/upgrading packages
  edit-sources - edit the source information file
  satisfy - satisfy dependency strings

See apt(8) for more information about the available commands.
Configuration options and syntax is detailed in apt.conf(5).
Information about how to configure sources can be found in sources.list(5).
Package and version choices can be expressed via apt_preferences(5).
Security details are available in apt-secure(8).
                                        This APT has Super Cow Powers.`

// aptBuiltin is apt-get/apt 2.4 on a box with no DNS (see wgetBuiltin): it
// installs nothing, and says so the way apt does. Messages measured on
// 22.04; without a tty apt drops the " Done" after each progress line, and
// apt (not apt-get) warns on stderr.
func (s *Interpreter) aptBuiltin(cmd string, args []string) (string, int) {
	var sub string
	var pkgs []string
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "-"):
		case sub == "":
			sub = a
		default:
			pkgs = append(pkgs, a)
		}
	}
	if sub == "" {
		usage := aptGetUsage
		if cmd == "apt" {
			usage = aptUsage
		}
		return strings.ReplaceAll(usage, "\n", "\r\n"), 1
	}
	if cmd == "apt" && !s.tty {
		s.pendingErr = append(s.pendingErr, "", "WARNING: apt does not have a stable CLI interface. Use with caution in scripts.", "")
	}
	done := ""
	if s.tty {
		done = " Done"
	}
	head := []string{"Reading package lists..." + done, "Building dependency tree..." + done, "Reading state information..." + done}
	summary := fmt.Sprintf("0 upgraded, 0 newly installed, 0 to remove and %d not upgraded.", s.aptNotUpgraded)

	switch sub {
	case "update":
		if s.Username != "root" {
			s.pendingErr = append(s.pendingErr, "E: Could not open lock file /var/lib/apt/lists/lock - open (13: Permission denied)", "E: Unable to lock directory /var/lib/apt/lists/")
			return "Reading package lists..." + done, 100
		}
		sources := []struct{ host, suite string }{
			{aptMirror, "jammy"}, {"security.ubuntu.com", "jammy-security"},
			{aptMirror, "jammy-updates"}, {aptMirror, "jammy-backports"},
		}
		var out []string
		for try := 0; try < 3; try++ {
			for i, src := range sources {
				out = append(out, fmt.Sprintf("Ign:%d http://%s/ubuntu %s InRelease", i+1, src.host, src.suite))
			}
		}
		for i, src := range sources {
			out = append(out, fmt.Sprintf("Err:%d http://%s/ubuntu %s InRelease", i+1, src.host, src.suite),
				fmt.Sprintf("  Temporary failure resolving '%s'", src.host))
		}
		out = append(out, "Reading package lists..."+done)
		for _, i := range []int{0, 2, 3, 1} {
			src := sources[i]
			s.pendingErr = append(s.pendingErr, fmt.Sprintf("W: Failed to fetch http://%s/ubuntu/dists/%s/InRelease  Temporary failure resolving '%s'", src.host, src.suite, src.host))
		}
		s.pendingErr = append(s.pendingErr, "W: Some index files failed to download. They have been ignored, or old ones used instead.")
		return strings.Join(out, "\r\n"), 0

	case "install", "reinstall", "remove", "purge", "upgrade", "dist-upgrade", "full-upgrade", "autoremove":
		if s.Username != "root" {
			s.pendingErr = append(s.pendingErr, "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)", "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?")
			return "", 100
		}
		out := head
		missing := false
		for _, p := range pkgs {
			v, ok := aptInstalled[p]
			switch {
			case !ok && (sub == "remove" || sub == "purge"):
				out = append(out, fmt.Sprintf("Package '%s' is not installed, so not removed", p))
			case !ok:
				s.pendingErr = append(s.pendingErr, "E: Unable to locate package "+p)
				missing = true
			case sub == "install" || sub == "reinstall":
				out = append(out, fmt.Sprintf("%s is already the newest version (%s).", p, v))
			}
		}
		if missing {
			return strings.Join(out, "\r\n"), 100
		}
		return strings.Join(append(out, summary), "\r\n"), 0
	}
	s.pendingErr = append(s.pendingErr, "E: Invalid operation "+sub)
	return "", 100
}
