package shell

import (
	"fmt"
	"path"
	"strings"

	"github.com/mirage-source/mirage-core/internal/session"
)

// NodeType distinguishes files from directories in the simulated filesystem.
type NodeType int

const (
	NodeFile NodeType = iota
	NodeDir
)

// BaitInfo marks a node as a planted lure. Any command that reads or lists it
// reports the interaction back to the caller so it can be recorded.
//
// Hidden nodes are only visible in `ls` output and readable via `cat` on the
// turn the deception policy decides SURFACE_BAIT — see ConditionalChildren
// below. Zero value (false) is today's behavior: unconditionally
// visible/readable, which is why the two original bait nodes (.env, id_rsa)
// need no changes to keep working exactly as before.
type BaitInfo struct {
	BaitID   string
	BaitType session.BaitType
	Hidden   bool
}

// ConditionalChild is a directory entry only shown in `ls` output when the
// deception policy's decided action for that turn matches Action (e.g.
// "ENRICH" or "SURFACE_BAIT"). The node itself always exists in fs (so a
// direct `cat`/`cd` by a known name still works, same realism as any other
// bait node) -- this only governs whether it shows up during exploration.
// A slice, not a map, so listing order (and therefore output) is
// deterministic.
type ConditionalChild struct {
	Name   string
	Action string
}

// Node is a single file or directory in the simulated filesystem. Every
// directory's Children list is the single source of truth for what `ls`
// shows — there is no separate listing table that can drift out of sync.
type Node struct {
	Path                string // this node's own cleaned absolute path, set by init()
	Type                NodeType
	Mode                string
	Owner               string
	Group               string
	Size                int64
	MTime               string
	Content             string             // files only
	EnrichedContent     string             // files only; used instead of Content when action is ENRICH
	Children            []string           // dirs only, ordered basenames, always shown
	ConditionalChildren []ConditionalChild // dirs only, shown only for a matching action
	Bait                *BaitInfo
	Total               int // dirs only, the "total N" ls header value
}

// fs is keyed by cleaned absolute path. Every path referenced as a child
// anywhere in this map must have its own entry — that invariant is what
// keeps `ls`, `cd`, and `cat` from contradicting each other.
var fs = map[string]*Node{
	"/": {
		Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Total: 68,
		Children: []string{"bin", "boot", "dev", "etc", "home", "lib", "lib64", "opt", "proc", "root", "run", "sbin", "srv", "tmp", "usr", "var"},
	},
	"/bin":   emptySystemDir(),
	"/boot":  emptySystemDir(),
	"/dev":   emptySystemDir(),
	"/lib":   emptySystemDir(),
	"/lib64": emptySystemDir(),
	"/opt":   emptySystemDir(),
	"/proc": {
		Type: NodeDir, Mode: "dr-xr-xr-x", Owner: "root", Group: "root", MTime: "Jul 11 09:11", Total: 0,
		Children: []string{"version", "cpuinfo", "uptime"},
	},
	"/proc/version": {
		Type: NodeFile, Mode: "-r--r--r--", Owner: "root", Group: "root", MTime: "Jul 11 09:11",
		Content: "Linux version 5.15.0-1031-aws (buildd@lcy02-amd64-059) (gcc (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #35-Ubuntu SMP Fri Feb 10 02:07:19 UTC 2023",
	},
	"/proc/cpuinfo": {
		Type: NodeFile, Mode: "-r--r--r--", Owner: "root", Group: "root", MTime: "Jul 11 09:11",
		Content: "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm",
	},
	"/proc/uptime": {
		Type: NodeFile, Mode: "-r--r--r--", Owner: "root", Group: "root", MTime: "Jul 11 09:11",
		Content: "1284213.42 1198021.11",
	},
	"/root": {
		Type: NodeDir, Mode: "drwx------", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Total: 0,
	},
	"/run":  emptySystemDir(),
	"/sbin": emptySystemDir(),
	"/srv":  emptySystemDir(),
	"/tmp": {
		Type: NodeDir, Mode: "drwxrwxrwt", Owner: "root", Group: "root", MTime: "Jul 11 09:11", Total: 0,
	},
	"/usr": emptySystemDir(),
	"/home": {
		Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Total: 4,
		Children: []string{"ubuntu"},
	},
	"/home/ubuntu": {
		Type: NodeDir, Mode: "drwxr-xr-x", Owner: "ubuntu", Group: "ubuntu", MTime: "May 29 14:02", Total: 36,
		Children: []string{".bash_history", ".bashrc", ".cache", "django-app", ".env", ".ssh", ".profile"},
		ConditionalChildren: []ConditionalChild{
			{Name: ".python_history", Action: "ENRICH"},
			{Name: ".aws", Action: "SURFACE_BAIT"},
		},
	},
	"/home/ubuntu/.bash_history": {
		Type: NodeFile, Mode: "-rw-------", Owner: "ubuntu", Group: "ubuntu", MTime: "Jan 12 09:11",
		Content: strings.Join([]string{
			"sudo apt update",
			"sudo apt install python3-pip",
			"git clone https://github.com/company/django-app.git",
			"cd django-app",
			"pip3 install -r requirements.txt",
			"python3 manage.py migrate",
			"python3 manage.py runserver 0.0.0.0:8000",
			"sudo systemctl status nginx",
			"cat /etc/nginx/sites-enabled/default",
			"sudo nano /etc/nginx/sites-enabled/default",
			"sudo systemctl restart nginx",
			"ls -la",
			"cd /home/ubuntu",
			"cat .env",
		}, "\n"),
	},
	"/home/ubuntu/.bashrc": {
		Type: NodeFile, Mode: "-rw-r--r--", Owner: "ubuntu", Group: "ubuntu", MTime: "Jan 12 09:11", Size: 3526,
		Content: "# ~/.bashrc: executed by bash(1) for non-login shells.\nexport PATH=\"$HOME/.local/bin:$PATH\"\nHISTCONTROL=ignoreboth\n",
	},
	"/home/ubuntu/.cache": {
		Type: NodeDir, Mode: "drwx------", Owner: "ubuntu", Group: "ubuntu", MTime: "Jan 12 09:11", Total: 0,
	},
	"/home/ubuntu/django-app": {
		Type: NodeDir, Mode: "drwxrwxr-x", Owner: "ubuntu", Group: "ubuntu", MTime: "May 29 13:44", Total: 8,
		Children: []string{"manage.py", "requirements.txt"},
	},
	"/home/ubuntu/django-app/manage.py": {
		Type: NodeFile, Mode: "-rwxrwxr-x", Owner: "ubuntu", Group: "ubuntu", MTime: "May 29 13:44",
		Content: "#!/usr/bin/env python\nimport os, sys\nif __name__ == '__main__':\n    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'app.settings')\n    from django.core.management import execute_from_command_line\n    execute_from_command_line(sys.argv)\n",
	},
	"/home/ubuntu/django-app/requirements.txt": {
		Type: NodeFile, Mode: "-rw-rw-r--", Owner: "ubuntu", Group: "ubuntu", MTime: "May 29 13:44",
		Content: "Django==4.2.7\ngunicorn==21.2.0\npsycopg2-binary==2.9.9\n",
	},
	"/home/ubuntu/.env": {
		Type: NodeFile, Mode: "-rw-rw-r--", Owner: "ubuntu", Group: "ubuntu", MTime: "May 29 13:51", Size: 312,
		Content: strings.Join([]string{
			"DJANGO_SECRET_KEY=8f3b2c1a9d7e6f4b0a2c5d8e1f3a6b9c",
			"DATABASE_URL=postgres://django_app:Prod_db_2024!@10.0.4.12:5432/appdb",
			"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
			"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			"STRIPE_API_KEY=<rotated-see-1password-prod-vault>",
		}, "\n"),
		Bait: &BaitInfo{BaitID: "home-env-file", BaitType: session.BaitTypeEnvFile},
	},
	"/home/ubuntu/.python_history": {
		Type: NodeFile, Mode: "-rw-------", Owner: "ubuntu", Group: "ubuntu", MTime: "May 29 13:47",
		Content: strings.Join([]string{
			"import django",
			"django.VERSION",
			"from django.conf import settings",
			"settings.DATABASES",
			"exit()",
		}, "\n"),
	},
	"/home/ubuntu/.aws": {
		Type: NodeDir, Mode: "drwx------", Owner: "ubuntu", Group: "ubuntu", MTime: "May 29 13:40", Total: 4,
		Children: []string{"credentials"},
	},
	"/home/ubuntu/.aws/credentials": {
		Type: NodeFile, Mode: "-rw-------", Owner: "ubuntu", Group: "ubuntu", MTime: "May 29 13:40", Size: 116,
		Content: strings.Join([]string{
			"[default]",
			"aws_access_key_id=AKIAQXJ3EXAMPLEKEY9",
			"aws_secret_access_key=k3vQ/EXAMPLEnotarealsecretkeyDoNotUse1234567",
		}, "\n"),
		Bait: &BaitInfo{BaitID: "home-aws-credentials", BaitType: session.BaitTypeCredential, Hidden: true},
	},
	"/home/ubuntu/.profile": {
		Type: NodeFile, Mode: "-rw-r--r--", Owner: "ubuntu", Group: "ubuntu", MTime: "Jan 12 09:11", Size: 675,
		Content: "# ~/.profile: executed by the command interpreter for login shells.\n",
	},
	"/home/ubuntu/.ssh": {
		Type: NodeDir, Mode: "drwx------", Owner: "ubuntu", Group: "ubuntu", MTime: "Jan 12 09:11", Total: 12,
		Children: []string{"authorized_keys", "id_rsa", "id_rsa.pub"},
	},
	"/home/ubuntu/.ssh/authorized_keys": {
		Type: NodeFile, Mode: "-rw-------", Owner: "ubuntu", Group: "ubuntu", MTime: "Jan 12 09:11",
		Content: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE0000000000000000000000000000 ubuntu@ip-172-31-14-52\n",
	},
	"/home/ubuntu/.ssh/id_rsa": {
		Type: NodeFile, Mode: "-rw-------", Owner: "ubuntu", Group: "ubuntu", MTime: "Jan 12 09:11",
		Content: "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
			"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n" +
			"NhAAAAAwEAAQAAAYEAtNOTREPLACEDONOTUSEEXAMPLEKEYMATERIALONLYqwertyuiop\n" +
			"-----END OPENSSH PRIVATE KEY-----\n",
		Bait: &BaitInfo{BaitID: "home-ssh-private-key", BaitType: session.BaitTypePrivateKey},
	},
	"/home/ubuntu/.ssh/id_rsa.pub": {
		Type: NodeFile, Mode: "-rw-r--r--", Owner: "ubuntu", Group: "ubuntu", MTime: "Jan 12 09:11",
		Content: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC00EXAMPLE0000000000000000000000 ubuntu@ip-172-31-14-52\n",
	},
	"/etc": {
		Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "May 29 14:01", Total: 212,
		Children: []string{"adduser.conf", "apt", "bash.bashrc", "cron.d", "hosts", "hostname", "nsswitch.conf", "os-release", "passwd", "shadow", "nginx", "ssh", "systemd"},
	},
	"/etc/adduser.conf": {Type: NodeFile, Mode: "-rw-r--r--", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Size: 2981, Content: "# /etc/adduser.conf\nDSHELL=/bin/bash\n"},
	"/etc/apt":          {Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Total: 4},
	"/etc/bash.bashrc":  {Type: NodeFile, Mode: "-rw-r--r--", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Size: 367, Content: "# System-wide .bashrc\n"},
	"/etc/cron.d":       {Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "May 29 14:01", Total: 4},
	"/etc/hosts": {
		Type: NodeFile, Mode: "-rw-r--r--", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Size: 1748,
		Content: "127.0.0.1 localhost\n127.0.1.1 ip-172-31-14-52\n",
	},
	"/etc/hostname": {
		Type: NodeFile, Mode: "-rw-r--r--", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Size: 191,
		Content: "ip-172-31-14-52\n",
	},
	"/etc/nsswitch.conf": {Type: NodeFile, Mode: "-rw-r--r--", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Size: 522, Content: "passwd: files\ngroup: files\nshadow: files\n"},
	"/etc/os-release": {
		Type: NodeFile, Mode: "-rw-r--r--", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Size: 1317,
		Content: strings.Join([]string{
			`NAME="Ubuntu"`,
			`VERSION="22.04.3 LTS (Jammy Jellyfish)"`,
			`ID=ubuntu`,
			`ID_LIKE=debian`,
			`PRETTY_NAME="Ubuntu 22.04.3 LTS"`,
			`VERSION_ID="22.04"`,
			`HOME_URL="https://www.ubuntu.com/"`,
		}, "\n"),
		EnrichedContent: strings.Join([]string{
			`NAME="Ubuntu"`,
			`VERSION="22.04.3 LTS (Jammy Jellyfish)"`,
			`ID=ubuntu`,
			`ID_LIKE=debian`,
			`PRETTY_NAME="Ubuntu 22.04.3 LTS"`,
			`VERSION_ID="22.04"`,
			`HOME_URL="https://www.ubuntu.com/"`,
			`UBUNTU_CODENAME=jammy`,
		}, "\n"),
	},
	"/etc/passwd": {
		Type: NodeFile, Mode: "-rw-r--r--", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Size: 552,
		Content: strings.Join([]string{
			"root:x:0:0:root:/root:/bin/bash",
			"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
			"ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash",
			"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
		}, "\n"),
	},
	"/etc/shadow": {
		Type: NodeFile, Mode: "-rw-r-----", Owner: "root", Group: "shadow", MTime: "Jan 12 09:11",
		Content: strings.Join([]string{
			"root:$6$rZ1x9K2m$OqR3n7pXvL8wYbT5cFhJ4sEuIzA1MdN0gQkVxW6oPcB2yH9jS7tK3rM8nDpZfXvGqCwLbYh5eIuJoR4:19700:0:99999:7:::",
			"ubuntu:$6$Ab3xQ9mZ$K7pT2vL8nR5wYcF4hJ1sEuI0zA9MdN3gQkV6xW2oPcB8yH5jS1tK7rM4nDpZ0fXvGqCwLbYh3eIuJoR9:19700:0:99999:7:::",
		}, "\n"),
		Bait: &BaitInfo{BaitID: "etc-shadow", BaitType: session.BaitTypeShadow},
	},
	"/etc/nginx": {
		Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Total: 4,
		Children: []string{"sites-enabled"},
	},
	"/etc/nginx/sites-enabled": {
		Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Total: 4,
		Children: []string{"default"},
	},
	"/etc/nginx/sites-enabled/default": {
		Type: NodeFile, Mode: "-rw-r--r--", Owner: "root", Group: "root", MTime: "Jan 12 09:11",
		Content: "server {\n    listen 80;\n    server_name _;\n    location / {\n        proxy_pass http://127.0.0.1:8000;\n    }\n}\n",
	},
	"/etc/ssh": {
		Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Total: 4,
	},
	"/etc/systemd": {
		Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Total: 4,
	},
	"/var": {
		Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "May 29 14:01", Total: 52,
		Children: []string{"backups", "cache", "crash", "lib", "local", "log", "mail", "opt", "spool", "tmp", "www"},
	},
	"/var/backups": emptySystemDir(),
	"/var/cache":   emptySystemDir(),
	"/var/crash":   {Type: NodeDir, Mode: "drwxrwxrwt", Owner: "root", Group: "root", MTime: "May 29 14:01", Total: 0},
	"/var/lib":     emptySystemDir(),
	"/var/local":   emptySystemDir(),
	"/var/log": {
		Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "May 29 14:01", Total: 4,
		Children: []string{"syslog", "auth.log"},
	},
	"/var/log/syslog": {
		Type: NodeFile, Mode: "-rw-r-----", Owner: "syslog", Group: "adm", MTime: "Jul 11 09:00",
		Content: "Jul 11 09:00:01 ip-172-31-14-52 systemd[1]: Started Daily apt download activities.\n",
	},
	"/var/log/auth.log": {
		Type: NodeFile, Mode: "-rw-r-----", Owner: "syslog", Group: "adm", MTime: "Jul 11 09:00",
		Content: "Jul 11 08:58:12 ip-172-31-14-52 sshd[1021]: Accepted password for ubuntu from 10.0.4.9 port 51422 ssh2\n",
	},
	"/var/mail": emptySystemDir(),
	"/var/opt":  emptySystemDir(),
	"/var/spool": {
		Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Total: 20,
	},
	"/var/tmp": {Type: NodeDir, Mode: "drwxrwxrwt", Owner: "root", Group: "root", MTime: "May 29 14:01", Total: 0},
	"/var/www": emptySystemDir(),
}

func emptySystemDir() *Node {
	return &Node{Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Total: 0}
}

func init() {
	for p, n := range fs {
		n.Path = p
	}
}

// lookup resolves a path (absolute or relative to cwd) to its cleaned
// absolute form and the node at that path, if any.
func lookup(cwd, target string) (string, *Node) {
	clean := resolvePath(cwd, target)
	n, ok := fs[clean]
	if !ok {
		return clean, nil
	}
	return clean, n
}

func resolvePath(cwd, target string) string {
	if target == "" {
		return cwd
	}
	if strings.HasPrefix(target, "/") {
		return path.Clean(target)
	}
	return path.Clean(path.Join(cwd, target))
}

// displayPath renders a prompt/pwd-style path, collapsing the home directory
// to ~ the way a real bash PS1 does.
func displayPath(p string) string {
	const home = "/home/ubuntu"
	if p == home {
		return "~"
	}
	if strings.HasPrefix(p, home+"/") {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}

// lsListing renders `ls -la`-style output for a directory node. action is
// the deception decision for this turn ("" if none/not applied) -- any
// ConditionalChildren whose Action matches it are included alongside the
// always-shown Children, deterministically (declaration order).
func lsListing(n *Node, action string) string {
	type entry struct {
		name  string
		mode  string
		owner string
		group string
		size  int64
		mtime string
	}
	entries := []entry{
		{".", n.Mode, n.Owner, n.Group, 4096, n.MTime},
		{"..", "drwxr-xr-x", "root", "root", 4096, n.MTime},
	}
	names := append([]string{}, n.Children...)
	for _, cc := range n.ConditionalChildren {
		if cc.Action != "" && cc.Action == action {
			names = append(names, cc.Name)
		}
	}
	for _, name := range names {
		child := fs[path.Join(n.Path, name)]
		if child == nil {
			continue
		}
		entries = append(entries, entry{name, child.Mode, child.Owner, child.Group, sizeOf(child), child.MTime})
	}

	var b strings.Builder
	fmt.Fprintf(&b, "total %d\n", n.Total)
	for _, e := range entries {
		fmt.Fprintf(&b, "%s %2d %-6s %-6s %5d %s %s\n", e.mode, 1, e.owner, e.group, e.size, e.mtime, e.name)
	}
	return strings.TrimRight(b.String(), "\n")
}

// LooksLikeBaitAccess is a cheap, pre-execution heuristic for whether a raw
// command line looks like it targets a planted bait node -- a substring
// match against every bait node's basename, not real interpretation. Used
// only as the bait_hit feature sent to the deception inference service
// before the command has actually run (the interpreter is stateful, so it
// can't safely be run twice per command to get an exact post-execution
// answer -- see internal/deception's Decide caller in server.go).
func LooksLikeBaitAccess(command string) bool {
	lower := strings.ToLower(command)
	for p, n := range fs {
		if n.Bait == nil {
			continue
		}
		if strings.Contains(lower, strings.ToLower(path.Base(p))) {
			return true
		}
	}
	return false
}

func sizeOf(n *Node) int64 {
	if n.Type == NodeDir {
		return 4096
	}
	if n.Size > 0 {
		return n.Size
	}
	return int64(len(n.Content))
}
