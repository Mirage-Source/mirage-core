package shell

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

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
	Link                string                    // symlinks only: the target as stored (`sh` -> "dash"); Mode starts with "l"
	gen                 func(*Interpreter) string // files only: content generated at each read (/proc)
	Content             string                    // files only
	EnrichedContent     string                    // files only; used instead of Content when action is ENRICH
	Children            []string                  // dirs only, ordered basenames, always shown
	ConditionalChildren []ConditionalChild        // dirs only, shown only for a matching action
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
	"/bin": {
		Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Total: 172,
		Children: []string{"bash", "cat", "dash", "dd", "echo", "ls", "sh"},
	},
	// Sizes from 22.04's bash 5.1-6ubuntu1, dash 0.5.11 and coreutils 8.32.
	"/bin/bash": binaryNode("Jan  6  2022", 1396520),
	"/bin/cat":  binaryNode("Feb  7  2022", 35280),
	"/bin/dash": binaryNode("Mar 23  2022", 125688),
	"/bin/dd":   binaryNode("Feb  7  2022", 68104),
	"/bin/echo": binaryNode("Feb  7  2022", 35120),
	"/bin/ls":   binaryNode("Feb  7  2022", 138216),
	"/bin/sh":   {Type: NodeFile, Mode: "lrwxrwxrwx", Owner: "root", Group: "root", MTime: "Mar 23  2022", Link: "dash"},
	"/boot":     emptySystemDir(),
	"/dev": {
		Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "Jul 11 09:11", Total: 0,
		Children: []string{"null", "shm"},
	},
	"/dev/null": {Type: NodeFile, Mode: "crw-rw-rw-", Owner: "root", Group: "root", MTime: "Jul 11 09:11"},
	"/dev/shm":  {Type: NodeDir, Mode: "drwxrwxrwt", Owner: "root", Group: "root", MTime: "Jul 11 09:11", Total: 0},
	"/lib":      emptySystemDir(),
	"/lib64":    emptySystemDir(),
	"/opt":      emptySystemDir(),
	"/proc": {
		Type: NodeDir, Mode: "dr-xr-xr-x", Owner: "root", Group: "root", MTime: "Jul 11 09:11", Total: 0,
		Children: []string{"version", "cpuinfo", "meminfo", "uptime", "self"},
	},
	"/proc/self": {
		Type: NodeDir, Mode: "dr-xr-xr-x", Owner: "root", Group: "root", MTime: "Jul 11 09:11", Total: 0,
		Children: []string{"exe"},
	},
	"/proc/self/exe": binaryNode("Jul 11 09:11", 138216),
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
		gen: (*Interpreter).uptimeContent,
	},
	"/proc/meminfo": {
		Type: NodeFile, Mode: "-r--r--r--", Owner: "root", Group: "root", MTime: "Jul 11 09:11",
		gen: (*Interpreter).meminfoContent,
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
		Type: NodeFile, Mode: "-rw-r--r--", Owner: "ubuntu", Group: "ubuntu", MTime: "Jan 12 09:11",
		Content: rootFile("home/ubuntu/.bashrc"),
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
		Type: NodeFile, Mode: "-rw-rw-r--", Owner: "ubuntu", Group: "ubuntu", MTime: "May 29 13:51",
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
		Type: NodeFile, Mode: "-rw-------", Owner: "ubuntu", Group: "ubuntu", MTime: "May 29 13:40",
		Content: strings.Join([]string{
			"[default]",
			"aws_access_key_id=AKIAQXJ3EXAMPLEKEY9",
			"aws_secret_access_key=k3vQ/EXAMPLEnotarealsecretkeyDoNotUse1234567",
		}, "\n"),
		Bait: &BaitInfo{BaitID: "home-aws-credentials", BaitType: session.BaitTypeCredential, Hidden: true},
	},
	"/home/ubuntu/.profile": {
		Type: NodeFile, Mode: "-rw-r--r--", Owner: "ubuntu", Group: "ubuntu", MTime: "Jan 12 09:11",
		Content: rootFile("home/ubuntu/.profile"),
	},
	"/home/ubuntu/.ssh": {
		Type: NodeDir, Mode: "drwx------", Owner: "ubuntu", Group: "ubuntu", MTime: "Jan 12 09:11", Total: 12,
		Children: []string{"authorized_keys", "id_rsa", "id_rsa.pub"},
	},
	"/home/ubuntu/.ssh/authorized_keys": {
		Type: NodeFile, Mode: "-rw-------", Owner: "ubuntu", Group: "ubuntu", MTime: "Jan 12 09:11",
		Content: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE0000000000000000000000000000 ubuntu@{{hostname}}\n",
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
		Content: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC00EXAMPLE0000000000000000000000 ubuntu@{{hostname}}\n",
	},
	"/etc": {
		Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "May 29 14:01", Total: 212,
		Children: []string{"adduser.conf", "apt", "bash.bashrc", "cron.d", "hosts", "hostname", "nsswitch.conf", "os-release", "passwd", "shadow", "nginx", "ssh", "systemd"},
	},
	"/etc/adduser.conf": {
		Type: NodeFile, Mode: "-rw-r--r--", Owner: "root", Group: "root", MTime: "Jan 12 09:11",
		Content: rootFile("etc/adduser.conf"),
	},
	"/etc/apt": {Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Total: 4},
	"/etc/bash.bashrc": {
		Type: NodeFile, Mode: "-rw-r--r--", Owner: "root", Group: "root", MTime: "Jan 12 09:11",
		Content: rootFile("etc/bash.bashrc"),
	},
	"/etc/cron.d": {Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "May 29 14:01", Total: 4},
	"/etc/hosts": {
		Type: NodeFile, Mode: "-rw-r--r--", Owner: "root", Group: "root", MTime: "Jan 12 09:11",
		Content: "127.0.0.1 localhost\n127.0.1.1 {{hostname}}\n",
	},
	"/etc/hostname": {
		Type: NodeFile, Mode: "-rw-r--r--", Owner: "root", Group: "root", MTime: "Jan 12 09:11",
		Content: "{{hostname}}\n",
	},
	"/etc/nsswitch.conf": {
		Type: NodeFile, Mode: "-rw-r--r--", Owner: "root", Group: "root", MTime: "Jan 12 09:11",
		Content: rootFile("etc/nsswitch.conf"),
	},
	"/etc/os-release": {
		Type: NodeFile, Mode: "-rw-r--r--", Owner: "root", Group: "root", MTime: "Jan 12 09:11",
		Content: rootFile("etc/os-release"),
	},
	"/etc/passwd": {
		Type: NodeFile, Mode: "-rw-r--r--", Owner: "root", Group: "root", MTime: "Jan 12 09:11",
		Content: rootFile("etc/passwd"),
	},
	"/etc/shadow": {
		Type: NodeFile, Mode: "-rw-r-----", Owner: "root", Group: "shadow", MTime: "Jan 12 09:11",
		// Every account, as on a real box; hashes are yescrypt-shaped ($y$),
		// 22.04's default, and match no password.
		Content: strings.Join([]string{
			"root:$y$j9T$RQ68T22M4i1SfMUJAGQZTV$mvddqNVn3Tbn.NNLIljDbVx1Z.ZgTpQfh24YMTcaD5n:19700:0:99999:7:::",
			"daemon:*:19400:0:99999:7:::",
			"bin:*:19400:0:99999:7:::",
			"sys:*:19400:0:99999:7:::",
			"sync:*:19400:0:99999:7:::",
			"games:*:19400:0:99999:7:::",
			"man:*:19400:0:99999:7:::",
			"lp:*:19400:0:99999:7:::",
			"mail:*:19400:0:99999:7:::",
			"news:*:19400:0:99999:7:::",
			"uucp:*:19400:0:99999:7:::",
			"proxy:*:19400:0:99999:7:::",
			"www-data:*:19400:0:99999:7:::",
			"backup:*:19400:0:99999:7:::",
			"list:*:19400:0:99999:7:::",
			"irc:*:19400:0:99999:7:::",
			"gnats:*:19400:0:99999:7:::",
			"nobody:*:19400:0:99999:7:::",
			"_apt:*:19400:0:99999:7:::",
			"systemd-network:*:19400:0:99999:7:::",
			"systemd-resolve:*:19400:0:99999:7:::",
			"messagebus:*:19400:0:99999:7:::",
			"systemd-timesync:*:19400:0:99999:7:::",
			"sshd:*:19400:0:99999:7:::",
			"ubuntu:$y$j9T$b8n4.KZ8vv1npgHOgiIPaY$LRqABJwlecQluTiqT9IXihejq8gcBkB3WSk3vOl6kTw:19700:0:99999:7:::",
		}, "\n") + "\n",
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
		Content: "Jul 11 09:00:01 {{hostname}} systemd[1]: Started Daily apt download activities.\n",
	},
	"/var/log/auth.log": {
		Type: NodeFile, Mode: "-rw-r-----", Owner: "syslog", Group: "adm", MTime: "Jul 11 09:00",
		Content: "Jul 11 08:58:12 {{hostname}} sshd[1021]: Accepted password for ubuntu from 10.0.4.9 port 51422 ssh2\n",
	},
	"/var/mail": emptySystemDir(),
	"/var/opt":  emptySystemDir(),
	"/var/spool": {
		Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Total: 20,
	},
	"/var/tmp": {Type: NodeDir, Mode: "drwxrwxrwt", Owner: "root", Group: "root", MTime: "May 29 14:01", Total: 0},
	"/var/www": emptySystemDir(),
}

// binaryNode is an executable whose content is just an ELF header; see elfHeader.
func binaryNode(mtime string, size int64) *Node {
	return &Node{Type: NodeFile, Mode: "-rwxr-xr-x", Owner: "root", Group: "root", MTime: mtime, Size: size, Content: elfHeader}
}

func emptySystemDir() *Node {
	return &Node{Type: NodeDir, Mode: "drwxr-xr-x", Owner: "root", Group: "root", MTime: "Jan 12 09:11", Total: 0}
}

func init() {
	for _, tree := range []map[string]*Node{fs, dvrFS} {
		for p, n := range tree {
			n.Path = p
		}
	}
}

// lookup resolves a path (absolute or relative to s.Cwd) to its cleaned
// absolute form and the node at that path, if any. s.overlay (this
// session's `>`/`>>` writes) shadows the shared base filesystem.
func (s *Interpreter) lookup(target string) (string, *Node) {
	clean, n := s.lookupNoFollow(target)
	if n != nil && n.Link != "" {
		// Follow the final symlink once; base links point at real files.
		_, to := s.lookupNoFollow(path.Join(path.Dir(clean), n.Link))
		return clean, to
	}
	return clean, n
}

// lookupNoFollow is lookup without following a final symlink (lstat).
func (s *Interpreter) lookupNoFollow(target string) (string, *Node) {
	clean := s.resolvePath(target)
	if n, ok := s.overlay[clean]; ok {
		return clean, n
	}
	n, ok := s.profile.fs[clean]
	if !ok {
		return clean, nil
	}
	return clean, n
}

// writeFile creates or overwrites a file at target in this session's
// overlay -- never the shared base fs map. The parent directory must
// already exist.
func (s *Interpreter) writeFile(target, content string, appendMode bool) (string, int) {
	clean := s.resolvePath(target)
	if _, dev := s.lookup(clean); dev != nil && strings.HasPrefix(dev.Mode, "c") {
		return "", 0 // a character device (/dev/null) discards what is written to it, by any route
	}
	parentPath := path.Dir(clean)
	_, parent := s.lookup(parentPath)
	if parent == nil || parent.Type != NodeDir {
		return s.shellMsg(s.profile.msgs.createNoDir, target), 1
	}
	if s.readOnly(clean) {
		return s.shellMsg(s.profile.msgs.createRO, target), 1
	}

	base := path.Base(clean)
	_, existing := s.lookup(clean)
	if existing != nil && existing.Type == NodeDir {
		return s.shellMsg(s.profile.msgs.createIsDir, target), 1
	}

	newContent := content
	if appendMode && existing != nil {
		newContent = existing.Content + content
	}

	if s.overlay == nil {
		s.overlay = map[string]*Node{}
	}
	s.overlay[clean] = &Node{
		Path: clean, Type: NodeFile, Mode: "-rw-r--r--", Owner: s.Username, Group: s.Username,
		MTime: time.Now().UTC().Format("Jan _2 15:04"), Content: newContent,
	}

	s.addChild(parentPath, base)

	return "", 0
}

func (s *Interpreter) resolvePath(target string) string {
	cwd := s.Cwd
	if target == "" {
		return cwd
	}
	if target == "~" {
		target = s.HomeDir
	} else if strings.HasPrefix(target, "~/") {
		target = s.HomeDir + target[1:]
	}
	if strings.HasPrefix(target, "/") {
		return path.Clean(target)
	}
	return path.Clean(path.Join(cwd, target))
}

// displayPath renders a prompt/pwd-style path, collapsing this session's own
// home directory to ~ the way a real bash PS1 does -- root's ~ is /root, not
// /home/ubuntu, so home is passed in rather than hardcoded.
func displayPath(p, home string) string {
	if p == home {
		return "~"
	}
	if strings.HasPrefix(p, home+"/") {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}

// lsListing renders `ls`-style output for a directory node, matching real
// ls's flag semantics: bare `ls` and `ls -a` are short form (names only, no
// "total" header), `-l`/`-la`/`-al` are long form (permissions/owner/size),
// and dotfiles plus the synthetic "."/".." entries only appear when showAll
// is set. action is the deception decision for this turn ("" if none/not
// applied) -- any ConditionalChildren whose Action matches it are included
// alongside the always-shown Children, deterministically (declaration
// order), followed by any files this session wrote into n.Path via a
// `>`/`>>` redirect. Real ls sorts alphabetically by default; the long-form
// path deliberately does NOT (kept exactly as before this method learned
// about flags, to avoid disturbing every existing -la-shaped test/behavior)
// -- only the short form (the new code path) sorts.
func (s *Interpreter) lsListing(n *Node, action string, longFormat, showAll bool) string {
	var entries []lsEntry
	if showAll {
		entries = append(entries,
			lsEntry{".", n.Mode, s.nlink(n), n.Owner, n.Group, 4096, n.MTime, ""},
			lsEntry{"..", "drwxr-xr-x", 2, "root", "root", 4096, n.MTime, ""},
		)
	}
	names := append([]string{}, n.Children...)
	for _, cc := range n.ConditionalChildren {
		if cc.Action != "" && cc.Action == action {
			names = append(names, cc.Name)
		}
	}
	names = append(names, s.overlayChildren[n.Path]...)
	for _, name := range names {
		if !showAll && strings.HasPrefix(name, ".") {
			continue
		}
		_, child := s.lookupNoFollow(path.Join(n.Path, name))
		if child == nil {
			continue
		}
		entries = append(entries, s.entryFor(name, child))
	}

	if !longFormat {
		visible := make([]string, 0, len(entries))
		for _, e := range entries {
			visible = append(visible, e.name)
		}
		sort.Strings(visible)
		return strings.Join(visible, s.lsSep())
	}
	return fmt.Sprintf("total %d\r\n", n.Total) + formatLong(entries)
}

// lsSep separates short-form names: columns on a terminal, one per line
// when ls's stdout is not a tty (an exec without a pty).
func (s *Interpreter) lsSep() string {
	if s.exec && !s.tty {
		return "\r\n"
	}
	return "  "
}

type lsEntry struct {
	name, mode   string
	links        int
	owner, group string
	size         int64
	mtime, link  string
}

func (s *Interpreter) entryFor(name string, n *Node) lsEntry {
	return lsEntry{name, n.Mode, s.nlink(n), n.Owner, n.Group, s.sizeOf(n), n.MTime, n.Link}
}

// nlink is 1 for a file and 2 plus its subdirectories for a directory.
func (s *Interpreter) nlink(n *Node) int {
	if n.Type != NodeDir {
		return 1
	}
	links := 2
	for _, c := range append(append([]string{}, n.Children...), s.overlayChildren[n.Path]...) {
		if _, child := s.lookupNoFollow(path.Join(n.Path, c)); child != nil && child.Type == NodeDir {
			links++
		}
	}
	return links
}

// formatLong prints ls -l rows with GNU ls's column widths: each column as
// wide as its widest value in this listing.
func formatLong(entries []lsEntry) string {
	var wl, wo, wg, ws int
	for _, e := range entries {
		wl = max(wl, len(strconv.Itoa(e.links)))
		wo = max(wo, len(e.owner))
		wg = max(wg, len(e.group))
		ws = max(ws, len(strconv.FormatInt(e.size, 10)))
	}
	rows := make([]string, len(entries))
	for i, e := range entries {
		name := e.name
		if e.link != "" {
			name += " -> " + e.link
		}
		rows[i] = fmt.Sprintf("%s %*d %-*s %-*s %*d %s %s", e.mode, wl, e.links, wo, e.owner, wg, e.group, ws, e.size, e.mtime, name)
	}
	return strings.Join(rows, "\r\n")
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

// sizeOf is what ls reports: a binary's declared Size (its content is
// only an ELF header), otherwise the bytes cat would print, so ls -l and
// wc -c agree on every file.
func (s *Interpreter) sizeOf(n *Node) int64 {
	if n.Type == NodeDir {
		return 4096
	}
	if n.Link != "" {
		return int64(len(n.Link))
	}
	if n.Size > 0 {
		return n.Size
	}
	return int64(len(s.content(n)))
}
