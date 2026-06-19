package shell

import (
	"log"
	"strings"
	"path"
)

var fileContents = map[string]string{
"/etc/passwd": `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin`,
"/etc/os-release": `NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.3 LTS"
VERSION_ID="22.04"
HOME_URL="https://www.ubuntu.com/"`,
"/proc/version": `Linux version 5.15.0-1031-aws (buildd@lcy02-amd64-059) (gcc (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #35-Ubuntu SMP Fri Feb 10 02:07:19 UTC 2023`,
"/home/ubuntu/.bash_history": `sudo apt update
sudo apt install python3-pip
git clone https://github.com/company/django-app.git
cd django-app
pip3 install -r requirements.txt
python3 manage.py migrate
python3 manage.py runserver 0.0.0.0:8000
sudo systemctl status nginx
cat /etc/nginx/sites-enabled/default
sudo nano /etc/nginx/sites-enabled/default
sudo systemctl restart nginx
ls -la
cd /home/ubuntu
cat .env`,
}

var dirContents = map[string]string{
"/home/ubuntu": `total 36
drwxr-xr-x 5 ubuntu ubuntu 4096 May 29 14:02 .
drwxr-xr-x 3 root   root   4096 Jan 12 09:11 ..
-rw------- 1 ubuntu ubuntu  220 Jan 12 09:11 .bash_history
-rw-r--r-- 1 ubuntu ubuntu 3526 Jan 12 09:11 .bashrc
drwx------ 2 ubuntu ubuntu 4096 Jan 12 09:11 .cache
drwxrwxr-x 8 ubuntu ubuntu 4096 May 29 13:44 django-app
-rw-rw-r-- 1 ubuntu ubuntu  312 May 29 13:51 .env
drwx------ 2 ubuntu ubuntu 4096 Jan 12 09:11 .ssh
-rw-r--r-- 1 ubuntu ubuntu  675 Jan 12 09:11 .profile`,
"/etc": `total 212
drwxr-xr-x 80 root root  4096 May 29 14:01 .
drwxr-xr-x 19 root root  4096 Jan 12 09:11 ..
-rw-r--r--  1 root root  2981 Jan 12 09:11 adduser.conf
drwxr-xr-x  3 root root  4096 Jan 12 09:11 apt
-rw-r--r--  1 root root   367 Jan 12 09:11 bash.bashrc
drwxr-xr-x  2 root root  4096 May 29 14:01 cron.d
-rw-r--r--  1 root root  1748 Jan 12 09:11 hosts
-rw-r--r--  1 root root   191 Jan 12 09:11 hostname
-rw-r--r--  1 root root   522 Jan 12 09:11 nsswitch.conf
-rw-r--r--  1 root root  1317 Jan 12 09:11 os-release
-rw-r--r--  1 root root   552 Jan 12 09:11 passwd
drwxr-xr-x  2 root root  4096 Jan 12 09:11 nginx
drwxr-xr-x  4 root root  4096 Jan 12 09:11 ssh
drwxr-xr-x  3 root root  4096 Jan 12 09:11 systemd`,
"/": `total 68
drwxr-xr-x 19 root root  4096 Jan 12 09:11 .
drwxr-xr-x 19 root root  4096 Jan 12 09:11 ..
drwxr-xr-x  2 root root  4096 May 29 14:01 bin
drwxr-xr-x  3 root root  4096 Jan 12 09:11 boot
drwxr-xr-x  6 root root  4096 Jan 12 09:11 dev
drwxr-xr-x 80 root root  4096 May 29 14:01 etc
drwxr-xr-x  3 root root  4096 Jan 12 09:11 home
drwxr-xr-x 13 root root  4096 Jan 12 09:11 lib
drwxr-xr-x  2 root root  4096 Jan 12 09:11 lib64
drwxr-xr-x  3 root root  4096 Jan 12 09:11 opt
dr-xr-xr-x 96 root root     0 May 29 09:11 proc
drwx------  4 root root  4096 Jan 12 09:11 root
drwxr-xr-x 26 root root   820 May 29 14:01 run
drwxr-xr-x  2 root root  4096 Jan 12 09:11 sbin
drwxr-xr-x  6 root root  4096 Jan 12 09:11 srv
drwxr-xr-x  2 root root  4096 May 29 14:01 tmp
drwxr-xr-x 11 root root  4096 Jan 12 09:11 usr
drwxr-xr-x 13 root root  4096 Jan 12 09:11 var`,
"/var": `total 52
drwxr-xr-x 13 root root  4096 Jan 12 09:11 .
drwxr-xr-x 19 root root  4096 Jan 12 09:11 ..
drwxr-xr-x  2 root root  4096 May 29 14:01 backups
drwxr-xr-x 14 root root  4096 May 29 14:01 cache
drwxrwxrwt  2 root root  4096 May 29 14:01 crash
drwxr-xr-x 38 root root  4096 May 29 14:01 lib
drwxrwsr-x  2 root root  4096 Jan 12 09:11 local
drwxr-xr-x  2 root root  4096 May 29 14:01 log
drwxrwsr-x  2 root root  4096 Jan 12 09:11 mail
drwxr-xr-x  2 root root  4096 Jan 12 09:11 opt
drwxr-xr-x  5 root root  4096 Jan 12 09:11 spool
drwxrwxrwt  8 root root  4096 May 29 14:01 tmp
drwxr-xr-x  3 root root  4096 Jan 12 09:11 www`,
}
func Handle(input string, cwd string) (string, string, int) {
	trimmed := strings.TrimSpace(input)

	words := strings.Fields(trimmed)
	if len(words) == 0 {
		return "", cwd, 0
	}

	switch words[0] {
		case "echo":
			return strings.Join(words[1:], " "), cwd, 0
		case "whoami":
			return "ubuntu",cwd,0
		case "pwd":
			return cwd, cwd, 0
		case "hostname":
			return "ip-172-31-14-52", cwd, 0
		case "cat":
			if len(words) < 2 {
				return "cat: missing operand", cwd, 1
			}
			content, exists := fileContents[words[1]]
			if exists {
				return strings.ReplaceAll(content, "\n", "\r\n"), cwd, 0
			}
			return "cat: " + words[1] + ": No such file or directory", cwd, 1
		case "exit":
			return "", cwd, 257
		case "ls":
			target := cwd
			if len(words) >=2 && !strings.HasPrefix(words[len(words)-1], "-") {
				target = words[len(words)-1]
			}
			content, exists := dirContents[target]
			if !exists {
				return "ls: cannot access '" + target + "': No such file or directory", cwd, 2
			}
			return strings.ReplaceAll(content, "\n", "\r\n"), cwd, 0
		case "cd":
			var target string
			if len(words) < 2 {
				target = "/home/ubuntu"
			} else {
				target = words[1]
			}

			var candidate string
			if strings.HasPrefix(target, "/") {
				candidate = path.Clean(target)
			} else {
				candidate = path.Clean(path.Join(cwd, target))
			}
			if _, exists := dirContents[candidate]; exists {
				return "", candidate, 0
			}
			return "cd: "+ target + ": No such file or directory", cwd, 1

		default:
			log.Printf("Unknown command: %s", words[0])
			return "bash: " + words[0] + ": command not found", cwd, 127
	}
}
