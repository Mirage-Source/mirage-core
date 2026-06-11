package shell

import (
	"log"
	"strings"
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
func Handle(input string) (string, int) {
	trimmed := strings.TrimSpace(input)

	words := strings.Fields(trimmed)
	if len(words) == 0 {
		return "", 0
	}

	switch words[0] {
		case "echo":
			return strings.Join(words[1:], " "), 0
		case "whoami":
			return "ubuntu", 0
		case "pwd":
			return "/home/ubuntu", 0
		case "hostname":
			return "ip-172-31-14-52", 0
		case "cat":
			if len(words) < 2 {
				return "cat: missing operand", 1
			}
			content, exists := fileContents[words[1]]
			if exists {
				return strings.ReplaceAll(content, "\n", "\r\n"), 0
			}
				return "cat: " + words[1] + ": No such file or directory", 1
		case "exit":
			return "", 257
		default:
			log.Printf("Unknown command: %s", words[0])
			return "bash: " + words[0] + ": command not found", 127
	}
}
