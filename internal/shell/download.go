package shell

import (
	"net/url"
	"strings"
	"time"
)

// wget and curl exist, as on a stock Ubuntu image, but fail the way they
// would on a host with no outbound access. See SECURITY.md: a download is
// never reported as successful.

type target struct {
	raw, host, port string
	isIP            bool
}

func parseTarget(raw string) (target, bool) {
	full := raw
	if !strings.Contains(full, "://") {
		full = "http://" + full
	}
	u, err := url.Parse(full)
	if err != nil || u.Hostname() == "" {
		return target{}, false
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "ftp": "21"}[u.Scheme]
		if port == "" {
			port = "80"
		}
	}
	host := u.Hostname()
	return target{raw: full, host: host, port: port, isIP: isIPLiteral(host)}, true
}

func isIPLiteral(h string) bool {
	if strings.Contains(h, ":") {
		return true
	}
	parts := strings.Split(h, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 || strings.Trim(p, "0123456789") != "" {
			return false
		}
	}
	return true
}

func wgetBuiltin(args []string) (string, int) {
	quiet := false
	var urls []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-O" || a == "-P" || a == "-o" || a == "-t" || a == "-T" || a == "-U" || a == "--header":
			i++
		case strings.HasPrefix(a, "--"):
			if a == "--quiet" {
				quiet = true
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			flags := a[1:]
			if j := strings.IndexAny(flags, "OPotTU"); j >= 0 {
				if j == len(flags)-1 {
					i++
				}
				flags = flags[:j]
			}
			if strings.Contains(flags, "q") {
				quiet = true
			}
		default:
			urls = append(urls, a)
		}
	}
	if len(urls) == 0 {
		return "wget: missing URL\r\nUsage: wget [OPTION]... [URL]...\r\n\r\nTry `wget --help' for more options.", 1
	}
	var lines []string
	for _, raw := range urls {
		t, ok := parseTarget(raw)
		if !ok {
			lines = append(lines, raw+": Invalid URL "+raw+": Invalid host name.")
			continue
		}
		lines = append(lines, "--"+time.Now().UTC().Format("2006-01-02 15:04:05")+"--  "+t.raw)
		if t.isIP {
			lines = append(lines, "Connecting to "+t.host+":"+t.port+"... failed: Connection timed out.", "Giving up.")
		} else {
			lines = append(lines,
				"Resolving "+t.host+" ("+t.host+")... failed: Temporary failure in name resolution.",
				"wget: unable to resolve host address ‘"+t.host+"’")
		}
	}
	if quiet {
		return "", 4
	}
	return joinLines(lines), 4
}

func curlBuiltin(args []string) (string, int) {
	silent, showErr := false, false
	var urls []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-o" || a == "-H" || a == "-A" || a == "-d" || a == "-X" || a == "-u" || a == "-e" || a == "-m" || a == "--output" || a == "--header" || a == "--user-agent" || a == "--data" || a == "--max-time" || a == "--connect-timeout":
			i++
		case a == "--silent":
			silent = true
		case a == "--show-error":
			showErr = true
		case strings.HasPrefix(a, "--"):
		case strings.HasPrefix(a, "-") && len(a) > 1:
			flags := a[1:]
			if j := strings.IndexAny(flags, "oHAdXuem"); j >= 0 {
				if j == len(flags)-1 {
					i++
				}
				flags = flags[:j]
			}
			silent = silent || strings.Contains(flags, "s")
			showErr = showErr || strings.Contains(flags, "S")
		default:
			urls = append(urls, a)
		}
	}
	if len(urls) == 0 {
		return "curl: try 'curl --help' or 'curl --manual' for more information", 2
	}
	t, ok := parseTarget(urls[0])
	msg, code := "curl: (3) URL using bad/illegal format or missing URL", 3
	if ok && t.isIP {
		msg, code = "curl: (28) Failed to connect to "+t.host+" port "+t.port+" after 130000 ms: Connection timed out", 28
	} else if ok {
		msg, code = "curl: (6) Could not resolve host: "+t.host, 6
	}
	if silent && !showErr {
		return "", code
	}
	return msg, code
}
