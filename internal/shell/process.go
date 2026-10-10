package shell

import (
	"strconv"
	"strings"
)

func (s *Interpreter) shBuiltin(cmd string, args []string, bait *[]BaitHit, action string, stdin *string) (string, int) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-c":
			if i+1 >= len(args) {
				if cmd == "bash" {
					return "bash: -c: option requires an argument", 2
				}
				return "sh: 0: -c requires an argument", 2
			}
			return s.runNested(args[i+1], bait, action)
		case strings.HasPrefix(a, "-"):
		default:
			_, n := s.lookup(a)
			if n == nil || n.Type != NodeFile {
				if cmd == "bash" {
					return "bash: " + a + ": No such file or directory", 127
				}
				return "sh: 0: cannot open " + a + ": No such file", 2
			}
			return s.runNested(s.expandHostname(n.Content), bait, action)
		}
	}
	if stdin != nil {
		return s.runNested(*stdin, bait, action)
	}
	return "", 0
}

func (s *Interpreter) killBuiltin(args []string) (string, int) {
	_, ops := splitFlags(args)
	if len(ops) == 0 {
		return "kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]", 2
	}
	live := map[int]bool{}
	for _, p := range s.pids {
		live[p] = true
	}
	var errs []string
	for _, op := range ops {
		pid, err := strconv.Atoi(op)
		switch {
		case strings.HasPrefix(op, "%"):
			errs = append(errs, "bash: kill: "+op+": no such job")
		case err != nil:
			errs = append(errs, "bash: kill: "+op+": arguments must be process or job IDs")
		case !live[pid]:
			errs = append(errs, "bash: kill: ("+op+") - No such process")
		}
	}
	if len(errs) > 0 {
		return joinLines(errs), 1
	}
	return "", 0
}

func killallBuiltin(args []string) (string, int) {
	_, ops := splitFlags(args)
	if len(ops) == 0 {
		return "Usage: killall [OPTION]... [--] NAME...", 1
	}
	var errs []string
	for _, op := range ops {
		errs = append(errs, op+": no process found")
	}
	return joinLines(errs), 1
}
