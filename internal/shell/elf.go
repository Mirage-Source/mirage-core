package shell

import (
	"fmt"
	"strconv"
	"strings"
)

// elfHeader is the 64-byte ELF64 header of an x86-64 PIE executable, laid out
// like Ubuntu 22.04's /usr/bin/ls. It must agree with `uname -m` (x86_64):
// Mirai-style loaders read EI_CLASS, EI_DATA and e_machine from it to choose
// which payload to fetch. Only the header is served, not a full binary.
const elfHeader = "\x7fELF\x02\x01\x01\x00" + "\x00\x00\x00\x00\x00\x00\x00\x00" + // e_ident
	"\x03\x00" + "\x3e\x00" + "\x01\x00\x00\x00" + // ET_DYN, EM_X86_64, EV_CURRENT
	"\xb0\x6a\x00\x00\x00\x00\x00\x00" + // e_entry
	"\x40\x00\x00\x00\x00\x00\x00\x00" + // e_phoff
	"\x98\x22\x02\x00\x00\x00\x00\x00" + // e_shoff
	"\x00\x00\x00\x00" + // e_flags
	"\x40\x00" + "\x38\x00" + "\x0d\x00" + // e_ehsize, e_phentsize, e_phnum
	"\x40\x00" + "\x1f\x00" + "\x1e\x00" // e_shentsize, e_shnum, e_shstrndx

// ddBuiltin copies bs*count bytes from if= (or stdin) after skipping skip
// blocks, writing to of= if given, then prints GNU dd's record summary.
// Loaders use `dd bs=52 count=1 if=/bin/ls` to read just the ELF header.
func (s *Interpreter) ddBuiltin(args []string, stdin *string) (string, int) {
	bs, count, skip := 512, -1, 0
	var inFile, outFile string
	for _, a := range args {
		k, v, ok := strings.Cut(a, "=")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(v)
		switch {
		case k == "if":
			inFile = v
		case k == "of":
			outFile = v
		case (k == "bs" || k == "ibs") && err == nil && n > 0:
			bs = n
		case k == "count" && err == nil && n >= 0:
			count = n
		case k == "skip" && err == nil && n >= 0:
			skip = n
		}
	}

	data, ok := s.builtinInput(inFile, stdin)
	if !ok {
		return "dd: failed to open '" + inFile + "': No such file or directory", 1
	}
	data = data[min(skip*bs, len(data)):]
	if count >= 0 && count*bs < len(data) {
		data = data[:count*bs]
	}

	partial := 0
	if len(data)%bs != 0 {
		partial = 1
	}
	records := fmt.Sprintf("%d+%d", len(data)/bs, partial)
	rate := float64(len(data)) / 5.1e-05
	speed := fmt.Sprintf("%.0f kB/s", rate/1e3)
	if rate >= 1e6 {
		speed = fmt.Sprintf("%.1f MB/s", rate/1e6)
	}
	summary := records + " records in\r\n" + records + " records out\r\n" +
		fmt.Sprintf("%d bytes copied, 5.1e-05 s, %s", len(data), speed)

	if outFile != "" {
		if msg, code := s.writeFile(outFile, data, false); code != 0 {
			return strings.Replace(msg, "bash: ", "dd: failed to open '", 1), 1
		}
		return summary, 0
	}
	return strings.ReplaceAll(data, "\n", "\r\n") + summary, 0
}

// moreBuiltin behaves like more(1) when not on a terminal: it copies its
// input through unpaged, which is how `cat /bin/ls|more` reaches it.
func (s *Interpreter) moreBuiltin(args []string, stdin *string) (string, int) {
	var fileArg string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			fileArg = a
			break
		}
	}
	text, ok := s.builtinInput(fileArg, stdin)
	if !ok {
		return "more: cannot open " + fileArg + ": No such file or directory", 1
	}
	return strings.ReplaceAll(text, "\n", "\r\n"), 0
}
