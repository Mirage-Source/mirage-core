package proxyproto

import (
	"bufio"
	"bytes"
	"net"
	"strconv"
	"strings"
	"sync"
)

// maxHeaderLen is the PROXY protocol v1 spec's stated worst case: 
const maxHeaderLen = 107

const headerPrefix = "PROXY "

// Conn wraps a net.Conn and, on the first read, transparently strips a
// leading PROXY protocol v1 header if one is present. Read, Write, Close.
type Conn struct {
	net.Conn

	r    *bufio.Reader
	once sync.Once

	found   bool
	srcAddr *net.TCPAddr
	dstRaw  string // the header's dst-ip field, kept opaque -- see RealRemoteAddr.
}

// Wrap returns a Conn wrapping c. 
func Wrap(c net.Conn) *Conn {
	// Buffer sized exactly to maxHeaderLen so Peek(maxHeaderLen) can never
	// fail with bufio.ErrBufferFull -- it only ever returns fewer bytes
	// because the underlying conn hasn't sent that many (or has errored).
	return &Conn{Conn: c, r: bufio.NewReaderSize(c, maxHeaderLen)}
}

func (c *Conn) Read(b []byte) (int, error) {
	c.detect()
	return c.r.Read(b)
}

func (c *Conn) RealRemoteAddr() (*net.TCPAddr, string, bool) {
	c.detect()
	if !c.found {
		return nil, "", false
	}
	return c.srcAddr, c.dstRaw, true
}

func (c *Conn) detect() {
	c.once.Do(func() {
		prefix := []byte(headerPrefix)

		for n := 1; n <= maxHeaderLen; n++ {
			peeked, err := c.r.Peek(n)
			got := len(peeked)
			if got < n {
				return // conn ended/errored before n bytes ever arrived
			}

			if got <= len(prefix) {
				if !bytes.Equal(peeked, prefix[:got]) {
					return // does not start with "PROXY "
				}
			} else if idx := bytes.IndexByte(peeked, '\n'); idx >= 0 {
				line := peeked[:idx+1]
				if addr, dstRaw, ok := parseV1TCP4Line(line); ok {
					c.srcAddr = addr
					c.dstRaw = dstRaw
					c.found = true
					c.r.Discard(len(line))
				}
				return // matched or not, a full line was seen -- decision made
			}

			if err != nil {
				return // no newline yet and the conn already ended/errored
			}
		}
		
	})
}


func parseV1TCP4Line(line []byte) (addr *net.TCPAddr, dstRaw string, ok bool) {
	if !bytes.HasSuffix(line, []byte("\r\n")) {
		return nil, "", false // v1 requires CRLF, not bare LF
	}
	s := string(line[:len(line)-2])

	fields := strings.Split(s, " ")
	if len(fields) != 6 {
		return nil, "", false
	}
	if fields[0] != "PROXY" || fields[1] != "TCP4" {
		return nil, "", false
	}

	srcIP := net.ParseIP(fields[2])
	if srcIP == nil || srcIP.To4() == nil {
		return nil, "", false
	}
	// fields[3] (dst-ip) is intentionally NOT validated as an IP -- callers
	// get it back as an opaque string (see RealRemoteAddr's doc comment).
	dstRaw = fields[3]

	srcPort, err := strconv.Atoi(fields[4])
	if err != nil || srcPort < 0 || srcPort > 65535 {
		return nil, "", false
	}
	dstPort, err := strconv.Atoi(fields[5])
	if err != nil || dstPort < 0 || dstPort > 65535 {
		return nil, "", false
	}

	return &net.TCPAddr{IP: srcIP, Port: srcPort}, dstRaw, true
}
