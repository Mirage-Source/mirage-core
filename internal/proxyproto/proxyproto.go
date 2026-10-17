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
	dstPort int    // the header's dst-port: the port the client originally targeted.
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

// TargetPort returns the header's dst-port, i.e. the port the client
// connected to on the relay, which behind a tunnel differs from this
// listener's own port. ok is false when no valid header was present.
func (c *Conn) TargetPort() (port int, ok bool) {
	c.detect()
	if !c.found {
		return 0, false
	}
	return c.dstPort, true
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
				if addr, dstRaw, dstPort, ok := parseV1Line(line); ok {
					c.srcAddr = addr
					c.dstRaw = dstRaw
					c.dstPort = dstPort
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


// parseV1Line parses a "PROXY TCP4|TCP6 src dst sport dport\r\n" line. The
// source address family must match the protocol field.
func parseV1Line(line []byte) (addr *net.TCPAddr, dstRaw string, dstPort int, ok bool) {
	if !bytes.HasSuffix(line, []byte("\r\n")) {
		return nil, "", 0, false // v1 requires CRLF, not bare LF
	}
	s := string(line[:len(line)-2])

	fields := strings.Split(s, " ")
	if len(fields) != 6 || fields[0] != "PROXY" {
		return nil, "", 0, false
	}

	srcIP := net.ParseIP(fields[2])
	if srcIP == nil {
		return nil, "", 0, false
	}
	// IPv6 text always contains ':', IPv4 text never does; checking the
	// text rather than To4() keeps "::ffff:1.2.3.4" out of TCP4.
	isV6 := strings.Contains(fields[2], ":")
	switch fields[1] {
	case "TCP4":
		if isV6 {
			return nil, "", 0, false
		}
	case "TCP6":
		if !isV6 {
			return nil, "", 0, false
		}
	default:
		return nil, "", 0, false
	}
	// fields[3] (dst-ip) is intentionally NOT validated as an IP -- callers
	// get it back as an opaque string (see RealRemoteAddr's doc comment).
	dstRaw = fields[3]

	srcPort, err := strconv.Atoi(fields[4])
	if err != nil || srcPort < 0 || srcPort > 65535 {
		return nil, "", 0, false
	}
	dstPort, err = strconv.Atoi(fields[5])
	if err != nil || dstPort < 0 || dstPort > 65535 {
		return nil, "", 0, false
	}

	return &net.TCPAddr{IP: srcIP, Port: srcPort}, dstRaw, dstPort, true
}
