// Package proxyproto implements just enough of the PROXY protocol v1
// (https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) to recover
// the real client address when Mirage is deployed behind something that
// forwards TCP connections -- a load balancer, a relay/sensor node, etc. --
// instead of accepting them directly from the attacker.
//
// Deliberately dependency-free and v1-only (a single, human-readable,
// CRLF-terminated line), matching how the rest of this codebase hand-rolls
// small parsers (see internal/shell/tokenizer.go) rather than pulling in a
// library for something this size.
//
// This package only ever recovers information; it never trusts anything by
// default. A Conn with no PROXY header on it behaves exactly like the
// net.Conn it wraps. Whether the *caller* trusts what this package parses
// (i.e. whether it's safe to wrap a given listener's connections at all) is
// entirely the caller's decision -- see TRUST_PROXY_PROTOCOL in
// internal/server/server.go.
package proxyproto

import (
	"bufio"
	"bytes"
	"net"
	"strconv"
	"strings"
	"sync"
)

// maxHeaderLen is the PROXY protocol v1 spec's stated worst case: a single
// CRLF-terminated line, at most 107 bytes including the terminator (that's
// "PROXY UNKNOWN\r\n" at the short end, and the longest possible
// "PROXY TCP6 <max v6 addr> <max v6 addr> 65535 65535\r\n" at the long end).
const maxHeaderLen = 107

const headerPrefix = "PROXY "

// Conn wraps a net.Conn and, on the first read, transparently strips a
// leading PROXY protocol v1 header if one is present. Read, Write, Close,
// and every deadline method delegate to the wrapped net.Conn unchanged
// (Write/Close/deadlines via plain embedding; Read is the only method this
// type overrides, and only to peel off the header line before handing
// bytes to the caller).
type Conn struct {
	net.Conn

	r    *bufio.Reader
	once sync.Once

	found   bool
	srcAddr *net.TCPAddr
	dstRaw  string // the header's dst-ip field, kept opaque -- see RealRemoteAddr.
}

// Wrap returns a Conn wrapping c. It performs no I/O itself -- detection of
// a PROXY header happens lazily, on the first Read or RealRemoteAddr call,
// specifically so that constructing a Conn in an Accept loop can never block
// before the caller has had a chance to set a deadline on c.
func Wrap(c net.Conn) *Conn {
	// Buffer sized exactly to maxHeaderLen so Peek(maxHeaderLen) can never
	// fail with bufio.ErrBufferFull -- it only ever returns fewer bytes
	// because the underlying conn hasn't sent that many (or has errored).
	return &Conn{Conn: c, r: bufio.NewReaderSize(c, maxHeaderLen)}
}

// Read implements net.Conn. The first call (across all callers of this Conn)
// triggers header detection; every call, including the first, returns
// attacker-supplied payload bytes only -- a parsed header line is never
// handed back to the caller.
func (c *Conn) Read(b []byte) (int, error) {
	c.detect()
	return c.r.Read(b)
}

// RealRemoteAddr returns the address a PROXY v1 header claims as the
// original client, the header's raw destination-address field (returned as
// an opaque string -- the spec allows this to be a proxy-internal
// identifier, not necessarily a routable IP, so it is never parsed as one),
// and whether a header was actually found. If no PROXY line is present (or
// what's present doesn't parse as a valid "PROXY TCP4 ..." line), it returns
// (nil, "", false) and callers should fall back to c.RemoteAddr() unchanged
// -- exactly as if this type were never involved.
func (c *Conn) RealRemoteAddr() (*net.TCPAddr, string, bool) {
	c.detect()
	if !c.found {
		return nil, "", false
	}
	return c.srcAddr, c.dstRaw, true
}

// detect performs (at most once) the actual header sniff-and-strip. It reads
// only as many bytes as it needs to rule a header in or out -- one byte at a
// time while the prefix still matches, then up to maxHeaderLen total looking
// for the terminating newline -- so a connection that never sends a PROXY
// header (the common case when this feature is off, or a stray/misconfigured
// direct connection hits a listener that has it on) is never held up waiting
// to fill a fixed-size buffer that will never arrive. Any read error or EOF
// encountered while sniffing is treated the same as "no header": nothing is
// consumed, and the error will simply reappear on the next real Read.
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
		// Grew past maxHeaderLen without ever finding '\n': not a valid v1
		// header. Leave everything unconsumed and let it fall through to
		// whatever the real protocol on this connection is (which will then
		// fail to parse it as a valid one, the same safe outcome as if this
		// package were never involved).
	})
}

// parseV1TCP4Line parses a single CRLF-terminated PROXY protocol v1 line of
// the form "PROXY TCP4 <src-ip> <dst-ip> <src-port> <dst-port>\r\n". Any
// other family keyword (TCP6, UNKNOWN, or anything malformed) is reported as
// not-ok -- this package only claims to resolve IPv4 client addresses; a
// connection carrying anything else is treated exactly like one with no
// PROXY header at all.
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
