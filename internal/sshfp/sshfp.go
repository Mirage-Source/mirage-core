// Package sshfp fingerprints SSH clients from their key-exchange offer.
//
// HASSH (Salesforce, 2018) is md5 of "kex;enc_c2s;mac_c2s;comp_c2s", the
// client-to-server algorithm lists in the client's SSH_MSG_KEXINIT. Unlike
// the version banner, which any tool can set to anything, these lists come
// from the SSH library the client was built with, so they group bots by
// implementation even when the banner lies.
package sshfp

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"sync"
)

const (
	msgKexInit = 20
	// RFC 4253 6.1: implementations must handle packets of 35000 bytes.
	maxPacket = 35000
	// The version line is at most 255 bytes; give up well past both.
	maxCapture = 64 << 10
	// Lines a client might send before its version line; RFC 4253 only
	// allows this for servers, so a handful is generous.
	maxPreambleLines = 8
)

type Result struct {
	HASSH      string // hex md5 of Algorithms
	Algorithms string // "kex;enc_c2s;mac_c2s;comp_c2s"
}

// Lists are the eight algorithm name-lists of a KEXINIT, in wire order.
type Lists struct {
	Kex, HostKey, CiphersC2S, CiphersS2C, MACsC2S, MACsS2C, CompC2S, CompS2C string
}

// Parse extracts the HASSH inputs from the first bytes a client sent: its
// version line, then its KEXINIT packet. ok is false until the whole packet
// is present, and for anything that is not a well-formed KEXINIT.
func Parse(data []byte) (Result, bool) {
	l, ok := ParseLists(data)
	if !ok {
		return Result{}, false
	}
	algos := strings.Join([]string{l.Kex, l.CiphersC2S, l.MACsC2S, l.CompC2S}, ";")
	sum := md5.Sum([]byte(algos))
	return Result{HASSH: hex.EncodeToString(sum[:]), Algorithms: algos}, true
}

// ParseLists returns every name-list of the KEXINIT that follows the
// version line in data. It works on either side's stream.
func ParseLists(data []byte) (Lists, bool) {
	rest := data
	for i := 0; ; i++ {
		idx := bytes.IndexByte(rest, '\n')
		if idx < 0 || i >= maxPreambleLines {
			return Lists{}, false
		}
		line := rest[:idx]
		rest = rest[idx+1:]
		if bytes.HasPrefix(line, []byte("SSH-")) {
			break
		}
	}

	if len(rest) < 5 {
		return Lists{}, false
	}
	packetLen := binary.BigEndian.Uint32(rest)
	if packetLen < 1+1+16 || packetLen > maxPacket || uint64(len(rest)) < 4+uint64(packetLen) {
		return Lists{}, false
	}
	padLen := uint32(rest[4])
	if padLen+1 >= packetLen {
		return Lists{}, false
	}
	payload := rest[5 : 5+packetLen-padLen-1]
	if len(payload) < 17 || payload[0] != msgKexInit {
		return Lists{}, false
	}

	p := payload[17:] // skip message type and 16-byte cookie
	var lists [8]string
	for i := range lists {
		if len(p) < 4 {
			return Lists{}, false
		}
		n := binary.BigEndian.Uint32(p)
		if uint64(len(p)-4) < uint64(n) {
			return Lists{}, false
		}
		lists[i] = string(p[4 : 4+n])
		p = p[4+n:]
	}
	return Lists{lists[0], lists[1], lists[2], lists[3], lists[4], lists[5], lists[6], lists[7]}, true
}

// Capture tees the bytes a client sends until its KEXINIT has been parsed,
// then stops copying. It never alters what the wrapped reader sees.
type Capture struct {
	net.Conn

	mu   sync.Mutex
	buf  []byte
	done bool
	res  Result
	ok   bool
}

func NewCapture(c net.Conn) *Capture {
	return &Capture{Conn: c}
}

func (c *Capture) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.mu.Lock()
		if !c.done {
			c.buf = append(c.buf, b[:n]...)
			if r, ok := Parse(c.buf); ok {
				c.res, c.ok, c.done = r, true, true
				c.buf = nil
			} else if len(c.buf) >= maxCapture {
				c.done, c.buf = true, nil
			}
		}
		c.mu.Unlock()
	}
	return n, err
}

// Result is safe to call while the SSH library is still reading.
func (c *Capture) Result() (Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.res, c.ok
}
