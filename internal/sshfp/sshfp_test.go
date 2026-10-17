package sshfp

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"crypto/ed25519"
	"crypto/rand"

	"golang.org/x/crypto/ssh"
)

func nameList(b *bytes.Buffer, s string) {
	binary.Write(b, binary.BigEndian, uint32(len(s)))
	b.WriteString(s)
}

// kexInitPacket builds a client version line plus an unencrypted
// SSH_MSG_KEXINIT binary packet (RFC 4253 7.1).
func kexInitPacket(lists [10]string) []byte {
	var payload bytes.Buffer
	payload.WriteByte(20)
	payload.Write(make([]byte, 16)) // cookie
	for _, l := range lists {
		nameList(&payload, l)
	}
	payload.WriteByte(0)              // first_kex_packet_follows
	payload.Write([]byte{0, 0, 0, 0}) // reserved
	pad := 8 - (5+payload.Len())%8
	if pad < 4 {
		pad += 8
	}
	var pkt bytes.Buffer
	binary.Write(&pkt, binary.BigEndian, uint32(1+payload.Len()+pad))
	pkt.WriteByte(byte(pad))
	pkt.Write(payload.Bytes())
	pkt.Write(make([]byte, pad))
	return append([]byte("SSH-2.0-test_client\r\n"), pkt.Bytes()...)
}

var sample = [10]string{
	"curve25519-sha256,diffie-hellman-group14-sha256", // kex
	"ssh-ed25519",           // host key
	"aes128-ctr,aes256-ctr", // enc c2s
	"aes256-ctr",            // enc s2c
	"hmac-sha2-256",         // mac c2s
	"hmac-sha1",             // mac s2c
	"none,zlib@openssh.com", // comp c2s
	"none",                  // comp s2c
	"", "",                  // languages
}

func wantHASSH(algos string) string {
	sum := md5.Sum([]byte(algos))
	return hex.EncodeToString(sum[:])
}

func TestParseKexInit(t *testing.T) {
	r, ok := Parse(kexInitPacket(sample))
	if !ok {
		t.Fatal("not parsed")
	}
	wantAlgos := "curve25519-sha256,diffie-hellman-group14-sha256;aes128-ctr,aes256-ctr;hmac-sha2-256;none,zlib@openssh.com"
	if r.Algorithms != wantAlgos || r.HASSH != wantHASSH(wantAlgos) {
		t.Fatalf("got %+v", r)
	}
}

func TestBareLFVersionLineAndPreamble(t *testing.T) {
	data := kexInitPacket(sample)
	data = bytes.Replace(data, []byte("\r\n"), []byte("\n"), 1)
	if _, ok := Parse(data); !ok {
		t.Fatal("LF-terminated version line not accepted")
	}
}

func TestTruncatedAndMalformedInputDoNotParse(t *testing.T) {
	full := kexInitPacket(sample)
	for i := 0; i < len(full); i++ {
		if _, ok := Parse(full[:i]); ok {
			t.Fatalf("parsed from a %d-byte prefix", i)
		}
	}
	notKex := append([]byte(nil), full...)
	notKex[len("SSH-2.0-test_client\r\n")+5] = 21
	if _, ok := Parse(notKex); ok {
		t.Fatal("non-KEXINIT packet parsed")
	}
	if _, ok := Parse([]byte("SSH-2.0-x\r\n\xff\xff\xff\xff\x04")); ok {
		t.Fatal("absurd packet length parsed")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(kexInitPacket(sample))
	f.Add([]byte("SSH-2.0-x\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		Parse(data) // must never panic
	})
}

// trickle hands out one byte per Read, like a fragmented TCP stream.
type trickle struct{ net.Conn }

func (t trickle) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	return t.Conn.Read(b[:1])
}

// Against a real x/crypto client: the capture must see exactly the
// algorithms the client was configured to offer, without disturbing the
// handshake it sits under.
func TestCaptureUnderRealHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)

	got := make(chan Result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		cap := NewCapture(trickle{c})
		sc, _, _, err := ssh.NewServerConn(cap, cfg)
		if err == nil {
			sc.Close()
		}
		r, _ := cap.Result()
		got <- r
	}()

	clientCfg := &ssh.ClientConfig{
		User:            "x",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
		Config: ssh.Config{
			KeyExchanges: []string{"curve25519-sha256"},
			Ciphers:      []string{"aes128-ctr"},
			MACs:         []string{"hmac-sha2-256"},
		},
	}
	client, err := ssh.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("handshake through capture failed: %v", err)
	}
	client.Close()

	r := <-got
	// x/crypto appends its own extension pseudo-algorithms to the kex list.
	kex := strings.SplitN(r.Algorithms, ";", 2)[0]
	if !strings.HasPrefix(kex, "curve25519-sha256") {
		t.Fatalf("kex list %q", kex)
	}
	if !strings.HasSuffix(r.Algorithms, ";aes128-ctr;hmac-sha2-256;none") {
		t.Fatalf("algorithms %q", r.Algorithms)
	}
	if r.HASSH != wantHASSH(r.Algorithms) {
		t.Fatal("hash does not match algorithms")
	}
}

var _ = io.EOF
