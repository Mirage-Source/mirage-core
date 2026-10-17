package server

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mirage-source/mirage-core/internal/session"
	"github.com/mirage-source/mirage-core/internal/sshfp"
	"golang.org/x/crypto/ssh"
)

// serverKexInit returns the algorithm lists the sensor's KEXINIT advertises.
func serverKexInit(t *testing.T) sshfp.Lists {
	t.Helper()
	return serverKexInitWith(t, []ssh.Signer{testSigner(t)})
}

func serverKexInitWith(t *testing.T, keys []ssh.Signer) sshfp.Lists {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := newSSHServerConfig(&session.Session{}, nil, sshAuthConfig{authDelay: func(string, bool) time.Duration { return 0 }}, keys...)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		newServerConnForTest(c, cfg)
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("SSH-2.0-OpenSSH_8.9p1\r\n"))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var got []byte
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		got = append(got, buf[:n]...)
		if l, ok := sshfp.ParseLists(got); ok {
			return l
		}
		if err != nil {
			t.Fatalf("no KEXINIT: %v (%q)", err, got)
		}
	}
}

// Measured 2026-10-17 with ssh-audit against ubuntu:22.04's
// openssh-server 1:8.9p1-3ubuntu0.18, minus what x/crypto cannot do
// (sntrup761x25519-sha512@openssh.com and the umac MACs). group18 and
// hmac-sha1-etm come from third_party's patched x/crypto. Order is OpenSSH's.
const (
	wantKexPrefix = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256"
	wantCiphers   = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
	wantMACs      = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"
)

func TestAdvertisedAlgorithmsFollowOpenSSH89(t *testing.T) {
	l := serverKexInit(t)

	// After OpenSSH's list, only protocol pseudo-algorithms may follow
	// (strict-kex, ext-info), which real 8.9 sends too.
	if !strings.HasPrefix(l.Kex, wantKexPrefix) {
		t.Errorf("kex = %s\nwant prefix %s", l.Kex, wantKexPrefix)
	}
	for _, extra := range strings.Split(strings.TrimPrefix(strings.TrimPrefix(l.Kex, wantKexPrefix), ","), ",") {
		if extra != "" && !strings.HasPrefix(extra, "kex-strict-") && !strings.HasPrefix(extra, "ext-info-") {
			t.Errorf("kex offers %q, which OpenSSH 8.9 does not", extra)
		}
	}
	if l.CiphersS2C != wantCiphers || l.CiphersC2S != wantCiphers {
		t.Errorf("ciphers = %s / %s\nwant %s", l.CiphersC2S, l.CiphersS2C, wantCiphers)
	}
	if l.MACsS2C != wantMACs || l.MACsC2S != wantMACs {
		t.Errorf("macs = %s / %s\nwant %s", l.MACsC2S, l.MACsS2C, wantMACs)
	}
	if l.CompS2C != "none,zlib@openssh.com" && l.CompS2C != "none" {
		t.Errorf("compression = %s", l.CompS2C)
	}
}

func newServerConnForTest(c net.Conn, cfg *ssh.ServerConfig) {
	if sc, _, _, err := ssh.NewServerConn(c, cfg); err == nil {
		sc.Close()
	}
}
