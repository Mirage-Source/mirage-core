package ssh

// Tests for the MIRAGE: patches. Expected values were measured against
// ubuntu:22.04 openssh-server 1:8.9p1-3ubuntu0.18.

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func mirageServer(t *testing.T, cfg *ServerConfig) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				sc, chans, reqs, err := NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go DiscardRequests(reqs)
				for ch := range chans {
					ch.Reject(Prohibited, "")
				}
				sc.Close()
			}()
		}
	}()
	return ln.Addr()
}

func mirageConfig(t *testing.T) *ServerConfig {
	cfg := &ServerConfig{
		PasswordCallback:  func(ConnMetadata, []byte) (*Permissions, error) { return nil, io.EOF },
		PublicKeyCallback: func(ConnMetadata, PublicKey) (*Permissions, error) { return nil, io.EOF },
		ServerVersion:     "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
	}
	cfg.AddHostKey(testSigners["ed25519"])
	return cfg
}

// talk sends client bytes after reading the server banner and returns
// everything the server sent until it closed or went quiet.
func talk(t *testing.T, addr net.Addr, client []byte) (banner string, rest []byte) {
	t.Helper()
	c, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	br := bufio.NewReader(c)
	banner, _ = br.ReadString('\n')
	c.Write(client)
	c.SetReadDeadline(time.Now().Add(time.Second))
	rest, _ = io.ReadAll(br)
	return banner, rest
}

func TestMirageIdentificationLikeSSHD(t *testing.T) {
	addr := mirageServer(t, mirageConfig(t))
	const invalid = "Invalid SSH identification string.\r\n"
	const differ = "Protocol major versions differ.\r\n"
	for _, tc := range []struct {
		client string
		want   string // "" means the handshake continues with KEXINIT
	}{
		{"SSH-2.0-OpenSSH_8.9\r\n", ""},
		{"SSH-2.0-x\n", ""},
		{"SSH-2.2-OpenSSH \r\n", ""},
		{"SSH-2.5-x\r\n", ""},
		{"SSH-1.99-x\r\n", ""},
		{"SSH-2.0-x y z\r\n", ""},
		{"SSH-2.0-" + strings.Repeat("A", 1000) + "\r\n", ""},
		{"SSH-2.0-" + strings.Repeat("A", 9000) + "\r\n", invalid},
		{"SSH-1.5-x\r\n", differ},
		{"SSH-3.0-x\r\n", differ},
		{"SSH-2.0\r\n", invalid},
		{"SSH-2.0-\r\n", invalid},
		{"ssh-2.0-x\r\n", invalid},
		{"\r\n", invalid},
		{"GET / HTTP/1.0\r\n", invalid},
		{"hello\r\nSSH-2.0-x\r\n", invalid},
		{"SSH-2.0-x\x00\r\n", invalid},
	} {
		_, got := talk(t, addr, []byte(tc.client))
		switch {
		case tc.want == "" && (len(got) < 6 || got[5] != msgKexInit):
			t.Errorf("%.30q: want KEXINIT, got %q", tc.client, got)
		case tc.want != "" && string(got) != tc.want:
			t.Errorf("%.30q: got %q, want %q", tc.client, got, tc.want)
		}
	}
}

func TestMirageKexInitZeroPadded(t *testing.T) {
	addr := mirageServer(t, mirageConfig(t))
	_, got := talk(t, addr, []byte("SSH-2.0-OpenSSH_8.9\r\n"))
	if len(got) < 5 {
		t.Fatalf("no packet: %q", got)
	}
	length := binary.BigEndian.Uint32(got)
	pad := int(got[4])
	if int(length)+4 > len(got) {
		t.Fatalf("short packet")
	}
	padding := got[4+int(length)-pad : 4+int(length)]
	if !bytes.Equal(padding, make([]byte, pad)) {
		t.Errorf("KEXINIT padding %x, want zeros like OpenSSH", padding)
	}
}

// A client that sends garbage right after its version line must still
// receive the server's KEXINIT first, every time.
func TestMirageKexInitBeforeReadError(t *testing.T) {
	addr := mirageServer(t, mirageConfig(t))
	for i := 0; i < 30; i++ {
		_, got := talk(t, addr, []byte("SSH-2.0-OpenSSH\n\n\n\n\n\n\n\n\n\n"))
		if len(got) < 6 || got[5] != msgKexInit {
			t.Fatalf("try %d: got %q, want KEXINIT before close", i, got)
		}
	}
}

// noneProbe sends "none" itself and records the methods the server lists.
type noneProbe struct{ methods []string }

func (n *noneProbe) method() string { return "publickey" } // any listed name gets it called

func (n *noneProbe) auth(session []byte, user string, c packetConn, rand io.Reader, _ map[string][]byte) (authResult, []string, error) {
	if err := c.writePacket(Marshal(&userAuthRequestMsg{User: user, Service: serviceSSH, Method: "none"})); err != nil {
		return authFailure, nil, err
	}
	for {
		p, err := c.readPacket()
		if err != nil {
			return authFailure, nil, err
		}
		if p[0] == msgUserAuthFailure {
			var msg userAuthFailureMsg
			if err := Unmarshal(p, &msg); err != nil {
				return authFailure, nil, err
			}
			n.methods = msg.Methods
			return authFailure, nil, io.EOF
		}
	}
}

func TestMirageAuthMethodOrder(t *testing.T) {
	cfg := mirageConfig(t)
	cfg.KeyboardInteractiveCallback = func(ConnMetadata, KeyboardInteractiveChallenge) (*Permissions, error) {
		return nil, io.EOF
	}
	addr := mirageServer(t, cfg)
	probe := &noneProbe{}
	Dial("tcp", addr.String(), &ClientConfig{User: "x", Auth: []AuthMethod{probe}, HostKeyCallback: InsecureIgnoreHostKey()})
	if got := strings.Join(probe.methods, ","); got != "publickey,password,keyboard-interactive" {
		t.Errorf("methods = %q, want OpenSSH order publickey,password,keyboard-interactive", got)
	}
}

func TestMirageRSAHostKeyOrder(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := NewSignerFromKey(key)
	ms, _ := NewSignerWithAlgorithms(signer.(AlgorithmSigner), []string{KeyAlgoRSASHA512, KeyAlgoRSASHA256})
	cfg := mirageConfig(t)
	cfg.AddHostKey(ms)
	addr := mirageServer(t, cfg)
	_, got := talk(t, addr, []byte("SSH-2.0-OpenSSH_8.9\r\n"))
	length := binary.BigEndian.Uint32(got)
	var kex kexInitMsg
	if err := Unmarshal(got[5:4+int(length)-int(got[4])], &kex); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(kex.ServerHostKeyAlgos, ","); got != "ssh-ed25519,rsa-sha2-512,rsa-sha2-256" {
		t.Errorf("host key algos = %s", got)
	}
}
