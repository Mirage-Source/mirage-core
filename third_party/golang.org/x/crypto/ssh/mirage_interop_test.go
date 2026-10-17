package ssh

// Interop tests against the real OpenSSH client for the algorithms added in
// mirage_algorithms.go: a Go-only round trip cannot catch a bug both sides
// share. Skipped when no ssh binary is installed.

import (
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// sessionServer accepts any client and answers one exec with status 0.
func sessionServer(t *testing.T, cfg *ServerConfig) string {
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
				c.SetDeadline(time.Now().Add(20 * time.Second))
				_, chans, reqs, err := NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						for r := range creqs {
							r.Reply(r.Type == "exec", nil)
							if r.Type == "exec" {
								ch.Write([]byte("mirage-ok\n"))
								ch.SendRequest("exit-status", false, Marshal(struct{ Status uint32 }{0}))
								ch.Close()
							}
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func opensshConnect(t *testing.T, addr string, opts ...string) string {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("no ssh client")
	}
	host, port, _ := net.SplitHostPort(addr)
	args := []string{"-v", "-p", port, "-F", "/dev/null",
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes", "-o", "ConnectTimeout=10"}
	args = append(args, opts...)
	args = append(args, "x@"+host, "true")
	out, err := exec.Command("ssh", args...).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "mirage-ok") {
		t.Fatalf("ssh %v: %v\n%s", opts, err, out)
	}
	return string(out)
}

func interopConfig(t *testing.T) *ServerConfig {
	cfg := &ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(testSigners["ed25519"])
	cfg.KeyExchanges = append(supportedKexAlgos, keyExchangeCurve25519LibSSH)
	cfg.MACs = append([]string{}, supportedMACs...)
	return cfg
}

func TestMirageInteropGroup18(t *testing.T) {
	addr := sessionServer(t, interopConfig(t))
	out := opensshConnect(t, addr, "-o", "KexAlgorithms=diffie-hellman-group18-sha512")
	if !strings.Contains(out, "kex: algorithm: diffie-hellman-group18-sha512") {
		t.Errorf("group18 not negotiated:\n%s", out)
	}
}

func TestMirageInteropMACs(t *testing.T) {
	addr := sessionServer(t, interopConfig(t))
	for _, mac := range newMACsUnderTest() {
		out := opensshConnect(t, addr, "-o", "Ciphers=aes128-ctr", "-o", "MACs="+mac)
		if !strings.Contains(out, "MAC: "+mac) {
			t.Errorf("%s not negotiated:\n%s", mac, out)
		}
	}
}

func newMACsUnderTest() []string { return []string{HMACSHA1ETM} }
