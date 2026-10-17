package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mirage-source/mirage-core/internal/session"
	"golang.org/x/crypto/ssh"
)

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// runAuth performs one SSH handshake against newSSHServerConfig and returns
// the session the callbacks filled in, plus the client's handshake error.
func runAuth(t *testing.T, clientAuth []ssh.AuthMethod) (*session.Session, error) {
	return runAuthWith(t, clientAuth, false)
}

func runAuthWith(t *testing.T, clientAuth []ssh.AuthMethod, keyboardInteractive bool) (*session.Session, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	sess := &session.Session{SessionID: uuid.New().String(), Protocol: session.ProtocolSSH}
	cfg := newSSHServerConfig(sess, nil, sshAuthConfig{
		weakCreds:           map[string]struct{}{"root:root": {}},
		authDelay:           func(string, bool) time.Duration { return 0 },
		keyboardInteractive: keyboardInteractive,
	}, testSigner(t))

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if sc, _, _, err := ssh.NewServerConn(c, cfg); err == nil {
			sc.Close()
		}
	}()

	client, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User:            "root",
		Auth:            clientAuth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		client.Close()
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server side did not finish")
	}
	return sess, err
}

func TestPublicKeyAttemptIsRecordedAndRejected(t *testing.T) {
	k1, k2 := testSigner(t), testSigner(t)
	sess, err := runAuth(t, []ssh.AuthMethod{ssh.PublicKeys(k1, k2), ssh.Password("root")})
	if err != nil {
		t.Fatalf("password should still succeed after rejected keys: %v", err)
	}

	if len(sess.AuthAttempts) != 3 {
		t.Fatalf("auth attempts = %+v, want 2 keys + 1 password", sess.AuthAttempts)
	}
	for i, k := range []ssh.Signer{k1, k2} {
		a := sess.AuthAttempts[i]
		want := "ssh-ed25519 " + ssh.FingerprintSHA256(k.PublicKey())
		if a.Method != session.AuthMethodPublicKey || a.Credential != want || a.Success || a.Username != "root" {
			t.Errorf("attempt %d = %+v, want rejected publickey %q", i, a, want)
		}
	}
	if last := sess.AuthAttempts[2]; last.Method != session.AuthMethodPassword || !last.Success {
		t.Errorf("last attempt = %+v, want successful password", last)
	}
	// sessionGuard.username relies on the last attempt being the one that
	// authenticated.
	if got := (&sessionGuard{sess: sess}).username(); got != "root" {
		t.Errorf("username() = %q", got)
	}
}

func TestPublicKeyOnlyClientStillGetsNetworkMetadata(t *testing.T) {
	sess, err := runAuth(t, []ssh.AuthMethod{ssh.PublicKeys(testSigner(t))})
	if err == nil {
		t.Fatal("a key-only client must never authenticate")
	}
	if len(sess.AuthAttempts) != 1 || sess.AuthAttempts[0].Method != session.AuthMethodPublicKey {
		t.Fatalf("auth attempts = %+v", sess.AuthAttempts)
	}
	// A key-only bot never reaches PasswordCallback; without this the
	// auth_failed row would have a blank client_ip and banner.
	if sess.Network.ClientIP != "127.0.0.1" || sess.Network.SSHClientBanner == "" {
		t.Errorf("network = %+v", sess.Network)
	}
}

func answer(pass string, prompts *[]string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		*prompts = append(*prompts, questions...)
		out := make([]string, len(questions))
		for i := range out {
			out[i] = pass
		}
		return out, nil
	})
}

func TestKeyboardInteractiveIsRecordedWhenEnabled(t *testing.T) {
	var prompts []string
	calls := 0
	method := ssh.RetryableAuthMethod(ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
		prompts = append(prompts, questions...)
		calls++
		if calls == 1 {
			return []string{"wrong"}, nil
		}
		return []string{"root"}, nil
	}), 2)
	sess, err := runAuthWith(t, []ssh.AuthMethod{method}, true)
	if err != nil {
		t.Fatalf("keyboard-interactive login failed: %v", err)
	}
	if len(prompts) == 0 || prompts[0] != "Password: " {
		t.Errorf("prompts = %q, want PAM's \"Password: \"", prompts)
	}
	if len(sess.AuthAttempts) != 2 {
		t.Fatalf("attempts = %+v", sess.AuthAttempts)
	}
	for i, wantOK := range []bool{false, true} {
		a := sess.AuthAttempts[i]
		if a.Method != session.AuthMethodKeyboardInteractive || a.Success != wantOK || a.Username != "root" {
			t.Errorf("attempt %d = %+v", i, a)
		}
	}
	if sess.AuthAttempts[1].Credential != "root" {
		t.Errorf("credential = %q", sess.AuthAttempts[1].Credential)
	}
}

// Off by default: a stock Ubuntu 22.04 sshd does not offer it.
func TestKeyboardInteractiveIsNotOfferedByDefault(t *testing.T) {
	var prompts []string
	sess, err := runAuth(t, []ssh.AuthMethod{answer("root", &prompts)})
	if err == nil {
		t.Fatal("keyboard-interactive succeeded with the method disabled")
	}
	if len(prompts) != 0 || len(sess.AuthAttempts) != 0 {
		t.Errorf("prompts = %q, attempts = %+v", prompts, sess.AuthAttempts)
	}
}
