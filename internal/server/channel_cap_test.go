package server

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSH allows unlimited channels per connection. Like sshd's MaxSessions
// (default 10, measured on 8.9p1), the cap counts channels open at once:
// the 11th concurrent one is refused with "open failed" (reason 2), while
// any number of sequential ones succeed. A lifetime cap made a bot that
// runs each command in its own exec channel fail after a few commands.
func TestConnectionCapsConcurrentChannelsLikeMaxSessions(t *testing.T) {
	addr := startDeadlineTestSensor(t, 5*time.Second)

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password("root")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dialing test sensor: %v", err)
	}
	defer client.Close()

	var held []ssh.Channel
	var refusal error
	for i := 0; i < 13; i++ {
		ch, reqs, err := client.OpenChannel("session", nil)
		if err != nil {
			refusal = err
			break
		}
		go ssh.DiscardRequests(reqs)
		held = append(held, ch)
	}
	if len(held) != 10 {
		t.Errorf("held %d channels open at once, want 10 like sshd", len(held))
	}
	var oce *ssh.OpenChannelError
	if !errors.As(refusal, &oce) || oce.Reason != ssh.ConnectionFailed || oce.Message != "open failed" {
		t.Errorf("refusal = %v, want ConnectionFailed \"open failed\"", refusal)
	}
	for _, ch := range held {
		ch.Close()
	}

	for i := 0; i < 30; i++ {
		var s *ssh.Session
		for try := 0; try < 50; try++ { // closes are asynchronous
			if s, err = client.NewSession(); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("sequential session %d: %v", i, err)
		}
		if err := s.Run("true"); err != nil {
			t.Fatalf("sequential exec %d: %v", i, err)
		}
		s.Close()
	}
}
