package server

import (
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSH allows unlimited channels per connection, and handleChannels spawned an
// unbounded goroutine per session channel. The command and input-byte caps
// bound what a connection can store, not how many read loops it can hold open.
func TestConnectionRefusesChannelsPastTheCap(t *testing.T) {
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

	var opened int
	var held []ssh.Channel
	for i := 0; i < maxChannelsPerConnection+10; i++ {
		ch, reqs, err := client.OpenChannel("session", nil)
		if err != nil {
			break
		}
		go ssh.DiscardRequests(reqs)
		held = append(held, ch)
		opened++
	}
	for _, ch := range held {
		ch.Close()
	}

	if opened > maxChannelsPerConnection {
		t.Errorf("opened %d channels, want at most %d", opened, maxChannelsPerConnection)
	}
	if opened == 0 {
		t.Error("opened 0 channels; the cap rejects everything")
	}
}
