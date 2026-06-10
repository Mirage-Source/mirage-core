package server

import (
	"net"
	"log"
	"os"
	"golang.org/x/crypto/ssh"
)

func Start(addr string) {

	hostKey,err := os.ReadFile("config/hostkey")
	if err != nil {
		log.Fatal(err)
	}

	parsedKey, err := ssh.ParsePrivateKey(hostKey)
	if err != nil {
		log.Fatal(err)
	}
	config := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			username := conn.User()
			pass := string(password)
			log.Printf("User %s, password %s", username, pass)
			return nil, nil
		},
	}
	config.AddHostKey(parsedKey)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal("Error listening:", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go handleConnection(conn, config)	//this will handle the connection concurrently
	}
}

func handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()

	//log remote address
	log.Printf("New connection from %v", conn.RemoteAddr())
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("Failed to handshake: %v", err)
		return
	}
	log.Printf("Client Version: %s", sshConn.ClientVersion())

	go ssh.DiscardRequests(reqs)
	go handleChannels(chans)
}

func handleChannels(chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
	}
}



