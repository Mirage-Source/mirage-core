package server

import (
	"net"
	"log"
	"os"
	"golang.org/x/crypto/ssh"
	"github.com/mirage-source/mirage-core/internal/shell"
	"io"
	"fmt"
	"errors"
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
		}, }
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
	handleChannels(chans)
}

func handleChannels(chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		log.Printf("New channel type: %s", newChannel.ChannelType())
		switch newChannel.ChannelType() {
			case "session":
				channel, requests, err := newChannel.Accept()
				if err != nil {
					log.Printf("Could not accept channel: %v", err)
					continue
				}
				go handleSessionRequests(channel, requests)
			default:
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

func handleSessionRequests(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()
	var inputBuffer []byte
	log.Printf("Session started.")

	for req := range requests {
		log.Printf("Recieved session request type %s", req.Type)

		switch req.Type {
			case "pty-req":
				req.Reply(true, nil)
			case "shell", "exec":
				req.Reply(true, nil)
				fmt.Fprintf(channel, "Welcome to Ubuntu 22.04.3 LTS\r\n")

				for {
					fmt.Fprintf(channel, "ubuntu@ip-172-31-14-52:~$ ")

					for {
						singleByte := make([]byte, 1)
						_, err := channel.Read(singleByte)
						if err != nil {
							if errors.Is(err, io.EOF) {
								log.Printf("Client closed the input stream.")
								return
							}
							log.Printf("Read error on channel: %v", err)
							return
						}

						b := singleByte[0]

						if b == '\r' {
							fmt.Fprintf(channel, "\r\n")
							break
						}
						channel.Write(singleByte)
						inputBuffer = append(inputBuffer, b)
					}

					cli := string(inputBuffer)
					inputBuffer = inputBuffer[:0]

					if len(cli) > 0 {
						response, _ := shell.Handle(cli)
						fmt.Fprintf(channel, "%s\r\n", response)
					}
				}
			default:
				req.Reply(false, nil)
			}
		}
		log.Printf("Session ended.")
}
