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
	"time"
	"github.com/google/uuid"
	"github.com/mirage-source/mirage-core/internal/session"
	"strings"
	"encoding/base64"
	"github.com/mirage-source/mirage-core/internal/store"
	"database/sql"
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

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal("Error listening:", err)
	}
	defer listener.Close()

	db, err := store.Connect()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		sess := session.Session{
			SessionID: uuid.New().String(),
			SchemaVersion: "1.0",
			NodeID: "Ubuntu",
			Protocol: session.ProtocolSSH,
			Outcome: session.OutcomeActive,
			BaitEvents: []session.BaitEvent{},
			Timing: session.Timing{
				StartMS: time.Now().UnixMilli(),
			},
		}

		config := &ssh.ServerConfig{
			ServerVersion: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
			PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
				username := conn.User()
				pass := string(password)
				sess.AuthAttempts = append(sess.AuthAttempts, session.AuthAttempt{
					TimestampMS: time.Now().UnixMilli(),
					Method: session.AuthMethodPassword,
					Username: username,
					Credential: pass,
					Success: true,
				})
				log.Printf("User %s, password %s", username, pass)
				return nil, nil
			}, }
		config.AddHostKey(parsedKey)
		go handleConnection(conn, config, &sess, db)	//this will handle the connection concurrently
	}
}

func handleConnection(conn net.Conn, config *ssh.ServerConfig, sess *session.Session, db *sql.DB) {
	defer conn.Close()

	//log remote address
	log.Printf("New connection from %v", conn.RemoteAddr())
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("Failed to handshake: %v", err)
		return
	}
	remoteAddr := conn.RemoteAddr()

	sess.Network.SSHClientBanner = string(sshConn.ClientVersion())

	if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
		sess.Network.ClientIP = tcpAddr.IP.String()
		sess.Network.ClientPort = tcpAddr.Port
	}

	if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		sess.Network.ServerPort = tcpAddr.Port
	}
	log.Printf("Client Version: %s", sshConn.ClientVersion())
	go ssh.DiscardRequests(reqs)
	handleChannels(chans, sess, db)
}

func handleChannels(chans <-chan ssh.NewChannel, sess *session.Session, db *sql.DB) {
	for newChannel := range chans {
		log.Printf("New channel type: %s", newChannel.ChannelType())
		switch newChannel.ChannelType() {
			case "session":
				channel, requests, err := newChannel.Accept()
				if err != nil {
					log.Printf("Could not accept channel: %v", err)
					continue
				}
				go handleSessionRequests(channel, requests, sess, db)
			default:
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

func handleSessionRequests(channel ssh.Channel, requests <-chan *ssh.Request, sess *session.Session, db *sql.DB) {
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
								endMS := time.Now().UnixMilli()
								duration := endMS - sess.Timing.StartMS
								sess.Timing.EndMS = &endMS
								sess.Timing.DurationMS = &duration
								sess.Outcome = session.OutcomeCleanDisconnect
								if err := store.SaveSession(db, sess); err != nil {
									log.Printf("Error saving session: %v", err)
								}
								return
							}
							log.Printf("Read error on channel: %v", err)
							endMS := time.Now().UnixMilli()
							duration := endMS - sess.Timing.StartMS
							sess.Timing.EndMS = &endMS
							sess.Timing.DurationMS = &duration
							sess.Outcome = session.OutcomeConnectionReset
							if err := store.SaveSession(db, sess); err != nil {
								log.Printf("Error saving session: %v", err)
							}
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
					now := time.Now().UnixMilli()

					var delay *int64
					if len(sess.Commands) > 0 {
						prev := now - sess.Commands[len(sess.Commands)-1].TimestampMS
						delay = &prev
					}

					raw := base64.StdEncoding.EncodeToString(inputBuffer)

					words := strings.Fields(cli)
					var parsedCommand string
					var parsedArgs []string
					if len(words) > 0 {
						parsedCommand = words[0]
						parsedArgs = words[1:]
					}

					cmd := session.Command{
						EventID: uuid.New().String(),
						SequenceNumber: len(sess.Commands),
						TimestampMS: now,
						InterCommandDelayMS: delay,
						RawInputB64: raw,
						ParsedCommand: parsedCommand,
						ParsedArgs: parsedArgs,
						WorkingDirectory: "/home/ubuntu",
						ResponseSource: session.ResponseSourceHardcoded,
					}
					sess.Commands = append(sess.Commands, cmd)

					if len(cli) > 0 {
						response, code:= shell.Handle(cli)
						inputBuffer = inputBuffer[:0]
						if code == 257 {
							fmt.Fprintf(channel, "logout\r\n")
							endMS := time.Now().UnixMilli()
							duration := endMS - sess.Timing.StartMS
							sess.Timing.EndMS = &endMS
							sess.Timing.DurationMS = &duration
							sess.Outcome = session.OutcomeCleanDisconnect
							if err := store.SaveSession(db, sess); err != nil {
								log.Printf("Error saving session: %v", err)
							}
							return
						}
						fmt.Fprintf(channel, "%s\r\n", response)
					}
				}
			default:
				req.Reply(false, nil)
			}
		}

		log.Printf("Session ended.")
}
