package server

import (
	"bufio"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mirage-source/mirage-core/internal/session"
	"github.com/mirage-source/mirage-core/internal/shell"
	"github.com/mirage-source/mirage-core/internal/store"
	"golang.org/x/crypto/ssh"
)

const MaxInput = 255
const maxCommandsPerSession = 500

const defaultIdleTimeout = 120 * time.Second
const defaultHandshakeTimeout = 20 * time.Second

func Start(addr string) {
	hostKey, err := os.ReadFile("config/hostkey")
	if err != nil {
		log.Fatal(err)
	}

	parsedKey, err := ssh.ParsePrivateKey(hostKey)
	if err != nil {
		log.Fatal(err)
	}

	credPath := os.Getenv("WEAK_CREDENTIALS_FILE")
	if credPath == "" {
		credPath = "config/weak_credentials.txt"
	}
	weakCreds := loadWeakCredentials(credPath)
	log.Printf("Loaded %d weak credential pair(s) from %s", len(weakCreds), credPath)

	idleTimeout := envDuration("SSH_IDLE_TIMEOUT_SECONDS", defaultIdleTimeout)
	handshakeTimeout := envDuration("SSH_HANDSHAKE_TIMEOUT_SECONDS", defaultHandshakeTimeout)

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
			SessionID:     uuid.New().String(),
			SchemaVersion: "1.1",
			NodeID:        "Ubuntu",
			Protocol:      session.ProtocolSSH,
			Outcome:       session.OutcomeActive,
			BaitEvents:    []session.BaitEvent{},
			Timing: session.Timing{
				StartMS: time.Now().UnixMilli(),
			},
		}

		config := &ssh.ServerConfig{
			ServerVersion: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
			MaxAuthTries:  6,
			PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
				username := conn.User()
				pass := string(password)
				_, accepted := weakCreds[username+":"+pass]

				sess.AuthAttempts = append(sess.AuthAttempts, session.AuthAttempt{
					TimestampMS: time.Now().UnixMilli(),
					Method:      session.AuthMethodPassword,
					Username:    username,
					Credential:  pass,
					Success:     accepted,
				})
				log.Printf("Auth attempt user=%s password=%s accepted=%v", username, pass, accepted)

				delay := time.Duration(500+rand.Intn(2500)) * time.Millisecond
				time.Sleep(delay)

				if !accepted {
					return nil, errors.New("invalid credentials")
				}
				return nil, nil
			},
		}
		config.AddHostKey(parsedKey)
		go handleConnection(conn, config, &sess, db, idleTimeout, handshakeTimeout) //this will handle the connection concurrently
	}
}

// loadWeakCredentials reads "username:password" pairs, one per line
// (blank lines and lines starting with # are ignored). A missing or empty
// file means nothing will ever authenticate successfully.
func loadWeakCredentials(path string) map[string]struct{} {
	set := map[string]struct{}{}

	f, err := os.Open(path)
	if err != nil {
		log.Printf("warning: could not load weak credential list from %s: %v", path, err)
		return set
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set[line] = struct{}{}
	}
	return set
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs <= 0 {
		return fallback
	}
	return time.Duration(secs) * time.Second
}

func handleConnection(conn net.Conn, config *ssh.ServerConfig, sess *session.Session, db *sql.DB, idleTimeout, handshakeTimeout time.Duration) {
	defer conn.Close()

	log.Printf("New connection from %v", conn.RemoteAddr())

	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("Failed to handshake: %v", err)
		// A rejected/abandoned handshake never opens a channel, so nothing
		// would otherwise persist the credentials that were tried here.
		if len(sess.AuthAttempts) > 0 {
			finalizeSession(db, sess, session.OutcomeAuthFailed)
		}
		return
	}
	// Handshake succeeded; from here on a silent connection is bounded by
	// the idle timeout instead of hanging forever.
	conn.SetDeadline(time.Now().Add(idleTimeout))

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
	handleChannels(conn, idleTimeout, chans, sess, db)
}

func handleChannels(conn net.Conn, idleTimeout time.Duration, chans <-chan ssh.NewChannel, sess *session.Session, db *sql.DB) {
	for newChannel := range chans {
		log.Printf("New channel type: %s", newChannel.ChannelType())
		switch newChannel.ChannelType() {
		case "session":
			channel, requests, err := newChannel.Accept()
			if err != nil {
				log.Printf("Could not accept channel: %v", err)
				continue
			}
			go handleSessionRequests(conn, idleTimeout, channel, requests, sess, db)
		default:
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

func handleSessionRequests(conn net.Conn, idleTimeout time.Duration, channel ssh.Channel, requests <-chan *ssh.Request, sess *session.Session, db *sql.DB) {
	defer channel.Close()
	var inputBuffer []byte
	log.Printf("Session started.")

	for req := range requests {
		log.Printf("Recieved session request type %s", req.Type)

		switch req.Type {
		case "pty-req":
			req.Reply(true, nil)
		case "exec":
			var payload struct {
				Command string
			}
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				log.Printf("Could not unmarshal exec payload: %v", err)
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)

			log.Printf("Executing command: %s", payload.Command)

			interp := shell.NewInterpreter()
			beforeCwd := interp.Cwd
			response, code, baitHits := interp.Run(payload.Command)
			if response != "" {
				fmt.Fprintf(channel, "%s\r\n", response)
			}

			now := time.Now().UnixMilli()
			raw := base64.StdEncoding.EncodeToString([]byte(payload.Command))
			words := strings.Fields(payload.Command)
			var parsedCommand string
			var parsedArgs []string
			if len(words) > 0 {
				parsedCommand = words[0]
				parsedArgs = words[1:]
			}

			cmd := session.Command{
				EventID:             uuid.New().String(),
				SequenceNumber:      len(sess.Commands),
				TimestampMS:         now,
				InterCommandDelayMS: nil,
				RawInputB64:         raw,
				ParsedCommand:       parsedCommand,
				ParsedArgs:          parsedArgs,
				WorkingDirectory:    beforeCwd,
				ResponseSource:      responseSourceFor(baitHits),
			}
			sess.Commands = append(sess.Commands, cmd)
			appendBaitEvents(sess, cmd.EventID, baitHits)

			status := code
			if status == shell.ExitRequested {
				status = 0
			}
			// Send exit status to notify client of success/failure
			channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: uint32(status)}))

			log.Printf("Saving exec session to DB.")
			finalizeSession(db, sess, session.OutcomeCleanDisconnect)
			return
		case "shell":
			req.Reply(true, nil)
			fmt.Fprintf(channel, "Welcome to Ubuntu 22.04.3 LTS\r\n")

			interp := shell.NewInterpreter()

			for {
				if len(sess.Commands) >= maxCommandsPerSession {
					finalizeSession(db, sess, session.OutcomeCommandLimitReached)
					return
				}

				fmt.Fprintf(channel, "%s", interp.Prompt())

				for {
					conn.SetReadDeadline(time.Now().Add(idleTimeout))
					singleByte := make([]byte, 1)
					_, err := channel.Read(singleByte)
					if err != nil {
						if errors.Is(err, io.EOF) {
							log.Printf("Client closed the input stream.")
							finalizeSession(db, sess, session.OutcomeCleanDisconnect)
							return
						}
						if ne, ok := err.(net.Error); ok && ne.Timeout() {
							log.Printf("Connection idle timeout.")
							finalizeSession(db, sess, session.OutcomeTimeout)
							return
						}
						log.Printf("Read error on channel: %v", err)
						finalizeSession(db, sess, session.OutcomeConnectionReset)
						return
					}

					b := singleByte[0]

					if b == '\r' || b == '\n' {
						if len(inputBuffer) > 0 {
							fmt.Fprintf(channel, "\r\n")
							break
						} else {
							if b == '\r' {
								fmt.Fprintf(channel, "\r\n")
								break
							}
							continue
						}
					} else if b == 0x7F || b == 0x08 {
						if len(inputBuffer) > 0 {
							inputBuffer = inputBuffer[:len(inputBuffer)-1]
							channel.Write([]byte{'\x08', ' ', '\x08'})
							continue
						}
					}
					if len(inputBuffer) >= MaxInput {
						continue
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
				inputBuffer = inputBuffer[:0]

				words := strings.Fields(cli)
				var parsedCommand string
				var parsedArgs []string
				if len(words) > 0 {
					parsedCommand = words[0]
					parsedArgs = words[1:]
				}

				beforeCwd := interp.Cwd
				response, code, baitHits := interp.Run(cli)

				cmd := session.Command{
					EventID:             uuid.New().String(),
					SequenceNumber:      len(sess.Commands),
					TimestampMS:         now,
					InterCommandDelayMS: delay,
					RawInputB64:         raw,
					ParsedCommand:       parsedCommand,
					ParsedArgs:          parsedArgs,
					WorkingDirectory:    beforeCwd,
					ResponseSource:      responseSourceFor(baitHits),
				}
				sess.Commands = append(sess.Commands, cmd)
				appendBaitEvents(sess, cmd.EventID, baitHits)

				if code == shell.ExitRequested {
					fmt.Fprintf(channel, "logout\r\n")
					finalizeSession(db, sess, session.OutcomeCleanDisconnect)
					return
				}

				if response != "" {
					fmt.Fprintf(channel, "%s\r\n", response)
				}
			}
		default:
			req.Reply(false, nil)
		}
	}
	log.Printf("Session ended.")
}

func responseSourceFor(bait []shell.BaitHit) session.ResponseSource {
	if len(bait) > 0 {
		return session.ResponseSourceBaitTriggered
	}
	return session.ResponseSourceHardcoded
}

func appendBaitEvents(sess *session.Session, commandEventID string, hits []shell.BaitHit) {
	now := time.Now().UnixMilli()
	for _, h := range hits {
		sess.BaitEvents = append(sess.BaitEvents, session.BaitEvent{
			EventID:                   uuid.New().String(),
			TimestampMS:               now,
			BaitID:                    h.BaitID,
			BaitType:                  h.BaitType,
			AccessType:                h.AccessType,
			TriggeredByCommandEventID: commandEventID,
		})
	}
}

func finalizeSession(db *sql.DB, sess *session.Session, outcome session.Outcome) {
	endMS := time.Now().UnixMilli()
	duration := endMS - sess.Timing.StartMS
	sess.Timing.EndMS = &endMS
	sess.Timing.DurationMS = &duration
	sess.Outcome = outcome
	if err := store.SaveSession(db, sess); err != nil {
		log.Printf("Error saving session: %v", err)
	}
}
