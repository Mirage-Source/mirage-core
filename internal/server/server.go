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
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mirage-source/mirage-core/internal/deception"
	"github.com/mirage-source/mirage-core/internal/proxyproto"
	"github.com/mirage-source/mirage-core/internal/session"
	"github.com/mirage-source/mirage-core/internal/shell"
	"github.com/mirage-source/mirage-core/internal/store"
	"github.com/mirage-source/mirage-core/internal/validity"
	"golang.org/x/crypto/ssh"
)

const MaxInput = 255
const maxCommandsPerSession = 500

const defaultIdleTimeout = 120 * time.Second
const defaultHandshakeTimeout = 20 * time.Second
const defaultMaxConcurrentConnections = 500

// sessionGuard makes a single *session.Session safe to share across the
// multiple goroutines that can exist per SSH connection -- one per "session"
// channel, since a single connection may open more than one. Without this,
// concurrent channels racing to append to sess.Commands/BaitEvents (or each
// independently calling SaveSession) corrupts the shared slices and causes a
// primary-key collision in the DB, silently dropping whichever channel's
// commands lost the race. See SESSION_NOTES.md for how this was found.
type sessionGuard struct {
	mu   sync.Mutex
	sess *session.Session
	once sync.Once
}

// sessionID is safe to read without the mutex -- it is set once in Start()
// before any channel goroutine exists and never mutated afterward, unlike
// Commands/BaitEvents below.
func (g *sessionGuard) sessionID() string {
	return g.sess.SessionID
}

// appendCommand assigns SequenceNumber (and, if computeDelay, InterCommandDelayMS
// relative to the previous command across ALL channels on this connection)
// and appends atomically, so two channels can never be assigned the same
// sequence number.
func (g *sessionGuard) appendCommand(cmd session.Command, computeDelay bool) session.Command {
	g.mu.Lock()
	defer g.mu.Unlock()

	cmd.SequenceNumber = len(g.sess.Commands)
	if computeDelay && len(g.sess.Commands) > 0 {
		prev := cmd.TimestampMS - g.sess.Commands[len(g.sess.Commands)-1].TimestampMS
		cmd.InterCommandDelayMS = &prev
	}
	g.sess.Commands = append(g.sess.Commands, cmd)
	return cmd
}

func (g *sessionGuard) appendBaitEvents(commandEventID string, hits []shell.BaitHit) {
	if len(hits) == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now().UnixMilli()
	for _, h := range hits {
		g.sess.BaitEvents = append(g.sess.BaitEvents, session.BaitEvent{
			EventID:                   uuid.New().String(),
			TimestampMS:               now,
			BaitID:                    h.BaitID,
			BaitType:                  h.BaitType,
			AccessType:                h.AccessType,
			TriggeredByCommandEventID: commandEventID,
		})
	}
}

func (g *sessionGuard) commandCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.sess.Commands)
}

// recordOutcome sets the terminal outcome/timing once, on a first-wins basis:
// whichever channel on this connection finishes first determines the
// session's recorded outcome. Later channels calling this are no-ops.
func (g *sessionGuard) recordOutcome(outcome session.Outcome) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.sess.Outcome != session.OutcomeActive {
		return
	}
	endMS := time.Now().UnixMilli()
	duration := endMS - g.sess.Timing.StartMS
	g.sess.Timing.EndMS = &endMS
	g.sess.Timing.DurationMS = &duration
	g.sess.Outcome = outcome
}

// finalize persists the session exactly once, no matter how many channels
// or goroutines call it -- callers should call this only after every
// channel on the connection has finished (see handleChannels).
func (g *sessionGuard) finalize(db *sql.DB) {
	g.once.Do(func() {
		g.recordOutcome(session.OutcomeConnectionReset) // fallback if no channel ever recorded one
		if err := store.SaveSession(db, g.sess); err != nil {
			log.Printf("Error saving session: %v", err)
		}
	})
}

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
	maxConnections := envInt("MAX_CONCURRENT_CONNECTIONS", defaultMaxConcurrentConnections)
	log.Printf("Max concurrent connections: %d", maxConnections)

	// Off by default, and deliberately so: turning this on tells Mirage to
	// believe a PROXY protocol v1 header prepended to the raw TCP stream
	// over conn.RemoteAddr() for that connection. That's correct and
	// necessary when every connection reaching this listener is guaranteed
	// to come through a trusted relay/load balancer that prepends one -- but
	// on a listener directly reachable from the open internet it would let
	// literally anyone claim any source IP they want, silently poisoning
	// every downstream log/classification/re-identification signal. Never
	// enable this unless something in front of Mirage is the only thing
	// that can reach this port.
	trustProxyProtocol := envBool("TRUST_PROXY_PROTOCOL", false)
	if trustProxyProtocol {
		log.Printf("Trusting PROXY protocol v1 headers on incoming connections (TRUST_PROXY_PROTOCOL=true)")
	}

	deceptionRuntime := deception.NewRuntime(deception.ConfigFromEnv())
	log.Printf(
		"Deception policy: %v (apply_actions=%v); LLM shell completion: %v",
		deceptionRuntime.PolicyEnabled.Load(), deceptionRuntime.ApplyActions.Load(), deceptionRuntime.CompletionEnabled,
	)

	// Bounds the number of in-flight connections (and therefore goroutines
	// and per-connection memory) a flood can force us to hold onto. Without
	// this, an unbounded connection flood combined with the container's
	// memory limit (docker-compose.yml) can OOM-kill the whole process
	// instead of just refusing the excess connections, like a real
	// overloaded sshd would.
	connSlots := make(chan struct{}, maxConnections)

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

	// Deliberately independent of session traffic and NOT keyed by
	// sess.NodeID below (that field is hardcoded "Ubuntu", the emulated-OS
	// string shown to attackers, not a deployment identity) -- this is the
	// out-of-band liveness signal the downtime-vs-silence validity check
	// needs, since "sensor down" and "sensor up, nobody connected" are
	// otherwise indistinguishable from session data alone.
	sensorID := os.Getenv("SENSOR_ID")
	if sensorID == "" {
		sensorID = "default"
	}
	heartbeatInterval := envDuration("SENSOR_HEARTBEAT_INTERVAL_SECONDS", 60*time.Second)
	stopHeartbeat := validity.StartHeartbeat(db, sensorID, heartbeatInterval, log.Printf)
	defer stopHeartbeat()

	stopFlagPoll := watchRuntimeFlags(db, deceptionRuntime, envDuration("MIRAGE_RUNTIME_FLAGS_POLL_SECONDS", 3*time.Second))
	defer stopFlagPoll()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		select {
		case connSlots <- struct{}{}:
		default:
			log.Printf("At max concurrent connections (%d); dropping connection from %v", maxConnections, conn.RemoteAddr())
			conn.Close()
			continue
		}

		// Wrapping here, before the per-connection goroutine, is what lets
		// handleConnection recover it later with a plain type assertion
		// (conn.(*proxyproto.Conn)) instead of threading an extra parameter
		// through every call in between. Wrap itself does no I/O -- header
		// detection happens lazily on first Read, so this can never block
		// the accept loop.
		var handlerConn net.Conn = conn
		var pp *proxyproto.Conn
		if trustProxyProtocol {
			pp = proxyproto.Wrap(conn)
			handlerConn = pp
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

				// Captured here, not just after a successful handshake in
				// handleConnection: ConnMetadata already has the client's
				// version banner and remote address at auth time, and a
				// rejected handshake never reaches handleConnection's
				// post-handshake assignment, which used to leave every
				// auth_failed session with a blank client_ip/banner.
				sess.Network.SSHClientBanner = string(conn.ClientVersion())
				if tcpAddr, ingressSource, proxyNodeID := resolveRemoteAddr(pp, conn.RemoteAddr()); tcpAddr != nil {
					sess.Network.ClientIP = tcpAddr.IP.String()
					sess.Network.ClientPort = tcpAddr.Port
					sess.Network.IngressSource = ingressSource
					sess.Network.ProxyNodeID = proxyNodeID
				}

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
		guard := &sessionGuard{sess: &sess}
		go func() {
			defer func() { <-connSlots }()
			// A panic anywhere in attacker-reachable code (shell interpreter,
			// deception client, session bookkeeping) must never take down
			// every other connection -- recover scopes it to this one.
			defer func() {
				if r := recover(); r != nil {
					log.Printf("recovered panic in handleConnection for %v: %v", handlerConn.RemoteAddr(), r)
				}
			}()
			handleConnection(handlerConn, config, guard, db, idleTimeout, handshakeTimeout, deceptionRuntime)
		}() //this will handle the connection concurrently, bounded by connSlots
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

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

// watchRuntimeFlags keeps rt.PolicyEnabled/ApplyActions in sync with the
// runtime_flags table, so an operator's toggle in the console's Control tab
// (mirage-web docs/API-GAPS.md §4) reaches an already-running process
// without a restart. Polling rather than LISTEN/NOTIFY: the documented
// contract for this feature is "applies on the next connection, no restart",
// not sub-second push, and a plain poll needs no extra long-lived DB
// connection or reconnect handling on top of the pool store.Connect already
// gives every other caller in this process.
//
// Fails silent on a query error (logged, not fatal): a DB hiccup should
// leave the policy at its last-known value, exactly like every other
// deception.Client call already fails safe to ActionMinimal on error.
func watchRuntimeFlags(db *sql.DB, rt *deception.Runtime, interval time.Duration) (stop func()) {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				flags, err := store.LoadRuntimeFlags(db)
				if err != nil {
					log.Printf("polling runtime flags: %v", err)
					continue
				}
				if prev := rt.PolicyEnabled.Swap(flags.DeceptionEnabled); prev != flags.DeceptionEnabled {
					log.Printf("Deception policy: %v -> %v (console)", prev, flags.DeceptionEnabled)
				}
				if prev := rt.ApplyActions.Swap(flags.DeceptionApplyActions); prev != flags.DeceptionApplyActions {
					log.Printf("Deception apply_actions: %v -> %v (console)", prev, flags.DeceptionApplyActions)
				}
			case <-done:
				return
			}
		}
	}()
	return func() { close(done) }
}

func resolveRemoteAddr(pp *proxyproto.Conn, fallback net.Addr) (addr *net.TCPAddr, ingressSource, proxyNodeID string) {
	if pp != nil {
		if tcpAddr, dstRaw, found := pp.RealRemoteAddr(); found {
			return tcpAddr, session.IngressSourceProxied, dstRaw
		}
	}
	if tcpAddr, ok := fallback.(*net.TCPAddr); ok {
		return tcpAddr, session.IngressSourceDirect, ""
	}
	return nil, session.IngressSourceDirect, ""
}

func handleConnection(conn net.Conn, config *ssh.ServerConfig, guard *sessionGuard, db *sql.DB, idleTimeout, handshakeTimeout time.Duration, deceptionRuntime *deception.Runtime) {
	defer conn.Close()

	log.Printf("New connection from %v", conn.RemoteAddr())

	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("Failed to handshake: %v", err)
		// A rejected/abandoned handshake never opens a channel, so nothing
		// would otherwise persist the credentials that were tried here.
		if len(guard.sess.AuthAttempts) > 0 {
			guard.recordOutcome(session.OutcomeAuthFailed)
			guard.finalize(db)
		}
		return
	}
	// Handshake succeeded; from here on a silent connection is bounded by
	// the idle timeout instead of hanging forever.
	conn.SetDeadline(time.Now().Add(idleTimeout))

	remoteAddr := conn.RemoteAddr()

	pp, _ := conn.(*proxyproto.Conn)

	guard.sess.Network.SSHClientBanner = string(sshConn.ClientVersion())

	if tcpAddr, ingressSource, proxyNodeID := resolveRemoteAddr(pp, remoteAddr); tcpAddr != nil {
		guard.sess.Network.ClientIP = tcpAddr.IP.String()
		guard.sess.Network.ClientPort = tcpAddr.Port
		guard.sess.Network.IngressSource = ingressSource
		guard.sess.Network.ProxyNodeID = proxyNodeID
	}

	if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		guard.sess.Network.ServerPort = tcpAddr.Port
	}
	log.Printf("Client Version: %s", sshConn.ClientVersion())
	go ssh.DiscardRequests(reqs)
	handleChannels(conn, idleTimeout, chans, guard, db, deceptionRuntime)
}

// handleChannels accepts every "session" channel on this connection and
// waits for all of them to finish before finalizing -- a connection may open
// more than one, and the session must only be persisted once, after every
// channel has stopped mutating it.
func handleChannels(conn net.Conn, idleTimeout time.Duration, chans <-chan ssh.NewChannel, guard *sessionGuard, db *sql.DB, deceptionRuntime *deception.Runtime) {
	var wg sync.WaitGroup
	for newChannel := range chans {
		log.Printf("New channel type: %s", newChannel.ChannelType())
		switch newChannel.ChannelType() {
		case "session":
			channel, requests, err := newChannel.Accept()
			if err != nil {
				log.Printf("Could not accept channel: %v", err)
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() {
					if r := recover(); r != nil {
						log.Printf("recovered panic in handleSessionRequests for %v: %v", conn.RemoteAddr(), r)
					}
				}()
				handleSessionRequests(conn, idleTimeout, channel, requests, guard, deceptionRuntime)
			}()
		default:
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
	wg.Wait()
	guard.finalize(db)
}

// applyDeception asks the deception policy (if enabled) how to respond to
// one command, runs the interpreter exactly once, and -- only when the
// policy is also allowed to change shell output (deceptionRuntime.ApplyActions)
// -- lets that decision alter the response and its timing.
//
// usedLLM reports that the response came from the completion fallback rather
// than from the interpreter, so the caller can record the right
// session.ResponseSource against the command.
func applyDeception(deceptionRuntime *deception.Runtime, interp *shell.Interpreter, sessionID, command string) (response string, code int, baitHits []shell.BaitHit, deceptionAction *string, usedLLM bool) {
	if deceptionRuntime == nil {
		response, code, baitHits = interp.Run(command)
		return response, code, baitHits, nil, false
	}

	// Tried before the interpreter runs, and only for a command the
	// interpreter has no builtin for (see deception.ShouldAttemptCompletion,
	// which also refuses compound lines and anything egress-flavoured). On
	// success the interpreter is skipped entirely for this command: we
	// already know the only thing it would produce is "command not found".
	//
	// This path deliberately ignores the RL policy: a completion is not one
	// of its actions, and gating it behind ApplyActions would tie the
	// engagement fix to a policy that ships shadow-mode-first.
	if deceptionRuntime.CompletionEnabled {
		if _, eligible := deception.ShouldAttemptCompletion(command); eligible {
			if out, exitCode, ok := deceptionRuntime.Client.Complete(sessionID, command); ok {
				return out, exitCode, nil, nil, true
			}
		}
	}

	if !deceptionRuntime.PolicyEnabled.Load() {
		response, code, baitHits = interp.Run(command)
		return response, code, baitHits, nil, false
	}

	baitHint := shell.LooksLikeBaitAccess(command)
	decision, err := deceptionRuntime.Client.Decide(sessionID, command, baitHint)
	if err != nil {
		log.Printf("Deception decide failed, falling back to %s: %v", decision.Action, err)
	}
	action := decision.Action

	// Read once: this can be toggled concurrently by watchRuntimeFlags, and
	// the exec/apply decision below must agree with itself for one command.
	applyActions := deceptionRuntime.ApplyActions.Load()

	execAction := ""
	if applyActions {
		execAction = action
	}
	response, code, baitHits = interp.RunWithDeception(command, execAction)

	if applyActions {
		var delay time.Duration
		response, code, delay = deception.Apply(action, response, code)
		if delay > 0 {
			time.Sleep(delay)
		}
	}

	return response, code, baitHits, &action, false
}

func handleSessionRequests(conn net.Conn, idleTimeout time.Duration, channel ssh.Channel, requests <-chan *ssh.Request, guard *sessionGuard, deceptionRuntime *deception.Runtime) {
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
			response, code, baitHits, deceptionAction, usedLLM := applyDeception(deceptionRuntime, interp, guard.sessionID(), payload.Command)
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

			status := code
			if status == shell.ExitRequested {
				status = 0
			}

			cmd := session.Command{
				EventID:          uuid.New().String(),
				TimestampMS:      now,
				RawInputB64:      raw,
				ParsedCommand:    parsedCommand,
				ParsedArgs:       parsedArgs,
				WorkingDirectory: beforeCwd,
				Response:         &response,
				ExitCode:         &status,
				ResponseSource:   responseSourceFor(baitHits, usedLLM),
				DeceptionAction:  deceptionAction,
			}
			cmd = guard.appendCommand(cmd, false)
			guard.appendBaitEvents(cmd.EventID, baitHits)

			// Send exit status to notify client of success/failure
			channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: uint32(status)}))

			log.Printf("Exec channel done; session will be saved once the connection ends.")
			guard.recordOutcome(session.OutcomeCleanDisconnect)
			return
		case "shell":
			req.Reply(true, nil)
			fmt.Fprintf(channel, "Welcome to Ubuntu 22.04.3 LTS\r\n")

			interp := shell.NewInterpreter()

			for {
				if guard.commandCount() >= maxCommandsPerSession {
					guard.recordOutcome(session.OutcomeCommandLimitReached)
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
							guard.recordOutcome(session.OutcomeCleanDisconnect)
							return
						}
						if ne, ok := err.(net.Error); ok && ne.Timeout() {
							log.Printf("Connection idle timeout.")
							guard.recordOutcome(session.OutcomeTimeout)
							return
						}
						log.Printf("Read error on channel: %v", err)
						guard.recordOutcome(session.OutcomeConnectionReset)
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
				response, code, baitHits, deceptionAction, usedLLM := applyDeception(deceptionRuntime, interp, guard.sessionID(), cli)

				status := code
				if status == shell.ExitRequested {
					status = 0
				}

				cmd := session.Command{
					EventID:          uuid.New().String(),
					TimestampMS:      now,
					RawInputB64:      raw,
					ParsedCommand:    parsedCommand,
					ParsedArgs:       parsedArgs,
					WorkingDirectory: beforeCwd,
					Response:         &response,
					ExitCode:         &status,
					ResponseSource:   responseSourceFor(baitHits, usedLLM),
					DeceptionAction:  deceptionAction,
				}
				cmd = guard.appendCommand(cmd, true)
				guard.appendBaitEvents(cmd.EventID, baitHits)

				if code == shell.ExitRequested {
					fmt.Fprintf(channel, "logout\r\n")
					guard.recordOutcome(session.OutcomeCleanDisconnect)
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

// responseSourceFor records where a command's response actually came from.
// Bait wins over llm: a bait trigger is the more consequential fact about
// the command, and the two can't co-occur anyway (the completion fallback
// only ever fires for commands with no builtin, which cannot touch the
// planted files).
func responseSourceFor(bait []shell.BaitHit, usedLLM bool) session.ResponseSource {
	if len(bait) > 0 {
		return session.ResponseSourceBaitTriggered
	}
	if usedLLM {
		return session.ResponseSourceLLM
	}
	return session.ResponseSourceHardcoded
}
