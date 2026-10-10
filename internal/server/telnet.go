package server

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mirage-source/mirage-core/internal/fleet"
	"github.com/mirage-source/mirage-core/internal/session"
	"github.com/mirage-source/mirage-core/internal/shell"
	"github.com/mirage-source/mirage-core/internal/store"
	"github.com/mirage-source/mirage-core/internal/telnet"
	"github.com/mirage-source/mirage-core/internal/validity"
)

const telnetIssue = "Ubuntu 22.04.3 LTS\r\n"

type telnetConfig struct {
	weakCreds        map[string]struct{}
	loginTimeout     time.Duration
	idleTimeout      time.Duration
	maxLoginAttempts int
	authDelay        func() time.Duration
}

func StartTelnet(addr string) {
	credPath := os.Getenv("TELNET_WEAK_CREDENTIALS_FILE")
	if credPath == "" {
		credPath = "config/telnet_weak_credentials.txt"
	}
	cfg := telnetConfig{
		weakCreds:        loadWeakCredentials(credPath),
		loginTimeout:     envDuration("TELNET_LOGIN_TIMEOUT_SECONDS", 60*time.Second),
		idleTimeout:      envDuration("TELNET_IDLE_TIMEOUT_SECONDS", defaultIdleTimeout),
		maxLoginAttempts: envInt("TELNET_MAX_LOGIN_ATTEMPTS", 5),
		authDelay: func() time.Duration {
			return time.Duration(2000+rand.Intn(1500)) * time.Millisecond
		},
	}
	log.Printf("Telnet: loaded %d weak credential pair(s) from %s", len(cfg.weakCreds), credPath)

	maxConnections := envInt("MAX_CONCURRENT_CONNECTIONS", defaultMaxConcurrentConnections)
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

	sensorID := os.Getenv("SENSOR_ID")
	if sensorID == "" {
		sensorID = "telnet"
	}
	stopHeartbeat := validity.StartHeartbeat(db, sensorID, envDuration("SENSOR_HEARTBEAT_INTERVAL_SECONDS", 60*time.Second), log.Printf)
	defer stopHeartbeat()

	fleetOff := fleet.NewClient("", "", 0, nil)

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

		guard := &sessionGuard{sess: newTelnetSession()}
		go func() {
			defer func() { <-connSlots }()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("recovered panic in handleTelnet for %v: %v", conn.RemoteAddr(), r)
				}
			}()
			handleTelnet(conn, cfg, guard)
			conn.Close()
			if shouldPersistTelnet(guard) {
				guard.finalize(db, fleetOff)
			}
		}()
	}
}

func newTelnetSession() *session.Session {
	return &session.Session{
		SessionID:     uuid.New().String(),
		SchemaVersion: "1.1",
		NodeID:        "Ubuntu",
		Protocol:      session.ProtocolTelnet,
		Outcome:       session.OutcomeActive,
		Network:       session.Network{IngressSource: session.IngressSourceDirect},
		BaitEvents:    []session.BaitEvent{},
		Timing:        session.Timing{StartMS: time.Now().UnixMilli()},
		Telnet:        &session.TelnetMeta{ClientOptions: []int{}},
	}
}

func shouldPersistTelnet(g *sessionGuard) bool {
	return len(g.sess.AuthAttempts) > 0
}

func handleTelnet(conn net.Conn, cfg telnetConfig, guard *sessionGuard) {
	sess := guard.sess
	if a, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		sess.Network.ClientIP = a.IP.String()
		sess.Network.ClientPort = a.Port
	}
	if a, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		sess.Network.ServerPort = a.Port
	}

	ts := &telnetStream{conn: conn, neg: telnet.NewNegotiator()}
	defer func() {
		m := ts.neg.Meta()
		opts := make([]int, len(m.ClientWill))
		for i, o := range m.ClientWill {
			opts[i] = int(o)
		}
		sess.Telnet = &session.TelnetMeta{
			Negotiated:    m.Negotiated,
			ClientOptions: opts,
			TerminalType:  m.TerminalType,
			WindowWidth:   m.WindowWidth,
			WindowHeight:  m.WindowHeight,
		}
	}()

	conn.SetDeadline(time.Now().Add(cfg.loginTimeout))
	ts.writeRaw(ts.neg.Initial())
	ts.write(telnetIssue)

	hostname := shell.NewInterpreter("").Hostname
	username, ok := telnetLogin(ts, cfg, guard, hostname)
	if !ok {
		return
	}

	interp := shell.NewInterpreter(username)
	interp.Hostname = hostname
	interp.Busybox = true
	ts.idle = cfg.idleTimeout
	refreshDeadlines(conn, cfg.idleTimeout)
	ts.write("Welcome to Ubuntu 22.04.3 LTS\r\n")

	for {
		if guard.commandCount() >= maxCommandsPerSession {
			guard.recordOutcome(session.OutcomeCommandLimitReached)
			return
		}
		ts.write(interp.Prompt())
		line, err := ts.readLine(MaxInput, true)
		if err != nil {
			guard.recordOutcome(telnetOutcome(err))
			return
		}

		now := time.Now().UnixMilli()
		cwd := interp.Cwd
		response, code, baitHits, _, _ := applyDeception(nil, interp, guard.sessionID(), line)
		cmd, ok := guard.appendCommand(telnetCommand(line, cwd, response, code, baitHits, now), true)
		if !ok {
			guard.recordOutcome(session.OutcomeCommandLimitReached)
			return
		}
		guard.appendBaitEvents(cmd.EventID, baitHits)

		if code == shell.ExitRequested {
			ts.write("logout\r\n")
			guard.recordOutcome(session.OutcomeCleanDisconnect)
			return
		}
		if response != "" {
			ts.write(response + "\r\n")
		}
	}
}

func telnetLogin(ts *telnetStream, cfg telnetConfig, guard *sessionGuard, hostname string) (string, bool) {
	for attempts := 0; attempts < cfg.maxLoginAttempts; {
		ts.write(hostname + " login: ")
		username, err := ts.readLine(MaxInput, true)
		if err != nil {
			guard.recordOutcome(telnetOutcome(err))
			return "", false
		}
		if username == "" {
			continue
		}
		ts.write("Password: ")
		password, err := ts.readLine(MaxInput, false)
		if err != nil {
			guard.recordOutcome(telnetOutcome(err))
			return "", false
		}
		ts.write("\r\n")
		attempts++

		_, accepted := cfg.weakCreds[username+":"+password]
		guard.sess.AuthAttempts = append(guard.sess.AuthAttempts, session.AuthAttempt{
			TimestampMS: time.Now().UnixMilli(),
			Method:      session.AuthMethodPassword,
			Username:    username,
			Credential:  password,
			Success:     accepted,
		})
		log.Printf("Telnet auth attempt user=%s password=%s accepted=%v", username, password, accepted)
		if accepted {
			return username, true
		}
		time.Sleep(cfg.authDelay())
		ts.write("\r\nLogin incorrect\r\n")
	}
	guard.recordOutcome(session.OutcomeAuthFailed)
	return "", false
}

func telnetCommand(line, cwd, response string, code int, bait []shell.BaitHit, nowMS int64) session.Command {
	parsed, args, chain := parseCommandLine(line)
	if code == shell.ExitRequested {
		code = 0
	}
	return session.Command{
		EventID:          uuid.New().String(),
		TimestampMS:      nowMS,
		RawInputB64:      base64.StdEncoding.EncodeToString([]byte(line)),
		ParsedCommand:    parsed,
		ParsedArgs:       args,
		CommandChain:     chain,
		WorkingDirectory: cwd,
		Response:         &response,
		ExitCode:         &code,
		ResponseSource:   responseSourceFor(bait, false),
	}
}

func telnetOutcome(err error) session.Outcome {
	if errors.Is(err, io.EOF) {
		return session.OutcomeCleanDisconnect
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return session.OutcomeTimeout
	}
	return session.OutcomeConnectionReset
}

type telnetStream struct {
	conn    net.Conn
	neg     *telnet.Negotiator
	idle    time.Duration
	pending []byte
	skipLF  bool
}

func (s *telnetStream) writeRaw(b []byte) {
	s.conn.Write(b)
}

func (s *telnetStream) write(text string) {
	b := []byte(strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", "\r\n"))
	s.conn.Write(bytes.ReplaceAll(b, []byte{telnet.IAC}, []byte{telnet.IAC, telnet.IAC}))
}

func (s *telnetStream) readLine(max int, echo bool) (string, error) {
	var line, echoed []byte
	flush := func() {
		if len(echoed) > 0 {
			s.write(string(echoed))
			echoed = echoed[:0]
		}
	}
	buf := make([]byte, 512)
	for {
		for len(s.pending) > 0 {
			b := s.pending[0]
			s.pending = s.pending[1:]
			if s.skipLF {
				s.skipLF = false
				if b == '\n' {
					continue
				}
			}
			switch {
			case b == '\r' || b == '\n':
				s.skipLF = b == '\r'
				if echo {
					echoed = append(echoed, '\r', '\n')
				}
				flush()
				return string(line), nil
			case b == 0x7F || b == 0x08:
				if len(line) > 0 {
					line = line[:len(line)-1]
					if echo {
						echoed = append(echoed, '\b', ' ', '\b')
					}
				}
			case b == 0:
			default:
				if len(line) >= max {
					continue
				}
				line = append(line, b)
				if echo {
					echoed = append(echoed, b)
				}
			}
		}
		flush()
		if s.idle > 0 {
			refreshDeadlines(s.conn, s.idle)
		}
		n, err := s.conn.Read(buf)
		if n > 0 {
			data, reply := s.neg.Feed(buf[:n])
			if len(reply) > 0 {
				s.writeRaw(reply)
			}
			s.pending = append(s.pending, data...)
		}
		if err != nil {
			return string(line), err
		}
	}
}
