package session

import "encoding/json"

type Protocol string

const (
	ProtocolSSH Protocol = "ssh"
	ProtocolTelnet Protocol = "telnet"
	OutcomeCommandLimitReached Outcome = "command_limit_reached"
)

type Outcome string

const (
	OutcomeCleanDisconnect Outcome = "clean_disconnect"
	OutcomeTimeout         Outcome = "timeout"
	OutcomeConnectionReset Outcome = "connection_reset"
	OutcomeActive          Outcome = "active"
	OutcomeAuthFailed      Outcome = "auth_failed"

	// A telnet client that spoke another protocol (HTTP, SIP, TLS, ...).
	OutcomeProtocolMismatch Outcome = "protocol_mismatch"
)

type AuthMethod string

const (
	AuthMethodPassword  AuthMethod = "password"
	AuthMethodPublicKey AuthMethod = "publickey"
)

type ResponseSource string

const (
	ResponseSourceHardcoded     ResponseSource = "hardcoded"
	ResponseSourceLLM           ResponseSource = "llm"
	ResponseSourceBaitTriggered ResponseSource = "bait_triggered"
	ResponseSourceNoResponse    ResponseSource = "no_response"
)

type BaitType string

const (
	BaitTypeCredential BaitType = "credential"
	BaitTypePrivateKey BaitType = "private_key"
	BaitTypeConfig     BaitType = "config"
	BaitTypeEnvFile    BaitType = "env_file"
	BaitTypeShadow     BaitType = "shadow"
)

type AccessType string

const (
	AccessTypeRead         AccessType = "read"
	AccessTypeCopy         AccessType = "copy"
	AccessTypeExfilAttempt AccessType = "exfil_attempt"
)

type Session struct {
	SessionID     string          `json:"session_id"`
	SchemaVersion string          `json:"schema_version"`
	NodeID        string          `json:"node_id"`
	Protocol      Protocol        `json:"protocol"`
	Network       Network         `json:"network"`
	Timing        Timing          `json:"timing"`
	Outcome       Outcome         `json:"outcome"`
	AuthAttempts  []AuthAttempt   `json:"auth_attempts"`
	Commands      []Command       `json:"commands"`
	BaitEvents    []BaitEvent     `json:"bait_interactions"`
	Intelligence  Intelligence    `json:"intelligence"`

	Telnet *TelnetMeta `json:"telnet,omitempty"`

	// RejectedRequests is omitted when empty so documents of sessions that
	// never asked for one stay byte-identical to before it existed.
	RejectedRequests []RejectedRequest `json:"rejected_requests,omitempty"`
}

type RejectedKind string

const (
	// RejectedKindChannel is a channel open other than "session", e.g.
	// direct-tcpip (using the sensor as a proxy) or x11.
	RejectedKindChannel RejectedKind = "channel"
	// RejectedKindSubsystem is a subsystem request on a session channel,
	// e.g. sftp.
	RejectedKindSubsystem RejectedKind = "subsystem"
)

// RejectedRequest is something an SSH client asked for that the sensor
// refused. Type and Detail are client-supplied and stored truncated.
type RejectedRequest struct {
	TimestampMS int64        `json:"timestamp_ms"`
	Kind        RejectedKind `json:"kind"`
	Type        string       `json:"type"`
	// Detail is "host:port" for direct-tcpip, empty otherwise.
	Detail string `json:"detail,omitempty"`
}

type TelnetMeta struct {
	Negotiated    bool   `json:"negotiated"`
	ClientOptions []int  `json:"client_options"`
	TerminalType  string `json:"terminal_type"`
	WindowWidth   int    `json:"window_width"`
	WindowHeight  int    `json:"window_height"`

	// Set when the client spoke another protocol; see OutcomeProtocolMismatch.
	ForeignProtocolLine string `json:"foreign_protocol_line,omitempty"`
}

type Network struct {
	ClientIP       string `json:"client_ip"`
	ClientPort     int    `json:"client_port"`
	ServerPort     int    `json:"server_port"`
	SSHClientBanner string `json:"ssh_client_banner"`

	// IngressSource is "direct" unless TRUST_PROXY_PROTOCOL is enabled and a
	// PROXY protocol v1 header was actually parsed off this connection, in
	// which case it's "proxied" and ClientIP/ClientPort above are the
	// header's claimed original client, not the TCP peer that connected to
	// us. See internal/proxyproto and TRUST_PROXY_PROTOCOL in server.go.
	IngressSource string `json:"ingress_source"`
	// ProxyNodeID is the PROXY header's dst-ip field verbatim (kept opaque
	// -- it isn't necessarily a real IP, see proxyproto.Conn.RealRemoteAddr),
	// identifying which relay/sensor node this session came through. Empty
	// when IngressSource is "direct".
	ProxyNodeID string `json:"proxy_node_id"`
	// TargetPort is the PROXY header's dst-port: the port the client
	// connected to on the relay. ServerPort is this listener's own port,
	// which behind a tunnel says nothing about what was targeted. Zero
	// (omitted, NULL in the store) when IngressSource is "direct".
	TargetPort int `json:"target_port,omitempty"`
}

const (
	IngressSourceDirect  = "direct"
	IngressSourceProxied = "proxied"
)

type Timing struct {
	StartMS   int64  `json:"start_ms"`
	EndMS     *int64 `json:"end_ms"`
	DurationMS *int64 `json:"duration_ms"`
}

type AuthAttempt struct {
	TimestampMS int64      `json:"timestamp_ms"`
	Method      AuthMethod `json:"method"`
	Username    string     `json:"username"`
	Credential  string     `json:"credential"`
	Success     bool       `json:"success"`
}

type Command struct {
	EventID              string   `json:"event_id"`
	SequenceNumber       int      `json:"sequence_number"`
	TimestampMS          int64    `json:"timestamp_ms"`
	InterCommandDelayMS  *int64   `json:"inter_command_delay_ms"`
	RawInputB64          string   `json:"raw_input_b64"`
	ParsedCommand        string   `json:"parsed_command"`
	ParsedArgs           []string `json:"parsed_args"`
	CommandChain         []string `json:"command_chain"`
	WorkingDirectory     string   `json:"working_directory"`
	Response             *string  `json:"response"`
	ExitCode             *int     `json:"exit_code"`
	ResponseSource       ResponseSource `json:"response_source"`
	DeceptionAction      *string  `json:"deception_action"`
}

type BaitEvent struct {
	EventID                   string     `json:"event_id"`
	TimestampMS               int64      `json:"timestamp_ms"`
	BaitID                    string     `json:"bait_id"`
	BaitType                  BaitType   `json:"bait_type"`
	AccessType                AccessType `json:"access_type"`
	TriggeredByCommandEventID string     `json:"triggered_by_command_event_id"`
}

type Intelligence struct {
	AttackerClass        *string          `json:"attacker_class"`
	ClassifierConfidence *float64         `json:"classifier_confidence"`
	ClusterID            *string          `json:"cluster_id"`
	MitreTechniques      []string         `json:"mitre_techniques"`
	SessionSummary       *string          `json:"session_summary"`
	StixBundle           *json.RawMessage `json:"stix_bundle"`
	Severity             *string          `json:"severity"`
	RecommendedActions   []string         `json:"recommended_actions"`
}


