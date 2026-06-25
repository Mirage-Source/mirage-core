package session

import "encoding/json"

type Protocol string

const (
	ProtocolSSH Protocol = "ssh"
	OutcomeCommandLimitReached Outcome = "command_limit_reached"
)

type Outcome string

const (
	OutcomeCleanDisconnect Outcome = "clean_disconnect"
	OutcomeTimeout         Outcome = "timeout"
	OutcomeConnectionReset Outcome = "connection_reset"
	OutcomeActive          Outcome = "active"
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
}

type Network struct {
	ClientIP       string `json:"client_ip"`
	ClientPort     int    `json:"client_port"`
	ServerPort     int    `json:"server_port"`
	SSHClientBanner string `json:"ssh_client_banner"`
}

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
	WorkingDirectory     string   `json:"working_directory"`
	ResponseSource       ResponseSource `json:"response_source"`
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
}


