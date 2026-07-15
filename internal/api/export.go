package api

type ExportSession struct {
	SessionID             string   `json:"session_id"`
	NodeID                string   `json:"node_id"`
	ClientIP              string   `json:"client_ip"`
	SSHClientBanner       string   `json:"ssh_client_banner"`
	StartMS               int64    `json:"start_ms"`
	EndMS                 *int64   `json:"end_ms"`
	DurationMS            *int64   `json:"duration_ms"`
	Outcome               string   `json:"outcome"`
	CommandCount          int      `json:"command_count"`
	BaitHitCount          int      `json:"bait_hit_count"`
	AttackerClass         *string  `json:"attacker_class"`
	ClassifierConfidence  *float64 `json:"classifier_confidence"`
	ClusterID             *string  `json:"cluster_id"`
	MitreTechniques       []string `json:"mitre_techniques"`
	AuthAttemptCount      int      `json:"auth_attempt_count"`
	UniqueUsernamesTried  int      `json:"unique_usernames_tried"`
	TopUsername           *string  `json:"top_username"`
}

type ExportResponse struct {
	GeneratedAt  string          `json:"generated_at"`
	SessionCount int             `json:"session_count"`
	Sessions     []ExportSession `json:"sessions"`
}

// ExportCommand is one command/response pair, flattened with enough session
// context (ClientIP, SSHClientBanner, AttackerClass, MitreTechniques) to be
// self-contained -- consumers building a training corpus from this
// shouldn't need to join back against /api/export to make sense of a row.
type ExportCommand struct {
	EventID             string   `json:"event_id"`
	SessionID           string   `json:"session_id"`
	SequenceNumber      int      `json:"sequence_number"`
	TimestampMS         int64    `json:"timestamp_ms"`
	InterCommandDelayMS *int64   `json:"inter_command_delay_ms"`
	RawCommand          string   `json:"raw_command"`
	ParsedCommand       string   `json:"parsed_command"`
	ParsedArgs          []string `json:"parsed_args"`
	WorkingDirectory    string   `json:"working_directory"`
	Response            *string  `json:"response"`
	ExitCode            *int     `json:"exit_code"`
	ResponseSource      string   `json:"response_source"`
	DeceptionAction     *string  `json:"deception_action"`
	BaitHit             bool     `json:"bait_hit"`
	BaitType            *string  `json:"bait_type"`
	ClientIP            string   `json:"client_ip"`
	SSHClientBanner     string   `json:"ssh_client_banner"`
	AttackerClass       *string  `json:"attacker_class"`
	MitreTechniques     []string `json:"mitre_techniques"`
}

// ExportCommandsResponse is keyset-paginated: NextCursor is the EventID to
// pass as ?after= to fetch the next page, nil when the caller has reached
// the end. Unlike ExportResponse (returned in one shot), per-command volume
// is high enough (up to 500 commands per session) that an unpaginated dump
// isn't a safe default.
type ExportCommandsResponse struct {
	GeneratedAt  string          `json:"generated_at"`
	CommandCount int             `json:"command_count"`
	NextCursor   *string         `json:"next_cursor"`
	Commands     []ExportCommand `json:"commands"`
}
