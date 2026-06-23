package api

import "github.com/mirage-source/mirage-core/internal/session"

type SessionSummary struct {
	SessionID    string `json:"session_id"`
	ClientIP     string `json:"client_ip"`
	Outcome      string `json:"outcome"`
	CommandCount int    `json:"command_count"`
	StartMS      int64  `json:"start_ms"`
	DurationMS   *int64 `json:"duration_ms"`
	SSHBanner    string `json:"ssh_banner"`
}

type SessionsResponse struct {
	Total    int64            `json:"total"`
	Limit    int              `json:"limit"`
	Offset   int              `json:"offset"`
	Sessions []SessionSummary `json:"sessions"`
}

type SessionDetail struct {
	SessionID string `json:"session_id"`

	SchemaVersion string `json:"schema_version"`
	NodeID        string `json:"node_id"`
	Protocol      string `json:"protocol"`

	ClientIP        string `json:"client_ip"`
	ClientPort      int    `json:"client_port"`
	ServerPort      int    `json:"server_port"`
	SSHClientBanner string `json:"ssh_client_banner"`

	StartMS    int64  `json:"start_ms"`
	EndMS      *int64 `json:"end_ms"`
	DurationMS *int64 `json:"duration_ms"`

	Outcome string `json:"outcome"`

	CommandCount int `json:"command_count"`
	BaitHitCount int `json:"bait_hit_count"`

	AuthAttempts []session.AuthAttempt `json:"auth_attempts"`
	Commands     []session.Command     `json:"commands"`
	BaitEvents   []session.BaitEvent   `json:"bait_events"`

	Intelligence session.Intelligence `json:"intelligence"`
}
