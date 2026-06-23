package api

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
