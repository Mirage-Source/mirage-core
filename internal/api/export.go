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
