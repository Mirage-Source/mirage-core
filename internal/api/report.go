package api

import "encoding/json"

type SessionReport struct {
	SessionID   string `json:"session_id"`
	GeneratedAt string `json:"generated_at"`

	// Attacker profile
	Profile AttackerProfile `json:"profile"`

	// Network context
	Network ReportNetwork `json:"network"`

	// Timeline
	Timeline ReportTimeline `json:"timeline"`

	// Threat intelligence
	ThreatIntel ReportThreatIntel `json:"threat_intel"`

	// Raw STIX bundle (omitted if nil)
	StixBundle *json.RawMessage `json:"stix_bundle,omitempty"`
}

type AttackerProfile struct {
	Class      *string  `json:"class"`
	Confidence *float64 `json:"confidence"`
	ClusterID  *string  `json:"cluster_id"`
	Severity   string   `json:"severity"`
}

type ReportNetwork struct {
	ClientIP  string `json:"client_ip"`
	SSHBanner string `json:"ssh_banner"`
	Outcome   string `json:"outcome"`
}

type ReportTimeline struct {
	StartMS      int64  `json:"start_ms"`
	DurationMS   *int64 `json:"duration_ms"`
	AuthAttempts int    `json:"auth_attempts"`
	Commands     int    `json:"commands"`
	BaitHits     int    `json:"bait_hits"`
}

type ReportThreatIntel struct {
	MitreTechniques []string `json:"mitre_techniques"`
	Summary         *string  `json:"summary"`
}
