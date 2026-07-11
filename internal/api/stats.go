package api

type HoneypotStats struct {
	TotalSessions      uint64               `json:"total_sessions"`
	UniqueIPs          int                  `json:"unique_ips"`
	SessionsLast24h    int                  `json:"sessions_last_24h"`
	SessionsLast7d     int                  `json:"sessions_last_7d"`
	TopIPs             []IPCounts           `json:"top_ips"`
	TopUsernames       []UsernameCounts     `json:"top_usernames"`
	TopPasswords       []PasswordCounts     `json:"top_passwords"`
	TopCredentials     []CredentialCounts   `json:"top_credentials"`
	SSHBanners         []BannerCounts       `json:"ssh_banners"`
	CoordinatedIPs     []CoordinatedIPGroup `json:"coordinated_ips"`
	HourlyDistribution []HourlyDistribution `json:"hourly_distribution"`
}

type IPCounts struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

type UsernameCounts struct {
	Username string `json:"username"`
	Count    int    `json:"count"`
}

type PasswordCounts struct {
	Password string `json:"password"`
	Count    int    `json:"count"`
}

type CredentialCounts struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Count    int    `json:"count"`
}

type BannerCounts struct {
	Banner string `json:"banner"`
	Count  int    `json:"count"`
}

// CoordinatedIPGroup is a set of distinct IPs that authenticated with the
// same credential and SSH client banner within the same 5-minute window --
// a real signal of a single script/botnet driving multiple source IPs,
// rather than two unrelated IPs that happen to have the same session count.
type CoordinatedIPGroup struct {
	Count       int      `json:"count"`
	IPs         []string `json:"ips"`
	Username    string   `json:"username"`
	Credential  string   `json:"credential"`
	Banner      string   `json:"ssh_client_banner"`
	WindowStart int64    `json:"window_start_ms"`
}

type HourlyDistribution struct {
	Hour  int `json:"hour"`
	Count int `json:"count"`
}
