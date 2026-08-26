package validity

import (
	"database/sql"
	"fmt"
	"time"
)

// FieldSpec identifies one {table, column} pair the cardinality check is
// allowed to query. Only the values below are ever accepted -- FetchField
// Counts rejects anything else -- so a FieldSpec can never become a SQL
// injection surface even though its Table/Column end up interpolated into
// a query string (Postgres doesn't support parameterized identifiers).
type FieldSpec struct {
	Table  string
	Column string
}

// Fields worth watching for a silent cardinality collapse -- chosen as the
// columns closest to the preprint's `success`/`outcome` incident (a field
// that should vary but silently didn't) plus the other columns most likely
// to reveal the same failure shape elsewhere in the schema.
var (
	FieldSessionsOutcome         = FieldSpec{Table: "sessions", Column: "outcome"}
	FieldAuthAttemptsSuccess     = FieldSpec{Table: "auth_attempts", Column: "success"}
	FieldSessionsSSHBanner       = FieldSpec{Table: "sessions", Column: "ssh_client_banner"}
	FieldSessionsAttackerClass   = FieldSpec{Table: "sessions", Column: "attacker_class"}
	FieldCommandsDeceptionAction = FieldSpec{Table: "commands", Column: "deception_action"}
	FieldSessionsIngressSource   = FieldSpec{Table: "sessions", Column: "ingress_source"}
)

// WatchedFields is every FieldSpec the dashboard's cardinality check
// covers by default.
var WatchedFields = []FieldSpec{
	FieldSessionsOutcome,
	FieldAuthAttemptsSuccess,
	FieldSessionsSSHBanner,
	FieldSessionsAttackerClass,
	FieldCommandsDeceptionAction,
	FieldSessionsIngressSource,
}

func (f FieldSpec) allowed() bool {
	for _, w := range WatchedFields {
		if f == w {
			return true
		}
	}
	return false
}

// timestampColumn is the epoch-ms column each watched table's rows are
// windowed on for FetchFieldCounts.
func (f FieldSpec) timestampColumn() string {
	switch f.Table {
	case "auth_attempts", "commands":
		return "timestamp_ms"
	default:
		return "start_ms"
	}
}

// FetchFieldCounts returns raw {value: count} for spec's column, restricted
// to rows whose timestamp falls in [windowStart, windowEnd). NULL values
// are reported under the literal string "(null)" so a field that's silently
// stopped being populated shows up as a cardinality collapse too, not as an
// invisible gap.
func FetchFieldCounts(db *sql.DB, spec FieldSpec, windowStart, windowEnd time.Time) (map[string]int, error) {
	if !spec.allowed() {
		return nil, fmt.Errorf("validity: field %s.%s is not in the watched-fields allowlist", spec.Table, spec.Column)
	}

	query := fmt.Sprintf(
		`SELECT COALESCE(%[1]s::text, '(null)') AS value, COUNT(*)
		 FROM %[2]s
		 WHERE %[3]s >= $1 AND %[3]s < $2
		 GROUP BY value`,
		spec.Column, spec.Table, spec.timestampColumn(),
	)
	rows, err := db.Query(query, windowStart.UnixMilli(), windowEnd.UnixMilli())
	if err != nil {
		return nil, fmt.Errorf("validity: querying %s.%s counts: %w", spec.Table, spec.Column, err)
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var value string
		var n int
		if err := rows.Scan(&value, &n); err != nil {
			return nil, fmt.Errorf("validity: scanning %s.%s counts: %w", spec.Table, spec.Column, err)
		}
		counts[value] = n
	}
	return counts, rows.Err()
}

// FetchDailyAuthSuccessRate buckets auth_attempts by UTC calendar day over
// the trailing `days` days (through "today", inclusive) and returns one
// DailyRate per day with at least one attempt -- days with zero attempts
// are omitted rather than reported as rate 0, since DetectBandDrift should
// judge "no traffic" via the session-arrival/heartbeat checks, not as an
// auth-rate data point.
func FetchDailyAuthSuccessRate(db *sql.DB, days int) ([]DailyRate, error) {
	rows, err := db.Query(`
		SELECT
			date_trunc('day', to_timestamp(timestamp_ms / 1000.0)) AS day,
			COUNT(*) AS n,
			COUNT(*) FILTER (WHERE success) AS n_success
		FROM auth_attempts
		WHERE timestamp_ms >= $1
		GROUP BY day
		ORDER BY day ASC`,
		time.Now().AddDate(0, 0, -days).UnixMilli(),
	)
	if err != nil {
		return nil, fmt.Errorf("validity: querying daily auth success rate: %w", err)
	}
	defer rows.Close()

	var series []DailyRate
	for rows.Next() {
		var d time.Time
		var n, nSuccess int
		if err := rows.Scan(&d, &n, &nSuccess); err != nil {
			return nil, fmt.Errorf("validity: scanning daily auth success rate: %w", err)
		}
		rate := 0.0
		if n > 0 {
			rate = float64(nSuccess) / float64(n)
		}
		series = append(series, DailyRate{Date: d, N: n, Rate: rate})
	}
	return series, rows.Err()
}

// FetchCampaignInputs returns {ip: session_count} and {ip: credential-pair
// set} for every source address, mirroring
// ml/mirage/reid/real_db.py's fetch_session_counts/fetch_credential_pair_sets
// -- including that file's exclusion of the empty-client_ip rows (TCP
// connections that never completed a handshake, not a real source address).
func FetchCampaignInputs(db *sql.DB) (sessionCounts map[string]int, credentialPairSets map[string]map[CredentialPair]struct{}, err error) {
	sessionCounts = map[string]int{}
	rows, err := db.Query(`SELECT client_ip, COUNT(*) FROM sessions WHERE client_ip <> '' GROUP BY client_ip`)
	if err != nil {
		return nil, nil, fmt.Errorf("validity: querying session counts: %w", err)
	}
	for rows.Next() {
		var ip string
		var n int
		if err := rows.Scan(&ip, &n); err != nil {
			rows.Close()
			return nil, nil, fmt.Errorf("validity: scanning session counts: %w", err)
		}
		sessionCounts[ip] = n
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, err
	}
	rows.Close()

	credentialPairSets = map[string]map[CredentialPair]struct{}{}
	pairRows, err := db.Query(`
		SELECT s.client_ip, a.username, a.credential
		FROM auth_attempts a
		JOIN sessions s ON s.session_id = a.session_id
		WHERE s.client_ip <> ''`)
	if err != nil {
		return nil, nil, fmt.Errorf("validity: querying credential pairs: %w", err)
	}
	defer pairRows.Close()
	for pairRows.Next() {
		var ip, username, credential string
		if err := pairRows.Scan(&ip, &username, &credential); err != nil {
			return nil, nil, fmt.Errorf("validity: scanning credential pairs: %w", err)
		}
		set, ok := credentialPairSets[ip]
		if !ok {
			set = map[CredentialPair]struct{}{}
			credentialPairSets[ip] = set
		}
		set[CredentialPair{Username: username, Credential: credential}] = struct{}{}
	}
	return sessionCounts, credentialPairSets, pairRows.Err()
}

// FetchHeartbeats returns every sensor_heartbeats.ts for sensorID at or
// after `since`.
func FetchHeartbeats(db *sql.DB, sensorID string, since time.Time) ([]time.Time, error) {
	rows, err := db.Query(
		`SELECT ts FROM sensor_heartbeats WHERE sensor_id = $1 AND ts >= $2 ORDER BY ts ASC`,
		sensorID, since,
	)
	if err != nil {
		return nil, fmt.Errorf("validity: querying heartbeats: %w", err)
	}
	defer rows.Close()

	var out []time.Time
	for rows.Next() {
		var ts time.Time
		if err := rows.Scan(&ts); err != nil {
			return nil, fmt.Errorf("validity: scanning heartbeats: %w", err)
		}
		out = append(out, ts)
	}
	return out, rows.Err()
}
