package store

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"github.com/lib/pq"
	"github.com/mirage-source/mirage-core/internal/api"
	"github.com/mirage-source/mirage-core/internal/session"
)

func GetStats(db *sql.DB) (*api.HoneypotStats, error) {
	stats := &api.HoneypotStats{
		CoordinatedIPs: []api.CoordinatedIPGroup{},
	}

	// Total sessions
	if err := db.QueryRow(`
		SELECT COUNT(*)
		FROM sessions
	`).Scan(&stats.TotalSessions); err != nil {
		return nil, err
	}

	// Unique IPs
	if err := db.QueryRow(`
		SELECT COUNT(DISTINCT client_ip)
		FROM sessions
	`).Scan(&stats.UniqueIPs); err != nil {
		return nil, err
	}

	// Sessions in last 24h
	if err := db.QueryRow(`
		SELECT COUNT(*)
		FROM sessions
		WHERE start_ms >= (
			EXTRACT(EPOCH FROM NOW() - INTERVAL '24 hours') * 1000
		)
	`).Scan(&stats.SessionsLast24h); err != nil {
		return nil, err
	}

	// Sessions in last 7d
	if err := db.QueryRow(`
		SELECT COUNT(*)
		FROM sessions
		WHERE start_ms >= (
			EXTRACT(EPOCH FROM NOW() - INTERVAL '7 days') * 1000
		)
	`).Scan(&stats.SessionsLast7d); err != nil {
		return nil, err
	}

	// Top IPs
	rows, err := db.Query(`
		SELECT
			client_ip,
			COUNT(*) AS count
		FROM sessions
		GROUP BY client_ip
		ORDER BY count DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var item api.IPCounts

		if err := rows.Scan(&item.IP, &item.Count); err != nil {
			rows.Close()
			return nil, err
		}

		stats.TopIPs = append(stats.TopIPs, item)
	}

	rows.Close()

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Top usernames
	rows, err = db.Query(`
		SELECT
			username,
			COUNT(*) AS count
		FROM auth_attempts
		GROUP BY username
		ORDER BY count DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var item api.UsernameCounts

		if err := rows.Scan(&item.Username, &item.Count); err != nil {
			rows.Close()
			return nil, err
		}

		stats.TopUsernames = append(stats.TopUsernames, item)
	}

	rows.Close()

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Top passwords
	rows, err = db.Query(`
		SELECT
			credential,
			COUNT(*) AS count
		FROM auth_attempts
		GROUP BY credential
		ORDER BY count DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var item api.PasswordCounts

		if err := rows.Scan(&item.Password, &item.Count); err != nil {
			rows.Close()
			return nil, err
		}

		stats.TopPasswords = append(stats.TopPasswords, item)
	}

	rows.Close()

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Top credentials
	rows, err = db.Query(`
		SELECT
			username,
			credential,
			COUNT(*) AS count
		FROM auth_attempts
		GROUP BY username, credential
		ORDER BY count DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var item api.CredentialCounts

		if err := rows.Scan(
			&item.Username,
			&item.Password,
			&item.Count,
		); err != nil {
			rows.Close()
			return nil, err
		}

		stats.TopCredentials = append(stats.TopCredentials, item)
	}

	rows.Close()

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// SSH banners
	rows, err = db.Query(`
		SELECT
			ssh_client_banner,
			COUNT(*) AS count
		FROM sessions
		GROUP BY ssh_client_banner
		ORDER BY count DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var item api.BannerCounts

		if err := rows.Scan(&item.Banner, &item.Count); err != nil {
			rows.Close()
			return nil, err
		}

		stats.SSHBanners = append(stats.SSHBanners, item)
	}

	rows.Close()

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Coordinated IP groups: distinct IPs that used the same credential and
	// SSH client banner within the same 5-minute window. That combination --
	// same secret, same client fingerprint, tight time window, multiple
	// source IPs -- is what an actual botnet/script-driven campaign looks
	// like; unrelated IPs sharing a lifetime session count is not.
	rows, err = db.Query(`
		WITH attempts AS (
			SELECT
				s.client_ip,
				s.ssh_client_banner,
				a.username,
				a.credential,
				(floor(s.start_ms / 1000.0 / 300) * 300000)::bigint AS window_start_ms
			FROM sessions s
			JOIN auth_attempts a ON a.session_id = s.session_id
		)
		SELECT
			COUNT(DISTINCT client_ip) AS ip_count,
			ARRAY_AGG(DISTINCT client_ip ORDER BY client_ip),
			username,
			credential,
			ssh_client_banner,
			window_start_ms
		FROM attempts
		GROUP BY window_start_ms, ssh_client_banner, username, credential
		HAVING COUNT(DISTINCT client_ip) > 2
		ORDER BY ip_count DESC, window_start_ms DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var item api.CoordinatedIPGroup

		if err := rows.Scan(
			&item.Count,
			pq.Array(&item.IPs),
			&item.Username,
			&item.Credential,
			&item.Banner,
			&item.WindowStart,
		); err != nil {
			rows.Close()
			return nil, err
		}

		stats.CoordinatedIPs = append(stats.CoordinatedIPs, item)
	}

	rows.Close()

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Hourly distribution
	rows, err = db.Query(`
		SELECT
			EXTRACT(HOUR FROM to_timestamp(start_ms / 1000.0))::INT AS hour,
			COUNT(*) AS count
		FROM sessions
		GROUP BY hour
		ORDER BY hour
	`)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var item api.HourlyDistribution

		if err := rows.Scan(
			&item.Hour,
			&item.Count,
		); err != nil {
			rows.Close()
			return nil, err
		}

		stats.HourlyDistribution = append(stats.HourlyDistribution, item)
	}

	rows.Close()

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return stats, nil
}

func GetSessions(
	db *sql.DB,
	limit int,
	offset int,
) (*api.SessionsResponse, error) {
	resp := &api.SessionsResponse{
		Limit:  limit,
		Offset: offset,
	}

	// Total session count
	if err := db.QueryRow(`
		SELECT COUNT(*)
		FROM sessions
	`).Scan(&resp.Total); err != nil {
		return nil, err
	}

	rows, err := db.Query(`
		SELECT
			session_id,
			client_ip,
			outcome,
			command_count,
			start_ms,
			duration_ms,
			ssh_client_banner
		FROM sessions
		ORDER BY start_ms DESC
		LIMIT $1
		OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var session api.SessionSummary

		if err := rows.Scan(
			&session.SessionID,
			&session.ClientIP,
			&session.Outcome,
			&session.CommandCount,
			&session.StartMS,
			&session.DurationMS,
			&session.SSHBanner,
		); err != nil {
			return nil, err
		}

		resp.Sessions = append(resp.Sessions, session)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return resp, nil
}

func GetSessionByID(
	db *sql.DB,
	sessionID string,
) (*session.Session, error) {
	var raw []byte
	var attackerClass sql.NullString
	var classifierConfidence sql.NullFloat64
	var clusterID sql.NullString
	var mitreTechniquesRaw []byte
	var sessionSummary sql.NullString
	var stixBundleRaw []byte
	var severity sql.NullString
	var recommendedActionsRaw []byte

	err := db.QueryRow(`
		SELECT
			session_document,
			attacker_class,
			classifier_confidence,
			cluster_id,
			mitre_techniques,
			session_summary,
			stix_bundle,
			severity,
			recommended_actions
		FROM sessions
		WHERE session_id = $1
	`, sessionID).Scan(
		&raw,
		&attackerClass,
		&classifierConfidence,
		&clusterID,
		&mitreTechniquesRaw,
		&sessionSummary,
		&stixBundleRaw,
		&severity,
		&recommendedActionsRaw,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session not found")
		}
		return nil, err
	}

	var sess session.Session
	if err := json.Unmarshal(raw, &sess); err != nil {
		return nil, fmt.Errorf("unmarshalling session document: %w", err)
	}

	// Overlay the intelligence columns (written by the ML worker) onto the
	// session document. The document itself never has these populated — they
	// live in dedicated columns updated post-hoc by the enrichment pipeline.
	if attackerClass.Valid {
		sess.Intelligence.AttackerClass = &attackerClass.String
	}
	if classifierConfidence.Valid {
		sess.Intelligence.ClassifierConfidence = &classifierConfidence.Float64
	}
	if clusterID.Valid {
		sess.Intelligence.ClusterID = &clusterID.String
	}
	if len(mitreTechniquesRaw) > 0 {
		var techniques []string
		if err := json.Unmarshal(mitreTechniquesRaw, &techniques); err == nil {
			sess.Intelligence.MitreTechniques = techniques
		}
	}
	if sessionSummary.Valid {
		sess.Intelligence.SessionSummary = &sessionSummary.String
	}
	if len(stixBundleRaw) > 0 {
		var bundle json.RawMessage
		if err := json.Unmarshal(stixBundleRaw, &bundle); err == nil {
			sess.Intelligence.StixBundle = &bundle
		}
	}
	if severity.Valid {
		sess.Intelligence.Severity = &severity.String
	}
	if len(recommendedActionsRaw) > 0 {
		var actions []string
		if err := json.Unmarshal(recommendedActionsRaw, &actions); err == nil {
			sess.Intelligence.RecommendedActions = actions
		}
	}

	return &sess, nil
}
func GetSessionReport(
	db *sql.DB,
	sessionID string,
) (*api.SessionReport, error) {
	sess, err := GetSessionByID(db, sessionID)
	if err != nil {
		return nil, err
	}

	// Severity: prefer the ML pipeline's own computation (considers bait
	// escalation, not just attacker_class). Only sessions enriched before
	// this was persisted (see db/init/002_ml_intelligence.sql) lack it, so
	// fall back to a cruder class-only derivation for those.
	severity := "low"
	if sess.Intelligence.Severity != nil {
		severity = *sess.Intelligence.Severity
	} else if sess.Intelligence.AttackerClass != nil {
		switch *sess.Intelligence.AttackerClass {
		case "script_kiddie":
			severity = "medium"
		case "manual_recon":
			severity = "high"
		case "apt":
			severity = "critical"
		}
	}

	var durationMS *int64
	if sess.Timing.DurationMS != nil {
		durationMS = sess.Timing.DurationMS
	}

	report := &api.SessionReport{
		SessionID:   sess.SessionID,
		GeneratedAt: fmt.Sprintf("%d", time.Now().UnixMilli()),
		Profile: api.AttackerProfile{
			Class:      sess.Intelligence.AttackerClass,
			Confidence: sess.Intelligence.ClassifierConfidence,
			ClusterID:  sess.Intelligence.ClusterID,
			Severity:   severity,
		},
		Network: api.ReportNetwork{
			ClientIP:  sess.Network.ClientIP,
			SSHBanner: sess.Network.SSHClientBanner,
			Outcome:   string(sess.Outcome),
		},
		Timeline: api.ReportTimeline{
			StartMS:      sess.Timing.StartMS,
			DurationMS:   durationMS,
			AuthAttempts: len(sess.AuthAttempts),
			Commands:     len(sess.Commands),
			BaitHits:     len(sess.BaitEvents),
		},
		ThreatIntel: api.ReportThreatIntel{
			MitreTechniques:    sess.Intelligence.MitreTechniques,
			Summary:            sess.Intelligence.SessionSummary,
			RecommendedActions: sess.Intelligence.RecommendedActions,
		},
		StixBundle: sess.Intelligence.StixBundle,
	}

	return report, nil
}

const defaultCommandExportLimit = 2000
const maxCommandExportLimit = 10000

// encodeCommandCursor/decodeCommandCursor pack the keyset-pagination cursor
// for GetCommandExport as "timestamp_ms:event_id" -- commands.timestamp_ms
// alone isn't guaranteed unique across sessions, so event_id breaks ties and
// keeps pagination stable even if two commands share a millisecond.
func encodeCommandCursor(timestampMS int64, eventID string) string {
	return fmt.Sprintf("%d:%s", timestampMS, eventID)
}

func decodeCommandCursor(cursor string) (timestampMS int64, eventID string, ok bool) {
	tsPart, idPart, found := strings.Cut(cursor, ":")
	if !found || idPart == "" {
		return 0, "", false
	}
	ts, err := strconv.ParseInt(tsPart, 10, 64)
	if err != nil {
		return 0, "", false
	}
	return ts, idPart, true
}

// GetCommandExport returns one page of the flattened commands export (see
// api.ExportCommand) ordered by (timestamp_ms, event_id), the natural
// capture order. after is an opaque cursor from a previous page's
// NextCursor ("" for the first page); limit is clamped to
// [1, maxCommandExportLimit], defaulting to defaultCommandExportLimit.
//
// Unlike GetExportData (session-level, returned in one shot), per-command
// volume is high enough -- up to maxCommandsPerSession (500, see
// internal/server) per session, across every session -- that an unpaginated
// dump isn't a safe default; keyset pagination (rather than OFFSET) keeps
// each page's query cost independent of how deep into the export the caller
// already is.
func GetCommandExport(db *sql.DB, after string, limit int) (*api.ExportCommandsResponse, error) {
	if limit <= 0 || limit > maxCommandExportLimit {
		limit = defaultCommandExportLimit
	}

	afterTS := int64(-1) // sentinel below any real unix-ms timestamp
	afterID := ""
	if after != "" {
		ts, id, ok := decodeCommandCursor(after)
		if !ok {
			return nil, fmt.Errorf("invalid cursor: %q", after)
		}
		afterTS, afterID = ts, id
	}

	rows, err := db.Query(`
		SELECT
			c.event_id, c.session_id, c.sequence_number,
			c.timestamp_ms, c.inter_command_delay_ms,
			c.raw_input_b64, c.parsed_command, c.parsed_args,
			c.working_directory, c.response_text, c.exit_code,
			c.response_source, c.deception_action,
			b.bait_id, b.bait_type,
			s.client_ip, s.ssh_client_banner, s.attacker_class, s.mitre_techniques
		FROM commands c
		JOIN sessions s ON s.session_id = c.session_id
		LEFT JOIN bait_interactions b ON b.triggered_by_command_event_id = c.event_id
		WHERE c.timestamp_ms > $1 OR (c.timestamp_ms = $1 AND c.event_id > $2)
		ORDER BY c.timestamp_ms ASC, c.event_id ASC
		LIMIT $3
	`, afterTS, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("querying commands export: %w", err)
	}
	defer rows.Close()

	resp := &api.ExportCommandsResponse{
		GeneratedAt: fmt.Sprintf("%d", time.Now().UnixMilli()),
		Commands:    []api.ExportCommand{},
	}

	var lastTS int64
	var lastID string
	for rows.Next() {
		var item api.ExportCommand
		var rawB64 string
		var argsRaw, mitreRaw []byte
		var baitID, baitType sql.NullString

		if err := rows.Scan(
			&item.EventID, &item.SessionID, &item.SequenceNumber,
			&item.TimestampMS, &item.InterCommandDelayMS,
			&rawB64, &item.ParsedCommand, &argsRaw,
			&item.WorkingDirectory, &item.Response, &item.ExitCode,
			&item.ResponseSource, &item.DeceptionAction,
			&baitID, &baitType,
			&item.ClientIP, &item.SSHClientBanner, &item.AttackerClass, &mitreRaw,
		); err != nil {
			return nil, fmt.Errorf("scanning command export row: %w", err)
		}

		decoded, err := base64.StdEncoding.DecodeString(rawB64)
		if err != nil {
			return nil, fmt.Errorf("decoding raw_input_b64 for command %s: %w", item.EventID, err)
		}
		item.RawCommand = string(decoded)

		if len(argsRaw) > 0 {
			if err := json.Unmarshal(argsRaw, &item.ParsedArgs); err != nil {
				return nil, fmt.Errorf("unmarshalling parsed args: %w", err)
			}
		}
		if len(mitreRaw) > 0 {
			if err := json.Unmarshal(mitreRaw, &item.MitreTechniques); err != nil {
				return nil, fmt.Errorf("unmarshalling mitre techniques: %w", err)
			}
		}

		if baitID.Valid {
			item.BaitHit = true
			item.BaitType = &baitType.String
		}

		resp.Commands = append(resp.Commands, item)
		lastTS, lastID = item.TimestampMS, item.EventID
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	resp.CommandCount = len(resp.Commands)
	if resp.CommandCount == limit {
		cursor := encodeCommandCursor(lastTS, lastID)
		resp.NextCursor = &cursor
	}

	return resp, nil
}
