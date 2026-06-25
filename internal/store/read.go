package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/lib/pq"
	"github.com/mirage-source/mirage-core/internal/api"
	"github.com/mirage-source/mirage-core/internal/session"
)

func GetStats(db *sql.DB) (*api.HoneypotStats, error) {
	stats := &api.HoneypotStats{}

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

	// Coordinated IP groups
	rows, err = db.Query(`
		WITH ip_counts AS (
			SELECT
				client_ip,
				COUNT(*) AS session_count
			FROM sessions
			GROUP BY client_ip
		)
		SELECT
			session_count,
			ARRAY_AGG(client_ip ORDER BY client_ip)
		FROM ip_counts
		GROUP BY session_count
		HAVING COUNT(*) > 2
		ORDER BY session_count DESC
	`)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var item api.CoordinatedIPGroup

		if err := rows.Scan(
			&item.Count,
			pq.Array(&item.IPs),
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

	err := db.QueryRow(`
		SELECT
			session_document,
			attacker_class,
			classifier_confidence,
			cluster_id,
			mitre_techniques,
			session_summary
		FROM sessions
		WHERE session_id = $1
	`, sessionID).Scan(
		&raw,
		&attackerClass,
		&classifierConfidence,
		&clusterID,
		&mitreTechniquesRaw,
		&sessionSummary,
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

	return &sess, nil
}
