package store

import (
	"database/sql"

	"github.com/lib/pq"
	"github.com/mirage-source/mirage-core/internal/api"
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
