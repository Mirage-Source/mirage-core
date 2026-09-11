package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/lib/pq"
	"github.com/mirage-source/mirage-core/internal/api"
	"github.com/mirage-source/mirage-core/internal/session"
	"math"
	"os"
	"strconv"
	"time"
)

func Connect() (*sql.DB, error) {
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")

	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname,
	)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Unbounded by default, while MAX_CONCURRENT_CONNECTIONS allows 500
	// sessions each opening a transaction at finalize. Past Postgres's own
	// max_connections (100 by default) the surplus fails with "too many
	// clients", and SaveSession only logs, so those sessions are lost from
	// the store that is authoritative for this node. Better to queue behind
	// a bounded pool than to drop.
	db.SetMaxOpenConns(envInt("DB_MAX_OPEN_CONNS", 20))
	db.SetMaxIdleConns(envInt("DB_MAX_IDLE_CONNS", 10))
	db.SetConnMaxLifetime(time.Duration(envInt("DB_CONN_MAX_LIFETIME_MINUTES", 30)) * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("pinging database: %w", err)
	}
	return db, nil
}

func envInt(key string, fallback int) int {
	n, err := strconv.Atoi(os.Getenv(key))
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func SaveSession(db *sql.DB, sess *session.Session) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}
	defer tx.Rollback()

	docBytes, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("marshalling session: %w", err)
	}

	mitreBytes, err := json.Marshal(sess.Intelligence.MitreTechniques)
	if err != nil {
		return fmt.Errorf("marshalling mitre techniques: %w", err)
	}

	_, err = tx.Exec(`
		INSERT INTO sessions (
			session_id, schema_version, node_id, protocol,
			client_ip, client_port, server_port, ssh_client_banner,
			ingress_source, proxy_node_id,
			start_ms, end_ms, duration_ms, outcome,
			command_count, bait_hit_count,
			attacker_class, classifier_confidence, cluster_id,
			mitre_techniques, session_summary,
			session_document
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			$9, $10,
			$11, $12, $13, $14,
			$15, $16,
			$17, $18, $19,
			$20, $21,
			$22
		)
	`, sess.SessionID, sess.SchemaVersion, sess.NodeID, sess.Protocol,
		sess.Network.ClientIP, sess.Network.ClientPort, sess.Network.ServerPort, sess.Network.SSHClientBanner,
		sess.Network.IngressSource, sess.Network.ProxyNodeID,
		sess.Timing.StartMS, sess.Timing.EndMS, sess.Timing.DurationMS, sess.Outcome,
		len(sess.Commands), len(sess.BaitEvents),
		sess.Intelligence.AttackerClass, sess.Intelligence.ClassifierConfidence, sess.Intelligence.ClusterID,
		mitreBytes, sess.Intelligence.SessionSummary,
		docBytes,
	)
	if err != nil {
		return fmt.Errorf("inserting session: %w", err)
	}

	for _, a := range sess.AuthAttempts {
		_, err = tx.Exec(`
	   		INSERT INTO auth_attempts (
				session_id, timestamp_ms, method, username, credential, success
			) VALUES (
				$1, $2, $3, $4, $5, $6
			)
		`,
			sess.SessionID, a.TimestampMS, a.Method, a.Username, a.Credential, a.Success,
		)
		if err != nil {
			return fmt.Errorf("inserting auth attempt: %w", err)
		}
	}

	for _, c := range sess.Commands {
		argsBytes, err := json.Marshal(c.ParsedArgs)
		if err != nil {
			return fmt.Errorf("marshaling parsed args: %w", err)
		}

		_, err = tx.Exec(`
			INSERT INTO commands (
				event_id, session_id, sequence_number,
				timestamp_ms, inter_command_delay_ms,
				raw_input_b64, parsed_command, parsed_args,
				working_directory, response_text, exit_code,
				response_source, deception_action
			) VALUES (
				$1, $2, $3,
				$4, $5,
				$6, $7, $8,
				$9, $10, $11,
				$12, $13
			)
		`, c.EventID, sess.SessionID, c.SequenceNumber,
			c.TimestampMS, c.InterCommandDelayMS,
			c.RawInputB64, c.ParsedCommand, argsBytes,
			c.WorkingDirectory, c.Response, c.ExitCode,
			c.ResponseSource, c.DeceptionAction,
		)
		if err != nil {
			return fmt.Errorf("inserting command: %w", err)
		}
	}

	for _, b := range sess.BaitEvents {
		_, err = tx.Exec(`
			INSERT INTO bait_interactions (
				event_id, session_id, timestamp_ms,
				bait_id, bait_type, access_type,
				triggered_by_command_event_id
			) VALUES (
				$1, $2, $3,
				$4, $5, $6,
				$7
			)
		`, b.EventID, sess.SessionID, b.TimestampMS,
			b.BaitID, b.BaitType, b.AccessType,
			b.TriggeredByCommandEventID,
		)
		if err != nil {
			return fmt.Errorf("inserting bait interaction: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}

// GetExportPage returns one page of the session-level export, newest first,
// ordered by (start_ms DESC, session_id DESC). after is an opaque cursor from
// a previous page's NextCursor ("" for the first page).
//
// Keyset rather than OFFSET, for the same reason GetCommandExport uses it:
// each page's query cost stays independent of how deep the caller already is.
// This export was unpaginated and fully materialized until the corpus passed
// 54k sessions, at which point the LATERAL-per-row scan plus a whole-response
// encode began racing cmd/api's 15s WriteTimeout -- which truncates the body
// mid-JSON rather than failing cleanly.
func GetExportPage(db *sql.DB, after string, limit int) (*api.ExportResponse, error) {
	if limit <= 0 || limit > maxSessionExportLimit {
		limit = defaultSessionExportLimit
	}

	afterStart := int64(math.MaxInt64) // sentinel above any real unix-ms timestamp
	afterID := "\uffff"
	if after != "" {
		start, id, ok := decodeKeysetCursor(after)
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrInvalidCursor, after)
		}
		afterStart, afterID = start, id
	}

	rows, err := db.Query(`
		SELECT
			s.session_id,
			s.node_id,
			s.client_ip,
			s.ssh_client_banner,
			s.start_ms,
			s.end_ms,
			s.duration_ms,
			s.outcome,
			s.command_count,
			s.bait_hit_count,
			s.attacker_class,
			s.classifier_confidence,
			s.cluster_id,
			s.mitre_techniques,
			COALESCE(a.attempt_count, 0),
			COALESCE(a.unique_usernames, 0),
			a.top_username
		FROM sessions s
		LEFT JOIN LATERAL (
			SELECT
				COUNT(*) AS attempt_count,
				COUNT(DISTINCT username) AS unique_usernames,
				(
					SELECT username
					FROM auth_attempts aa2
					WHERE aa2.session_id = s.session_id
					GROUP BY username
					ORDER BY COUNT(*) DESC
					LIMIT 1
				) AS top_username
			FROM auth_attempts aa
			WHERE aa.session_id = s.session_id
		) a ON true
		WHERE s.start_ms < $1 OR (s.start_ms = $1 AND s.session_id < $2)
		ORDER BY s.start_ms DESC, s.session_id DESC
		LIMIT $3
	`, afterStart, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	resp := &api.ExportResponse{
		GeneratedAt: fmt.Sprintf("%d", time.Now().UnixMilli()),
		Sessions:    []api.ExportSession{},
	}

	var lastStart int64
	var lastID string
	for rows.Next() {
		var item api.ExportSession
		var mitreRaw []byte

		if err := rows.Scan(
			&item.SessionID,
			&item.NodeID,
			&item.ClientIP,
			&item.SSHClientBanner,
			&item.StartMS,
			&item.EndMS,
			&item.DurationMS,
			&item.Outcome,
			&item.CommandCount,
			&item.BaitHitCount,
			&item.AttackerClass,
			&item.ClassifierConfidence,
			&item.ClusterID,
			&mitreRaw,
			&item.AuthAttemptCount,
			&item.UniqueUsernamesTried,
			&item.TopUsername,
		); err != nil {
			return nil, err
		}

		if len(mitreRaw) > 0 {
			if err := json.Unmarshal(mitreRaw, &item.MitreTechniques); err != nil {
				return nil, fmt.Errorf("unmarshalling mitre techniques: %w", err)
			}
		}

		resp.Sessions = append(resp.Sessions, item)
		lastStart, lastID = item.StartMS, item.SessionID
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	resp.SessionCount = len(resp.Sessions)
	if resp.SessionCount == limit {
		cursor := encodeKeysetCursor(lastStart, lastID)
		resp.NextCursor = &cursor
	}

	return resp, nil
}
