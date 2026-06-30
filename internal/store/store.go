package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	_ "github.com/lib/pq"
	"github.com/mirage-source/mirage-core/internal/session"
	"github.com/mirage-source/mirage-core/internal/api"
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
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("pinging database: %w", err)
	}
	return db, nil
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
			start_ms, end_ms, duration_ms, outcome,
			command_count, bait_hit_count,
			attacker_class, classifier_confidence, cluster_id,
			mitre_techniques, session_summary,
			session_document
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			$9, $10, $11, $12,
			$13, $14,
			$15, $16, $17,
			$18, $19,
			$20
		)
	`, sess.SessionID, sess.SchemaVersion, sess.NodeID, sess.Protocol,
	   sess.Network.ClientIP, sess.Network.ClientPort, sess.Network.ServerPort, sess.Network.SSHClientBanner,
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
				working_directory, response_source
			) VALUES (
				$1, $2, $3,
				$4, $5,
				$6, $7, $8,
				$9, $10
			)
		`, c.EventID, sess.SessionID, c.SequenceNumber,
			c.TimestampMS, c.InterCommandDelayMS,
			c.RawInputB64, c.ParsedCommand, argsBytes,
			c.WorkingDirectory, c.ResponseSource,
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

func GetExportData(db *sql.DB) (*api.ExportResponse, error) {
	resp := &api.ExportResponse{
		GeneratedAt: fmt.Sprintf("%d", time.Now().UnixMilli()),
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
		ORDER BY s.start_ms DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

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
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	resp.SessionCount = len(resp.Sessions)

	return resp, nil
}
