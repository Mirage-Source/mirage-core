package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// RuntimeFlags are the dashboard-writable subset of what
// mirage-web/docs/API-GAPS.md §4 calls "runtime configuration" -- today just
// the two deception-policy switches. Nil UpdatedAt/UpdatedBy means the flag
// has never been written by an operator (only ever seeded by a migration).
type RuntimeFlags struct {
	DeceptionEnabled      bool
	DeceptionApplyActions bool
	UpdatedAt             *time.Time
	UpdatedBy             *string
}

// ErrUnknownFlag is returned by SetRuntimeFlag for any key besides the two
// this package knows how to persist.
var ErrUnknownFlag = errors.New("store: unknown runtime flag")

var runtimeFlagKeys = map[string]bool{
	"deception_enabled":       true,
	"deception_apply_actions": true,
}

// LoadRuntimeFlags reads both flags from the runtime_flags table (see
// migrations/010_runtime_flags.sql). A row missing entirely -- the table
// exists but a migration hasn't seeded it, or this DB predates the
// migration -- reads back as false, not an error: the caller's own
// ConfigFromEnv-derived default already covers "never configured".
func LoadRuntimeFlags(db *sql.DB) (RuntimeFlags, error) {
	rows, err := db.Query(`SELECT key, enabled, updated_at, updated_by FROM runtime_flags
		WHERE key IN ('deception_enabled', 'deception_apply_actions')`)
	if err != nil {
		return RuntimeFlags{}, fmt.Errorf("store: loading runtime flags: %w", err)
	}
	defer rows.Close()

	var out RuntimeFlags
	for rows.Next() {
		var key string
		var enabled bool
		var updatedAt time.Time
		var updatedBy *string
		if err := rows.Scan(&key, &enabled, &updatedAt, &updatedBy); err != nil {
			return RuntimeFlags{}, fmt.Errorf("store: scanning runtime flag: %w", err)
		}
		switch key {
		case "deception_enabled":
			out.DeceptionEnabled = enabled
		case "deception_apply_actions":
			out.DeceptionApplyActions = enabled
		}
		if out.UpdatedAt == nil || updatedAt.After(*out.UpdatedAt) {
			t := updatedAt
			out.UpdatedAt = &t
			out.UpdatedBy = updatedBy
		}
	}
	return out, rows.Err()
}

// SetRuntimeFlag upserts one flag's value. updatedBy is an operator-supplied
// label (e.g. "console"), not an authenticated identity -- mirage-api has no
// per-operator accounts, only the one shared API key -- so it is descriptive
// only, never trusted for authorization.
func SetRuntimeFlag(db *sql.DB, key string, enabled bool, updatedBy string) error {
	if !runtimeFlagKeys[key] {
		return ErrUnknownFlag
	}
	_, err := db.Exec(
		`INSERT INTO runtime_flags (key, enabled, updated_at, updated_by)
		 VALUES ($1, $2, now(), $3)
		 ON CONFLICT (key) DO UPDATE
		     SET enabled = EXCLUDED.enabled, updated_at = now(), updated_by = EXCLUDED.updated_by`,
		key, enabled, updatedBy,
	)
	if err != nil {
		return fmt.Errorf("store: setting runtime flag %q: %w", key, err)
	}
	return nil
}
