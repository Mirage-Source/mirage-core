package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Arbitrary, but must stay fixed so every process contends on the same lock.
const migrationLockID = 0x6d6972616765

func migrationVersions() ([]string, error) {
	names, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return nil, err
	}
	versions := make([]string, len(names))
	for i, n := range names {
		versions[i] = strings.TrimSuffix(path.Base(n), ".sql")
	}
	sort.Strings(versions)
	return versions, nil
}

// Migrate applies every embedded migration not yet in schema_migrations, one
// transaction per file, holding a session advisory lock so sensors starting
// together don't race.
func Migrate(db *sql.DB) error {
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquiring migration connection: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); err != nil {
		return fmt.Errorf("taking migration lock: %w", err)
	}
	defer conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", migrationLockID)

	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("creating schema_migrations: %w", err)
	}

	applied := map[string]bool{}
	rows, err := conn.QueryContext(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return fmt.Errorf("reading schema_migrations: %w", err)
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	versions, err := migrationVersions()
	if err != nil {
		return err
	}
	for _, v := range versions {
		if applied[v] {
			continue
		}
		body, err := migrationFS.ReadFile("migrations/" + v + ".sql")
		if err != nil {
			return err
		}
		if err := applyMigration(ctx, conn, v, string(body)); err != nil {
			return fmt.Errorf("migration %s: %w", v, err)
		}
	}
	return nil
}

func applyMigration(ctx context.Context, conn *sql.Conn, version, body string) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, body); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
		return err
	}
	return tx.Commit()
}
