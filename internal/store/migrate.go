package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Arbitrary, but must stay fixed so every process contends on the same lock.
const migrationLockID = 0x6d6972616765

// pgLockNotAvailable is SQLSTATE 55P03, raised when lock_timeout expires.
const pgLockNotAvailable = "55P03"

type migrateOpts struct {
	// lockTimeout bounds how long one attempt waits for a table lock.
	lockTimeout time.Duration
	// retryDelay is the pause after a timed-out attempt, so the queries that
	// piled up behind the waiting lock request can drain.
	retryDelay time.Duration
	logf       func(format string, args ...any)
}

func defaultMigrateOpts() migrateOpts {
	return migrateOpts{
		lockTimeout: time.Duration(envInt("MIGRATION_LOCK_TIMEOUT_SECONDS", 10)) * time.Second,
		retryDelay:  time.Duration(envInt("MIGRATION_RETRY_DELAY_SECONDS", 5)) * time.Second,
		logf:        log.Printf,
	}
}

func migrationVersions() ([]string, error) {
	return versionsIn(migrationFS, "migrations")
}

func versionsIn(fsys fs.FS, dir string) ([]string, error) {
	names, err := fs.Glob(fsys, dir+"/*.sql")
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
//
// Each migration runs under lock_timeout and is retried when it expires. An
// ALTER TABLE waits for every running query on the table, and while it waits
// every newer query on that table queues behind it. Without a timeout, one
// hours-long read froze the sensors in startup for 2.5 hours; with one, the
// request is withdrawn, the queue drains, and the attempt is made again.
func Migrate(db *sql.DB) error {
	return migrate(db, migrationFS, "migrations", defaultMigrateOpts())
}

func migrate(db *sql.DB, fsys fs.FS, dir string, opts migrateOpts) error {
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

	versions, err := versionsIn(fsys, dir)
	if err != nil {
		return err
	}
	for _, v := range versions {
		if applied[v] {
			continue
		}
		body, err := fs.ReadFile(fsys, dir+"/"+v+".sql")
		if err != nil {
			return err
		}
		for attempt := 1; ; attempt++ {
			err := applyMigration(ctx, conn, v, string(body), opts.lockTimeout)
			if err == nil {
				break
			}
			var pqErr *pq.Error
			if !errors.As(err, &pqErr) || pqErr.Code != pgLockNotAvailable {
				return fmt.Errorf("migration %s: %w", v, err)
			}
			opts.logf("migration %s: table lock not granted within %v (attempt %d); retrying in %v", v, opts.lockTimeout, attempt, opts.retryDelay)
			time.Sleep(opts.retryDelay)
		}
	}
	return nil
}

func applyMigration(ctx context.Context, conn *sql.Conn, version, body string, lockTimeout time.Duration) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// SET LOCAL takes no bind parameters; the value is an int of milliseconds.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL lock_timeout = %d", lockTimeout.Milliseconds())); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, body); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
		return err
	}
	return tx.Commit()
}
