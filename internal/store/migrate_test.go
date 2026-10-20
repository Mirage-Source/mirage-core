package store

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"
)

func TestMigrationVersionsAreOrderedAndUnique(t *testing.T) {
	versions, err := migrationVersions()
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) == 0 {
		t.Fatal("no embedded migrations")
	}
	seen := map[string]bool{}
	for i, v := range versions {
		prefix := v[:3]
		if seen[prefix] {
			t.Errorf("duplicate migration number %s", prefix)
		}
		seen[prefix] = true
		if i > 0 && versions[i-1] >= v {
			t.Errorf("%s sorts before %s", v, versions[i-1])
		}
		body, err := migrationFS.ReadFile("migrations/" + v + ".sql")
		if err != nil || len(strings.TrimSpace(string(body))) == 0 {
			t.Errorf("%s is empty or unreadable", v)
		}
	}
}

func TestMigrateFreshDatabaseConcurrentlyAndIdempotently(t *testing.T) {
	if os.Getenv("MIRAGE_E2E_TEST") == "" {
		t.Skip("set MIRAGE_E2E_TEST=1 against a reachable Postgres to run this test")
	}
	admin, err := Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()

	name := fmt.Sprintf("mirage_migrate_%d", os.Getpid())
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec("DROP DATABASE " + name)

	db, err := sql.Open("postgres", connString(name))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- Migrate(db)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Migrate: %v", err)
		}
	}
	if err := Migrate(db); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	versions, _ := migrationVersions()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM schema_migrations").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != len(versions) {
		t.Errorf("schema_migrations has %d rows, want %d", n, len(versions))
	}
	if _, err := db.Exec("SELECT command_chain FROM commands LIMIT 0"); err != nil {
		t.Errorf("latest column missing: %v", err)
	}
	if _, err := db.Exec("SELECT * FROM enriched_sessions LIMIT 0"); err != nil {
		t.Errorf("view missing: %v", err)
	}
}

// A migration that needs an exclusive lock must not queue behind a long
// reader indefinitely: while it waits, every newer query on that table waits
// behind it too. It gives up after lockTimeout, lets the queue drain, and
// tries again.
func TestMigrateRetriesWhenTableIsLockedAndDoesNotRetryOtherErrors(t *testing.T) {
	if os.Getenv("MIRAGE_E2E_TEST") == "" {
		t.Skip("set MIRAGE_E2E_TEST=1 against a reachable Postgres to run this test")
	}
	admin, err := Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()

	name := fmt.Sprintf("mirage_locktest_%d", os.Getpid())
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec("DROP DATABASE " + name)
	db, err := sql.Open("postgres", connString(name))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE locktarget (id INT)"); err != nil {
		t.Fatal(err)
	}

	var attempts atomic.Int32
	opts := migrateOpts{
		lockTimeout: 100 * time.Millisecond,
		retryDelay:  50 * time.Millisecond,
		logf:        func(string, ...any) { attempts.Add(1) },
	}

	// A reader holds ACCESS SHARE, which blocks ALTER TABLE's ACCESS EXCLUSIVE.
	reader, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Exec("LOCK TABLE locktarget IN ACCESS SHARE MODE"); err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(600*time.Millisecond, func() { reader.Rollback() })

	fsys := fstest.MapFS{"migrations/001_add.sql": {Data: []byte("ALTER TABLE locktarget ADD COLUMN c INT;")}}
	start := time.Now()
	if err := migrate(db, fsys, "migrations", opts); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if time.Since(start) < 500*time.Millisecond {
		t.Errorf("migrate returned in %v, before the reader released the lock", time.Since(start))
	}
	if attempts.Load() < 2 {
		t.Errorf("logged %d retries, want at least 2", attempts.Load())
	}
	if _, err := db.Exec("SELECT c FROM locktarget LIMIT 0"); err != nil {
		t.Errorf("column missing after migrate: %v", err)
	}

	attempts.Store(0)
	bad := fstest.MapFS{"migrations/002_bad.sql": {Data: []byte("THIS IS NOT SQL;")}}
	if err := migrate(db, bad, "migrations", opts); err == nil {
		t.Fatal("migrate of invalid SQL returned nil")
	}
	if attempts.Load() != 0 {
		t.Errorf("a non-lock error was retried %d times", attempts.Load())
	}
}
