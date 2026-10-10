package store

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
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
