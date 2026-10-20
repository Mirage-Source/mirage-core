package store

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/lib/pq"
)

// The API and validity loop run read queries that can hold locks on sessions
// for as long as they run; a runaway one blocked a schema migration for 2.5h.
// The API's pool therefore cancels any statement past a bound, while the
// sensors' pool (writes, migrations, CREATE INDEX) stays unbounded.
func TestConnectWithStatementTimeoutCancelsSlowQueriesOnly(t *testing.T) {
	if os.Getenv("MIRAGE_E2E_TEST") == "" {
		t.Skip("set MIRAGE_E2E_TEST=1 against a reachable Postgres to run this test")
	}

	bounded, err := ConnectWithStatementTimeout(200 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer bounded.Close()

	start := time.Now()
	_, err = bounded.Exec("SELECT pg_sleep(2)")
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) || pqErr.Code != "57014" {
		t.Fatalf("slow query on bounded pool: err = %v, want query_canceled (57014)", err)
	}
	if time.Since(start) > time.Second {
		t.Errorf("slow query ran %v, want cancelled near 200ms", time.Since(start))
	}
	if _, err := bounded.Exec("SELECT pg_sleep(0.01)"); err != nil {
		t.Errorf("fast query on bounded pool failed: %v", err)
	}

	plain, err := Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if _, err := plain.Exec("SELECT pg_sleep(0.5)"); err != nil {
		t.Errorf("Connect() must not impose a statement timeout: %v", err)
	}
}
