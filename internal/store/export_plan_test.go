package store

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The export cursor has to start the index scan at the cursor. When it was
// only a Filter, every page walked the index from the newest session down to
// the cursor, so page N cost O(N) and the full dump O(N^2): on 1.29M sessions
// a page 20 deep discarded 984k rows to return 2000, and the weekly publish
// ran past the export's 5-minute write deadline.
//
// The test table is tiny, so seq and bitmap scans are switched off to make the
// planner show which predicate the start_ms index can actually use.
func TestExportPageCursorIsAnIndexCondition(t *testing.T) {
	if os.Getenv("MIRAGE_E2E_TEST") == "" {
		t.Skip("set MIRAGE_E2E_TEST=1 against a reachable, migrated Postgres to run this test")
	}
	db, err := Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, stmt := range []string{"SET LOCAL enable_seqscan = off", "SET LOCAL enable_bitmapscan = off"} {
		if _, err := tx.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}

	var raw []byte
	err = tx.QueryRow("EXPLAIN (FORMAT JSON) "+exportPageSQL,
		int64(1_790_000_000_000), "some-session-id", 2000, "ssh").Scan(&raw)
	if err != nil {
		t.Fatal(err)
	}
	var plan []struct {
		Plan map[string]any `json:"Plan"`
	}
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}

	scan := findScan(plan[0].Plan, "sessions")
	if scan == nil {
		t.Fatalf("no scan on sessions in plan:\n%s", raw)
	}
	cond, _ := scan["Index Cond"].(string)
	if !strings.Contains(cond, "start_ms") {
		t.Fatalf("sessions scan %q has Index Cond %q, want the cursor's start_ms bound in it; plan:\n%s",
			scan["Node Type"], cond, raw)
	}
}

func findScan(node map[string]any, relation string) map[string]any {
	if node["Relation Name"] == relation {
		return node
	}
	children, _ := node["Plans"].([]any)
	for _, c := range children {
		if child, ok := c.(map[string]any); ok {
			if found := findScan(child, relation); found != nil {
				return found
			}
		}
	}
	return nil
}
