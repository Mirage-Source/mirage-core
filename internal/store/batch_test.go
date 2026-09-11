package store

import (
	"fmt"
	"strings"
	"testing"
)

func TestValuesClause(t *testing.T) {
	cases := []struct {
		rows, cols int
		want       string
	}{
		{1, 1, "($1)"},
		{1, 3, "($1,$2,$3)"},
		{3, 2, "($1,$2),($3,$4),($5,$6)"},
		{2, 6, "($1,$2,$3,$4,$5,$6),($7,$8,$9,$10,$11,$12)"},
		{0, 5, ""},
	}
	for _, tc := range cases {
		if got := valuesClause(tc.rows, tc.cols); got != tc.want {
			t.Errorf("valuesClause(%d, %d) = %q, want %q", tc.rows, tc.cols, got, tc.want)
		}
	}
}

// Placeholders must run 1..rows*cols with no gap or repeat, or a batch binds
// the wrong value to the wrong column.
func TestValuesClausePlaceholdersAreContiguous(t *testing.T) {
	const rows, cols = 500, 13
	clause := valuesClause(rows, cols)

	if got := strings.Count(clause, "("); got != rows {
		t.Fatalf("got %d row groups, want %d", got, rows)
	}
	for n := 1; n <= rows*cols; n++ {
		// Bounded on both sides so $1 does not match inside $10.
		if !strings.Contains(clause, fmt.Sprintf("$%d,", n)) && !strings.Contains(clause, fmt.Sprintf("$%d)", n)) {
			t.Fatalf("placeholder $%d is missing", n)
		}
	}
	if strings.Contains(clause, fmt.Sprintf("$%d", rows*cols+1)) {
		t.Errorf("placeholders run past %d", rows*cols)
	}
}

// The column lists and the counts passed to execBatch have to agree. If they
// drift -- someone adds a column and forgets to bump the count -- every value
// lands one column off, which Postgres accepts whenever the types happen to
// line up.
func TestBatchColumnCountsMatchTheirColumnLists(t *testing.T) {
	cases := []struct {
		name    string
		columns string
		cols    int
	}{
		{"auth_attempts", authAttemptColumns, 6},
		{"commands", commandColumns, 13},
		{"bait_interactions", baitColumns, 7},
	}
	for _, tc := range cases {
		got := len(strings.Split(tc.columns, ","))
		if got != tc.cols {
			t.Errorf("%s: column list names %d columns, execBatch is called with %d", tc.name, got, tc.cols)
		}
		for _, col := range strings.Split(tc.columns, ",") {
			if trimmed := strings.TrimSpace(col); trimmed == "" || strings.ContainsAny(trimmed, " \t") {
				t.Errorf("%s: %q is not a bare column name", tc.name, col)
			}
		}
	}
}

// A session's commands fit one statement; the chunking only matters if a cap
// ever grows past the parameter limit, so pin the arithmetic rather than
// discovering it then.
func TestBatchChunkingRespectsTheParameterLimit(t *testing.T) {
	const cols = 13
	perStatement := (maxBindParams / cols) * cols

	if perStatement > maxBindParams {
		t.Fatalf("a chunk of %d parameters exceeds the %d limit", perStatement, maxBindParams)
	}
	if perStatement%cols != 0 {
		t.Errorf("chunk of %d parameters is not a whole number of %d-column rows", perStatement, cols)
	}

	// 500 commands is the current per-session ceiling and must not chunk.
	if 500*cols > perStatement {
		t.Errorf("500 commands (%d parameters) no longer fits one statement", 500*cols)
	}
}
