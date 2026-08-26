package validity

import (
	"database/sql"
	"fmt"

	"github.com/lib/pq"
)

// AggregateStats is a headline view of the corpus, optionally with a set
// of source addresses excluded -- used to show whether check 3's detected
// campaign is masking the aggregate's real shape (audit §03: "the corpus
// is too class-skewed to train the neural stack" was measured against the
// whole corpus, campaign included).
type AggregateStats struct {
	TotalSessions       int
	ZeroCommandSessions int
	ZeroCommandPct      float64
}

// ComputeAggregateStats computes AggregateStats over all sessions, and
// again with excludeIPs removed. Passing a nil/empty excludeIPs makes the
// two results identical (there's no campaign to exclude yet, or none was
// detected).
func ComputeAggregateStats(db *sql.DB, excludeIPs []string) (all, excluding AggregateStats, err error) {
	row := db.QueryRow(`
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE command_count = 0)
		FROM sessions`)
	if err := row.Scan(&all.TotalSessions, &all.ZeroCommandSessions); err != nil {
		return AggregateStats{}, AggregateStats{}, fmt.Errorf("validity: computing aggregate stats: %w", err)
	}
	if all.TotalSessions > 0 {
		all.ZeroCommandPct = 100 * float64(all.ZeroCommandSessions) / float64(all.TotalSessions)
	}

	row = db.QueryRow(`
		SELECT
			COUNT(*) FILTER (WHERE NOT (client_ip = ANY($1))),
			COUNT(*) FILTER (WHERE command_count = 0 AND NOT (client_ip = ANY($1)))
		FROM sessions`,
		pq.Array(excludeIPs))
	if err := row.Scan(&excluding.TotalSessions, &excluding.ZeroCommandSessions); err != nil {
		return AggregateStats{}, AggregateStats{}, fmt.Errorf("validity: computing aggregate stats excluding campaign: %w", err)
	}
	if excluding.TotalSessions > 0 {
		excluding.ZeroCommandPct = 100 * float64(excluding.ZeroCommandSessions) / float64(excluding.TotalSessions)
	}

	return all, excluding, nil
}
