package validity

import (
	"math"
	"time"
)

// DailyRate is one day's observation of a rate-valued field (e.g. auth
// success rate, or a session-outcome share) for band-drift detection.
// Callers are expected to supply one entry per calendar day, sorted
// ascending by Date, with no gaps -- DetectBandDrift doesn't validate
// either property.
type DailyRate struct {
	Date time.Time
	N    int // total observations that day, informational only
	Rate float64
}

// BandDriftFlag marks one day whose rate fell outside the band implied by
// its own trailing history.
type BandDriftFlag struct {
	Date   time.Time
	Rate   float64
	Mean   float64
	StdDev float64
}

// DetectBandDrift flags each day whose Rate falls outside mean ±
// sigma*stddev of the `window` days strictly before it. Days with fewer
// than minWindow prior observations are skipped (not enough history to
// judge yet).
//
// The band is self-referential -- built from the field's own recent
// history, not a hardcoded "should be X%" -- so this needs no
// honeypot-specific domain knowledge and generalizes to any rate-valued
// field. When the trailing window has zero variance (every prior day was
// identical), any deviation at all is flagged rather than divided by a
// zero stddev: a field that's been perfectly constant and then moves (or
// vice versa) is exactly the corruption shape this check exists to catch.
//
// Known limitation: once a corrupted run is longer than `window` days,
// the trailing window eventually consists entirely of corrupted days and
// stops flagging further days in that same run as anomalous -- only the
// transition day(s) at each boundary are guaranteed to be caught. That
// still catches a bug at the moment it starts, which is what makes this
// different from the ad hoc single-threshold check it replaces.
func DetectBandDrift(series []DailyRate, window int, sigma float64, minWindow int) []BandDriftFlag {
	var flags []BandDriftFlag
	for i, d := range series {
		start := i - window
		if start < 0 {
			start = 0
		}
		trailing := series[start:i]
		if len(trailing) < minWindow {
			continue
		}
		mean, stddev := meanStdDev(trailing)
		deviation := d.Rate - mean
		if stddev == 0 {
			if deviation != 0 {
				flags = append(flags, BandDriftFlag{Date: d.Date, Rate: d.Rate, Mean: mean, StdDev: stddev})
			}
			continue
		}
		if z := math.Abs(deviation / stddev); z > sigma {
			flags = append(flags, BandDriftFlag{Date: d.Date, Rate: d.Rate, Mean: mean, StdDev: stddev})
		}
	}
	return flags
}

func meanStdDev(rates []DailyRate) (mean, stddev float64) {
	n := float64(len(rates))
	sum := 0.0
	for _, r := range rates {
		sum += r.Rate
	}
	mean = sum / n

	variance := 0.0
	for _, r := range rates {
		d := r.Rate - mean
		variance += d * d
	}
	variance /= n
	return mean, math.Sqrt(variance)
}
