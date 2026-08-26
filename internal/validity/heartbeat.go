package validity

import (
	"sort"
	"time"
)

// Gap is one period during which no heartbeat was observed for longer than
// expected. End equals the `now` passed to DetectHeartbeatGaps when the gap
// is still ongoing (no heartbeat has closed it yet).
type Gap struct {
	Start    time.Time
	End      time.Time
	Duration time.Duration
}

// DetectHeartbeatGaps finds gaps between consecutive heartbeats (which
// need not be pre-sorted -- this sorts a copy) exceeding
// expectedInterval*tolerance, including a final ongoing gap if `now` is
// further past the last heartbeat than that threshold. Returns nil for
// fewer than one heartbeat -- with no data at all there's nothing to
// measure a gap against.
func DetectHeartbeatGaps(heartbeats []time.Time, expectedInterval time.Duration, tolerance float64, now time.Time) []Gap {
	if len(heartbeats) == 0 {
		return nil
	}
	sorted := append([]time.Time(nil), heartbeats...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Before(sorted[j]) })

	threshold := time.Duration(float64(expectedInterval) * tolerance)

	var gaps []Gap
	for i := 1; i < len(sorted); i++ {
		if d := sorted[i].Sub(sorted[i-1]); d > threshold {
			gaps = append(gaps, Gap{Start: sorted[i-1], End: sorted[i], Duration: d})
		}
	}
	last := sorted[len(sorted)-1]
	if d := now.Sub(last); d > threshold {
		gaps = append(gaps, Gap{Start: last, End: now, Duration: d})
	}
	return gaps
}

// SilenceClassification is the result of ClassifySilence.
type SilenceClassification string

const (
	// SilenceDowntime means the sensor's own heartbeat stream also had a
	// gap overlapping this period -- the silence is (at least partly)
	// explained by the sensor being down, not by an absence of attackers.
	SilenceDowntime SilenceClassification = "downtime"
	// SilenceGenuine means the heartbeat stream had no gap overlapping
	// this period -- the sensor was up throughout; nobody connected.
	SilenceGenuine SilenceClassification = "genuine"
)

// ClassifySilence reports whether a period of zero session arrivals
// [start, end) is explained by sensor downtime (any overlap with a
// heartbeat gap) or is genuine silence (the sensor was up the whole time).
func ClassifySilence(start, end time.Time, gaps []Gap) SilenceClassification {
	for _, g := range gaps {
		if start.Before(g.End) && g.Start.Before(end) {
			return SilenceDowntime
		}
	}
	return SilenceGenuine
}
