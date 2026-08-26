package validity

import (
	"database/sql"
	"time"
)

// FieldCardinalityStatus is one watched field's current cardinality check
// result.
type FieldCardinalityStatus struct {
	Field     FieldSpec
	Current   CardinalityResult
	Baseline  CardinalityResult
	Collapsed bool
}

// Summary is the full computed state of all four validity checks for one
// sensor, meant to be cached and served rather than recomputed per
// request -- campaign decomposition alone is an O(sessions) scan.
type Summary struct {
	ComputedAt time.Time

	AcceptRateSeries []DailyRate
	AcceptRateFlags  []BandDriftFlag

	FieldCardinality []FieldCardinalityStatus

	Campaign           CampaignResult
	CampaignTiers      map[int]TierStats
	AggregateAll       AggregateStats
	AggregateExcluding AggregateStats

	HeartbeatGaps []Gap
	LastHeartbeat *time.Time
}

// Compute runs all four checks against db for sensorID as of `now` and
// returns one Summary.
func Compute(db *sql.DB, sensorID string, now time.Time) (Summary, error) {
	series, err := FetchDailyAuthSuccessRate(db, 90)
	if err != nil {
		return Summary{}, err
	}
	flags := DetectBandDrift(series, 14, 3, 7)

	fields := make([]FieldCardinalityStatus, 0, len(WatchedFields))
	for _, spec := range WatchedFields {
		baselineCounts, err := FetchFieldCounts(db, spec, now.AddDate(0, 0, -14), now.AddDate(0, 0, -7))
		if err != nil {
			return Summary{}, err
		}
		currentCounts, err := FetchFieldCounts(db, spec, now.AddDate(0, 0, -7), now)
		if err != nil {
			return Summary{}, err
		}
		baseline := AssessCardinality(baselineCounts)
		current := AssessCardinality(currentCounts)
		fields = append(fields, FieldCardinalityStatus{
			Field: spec, Current: current, Baseline: baseline,
			Collapsed: DetectCardinalityCollapse(baseline, current, 0.99),
		})
	}

	sessionCounts, credentialPairSets, err := FetchCampaignInputs(db)
	if err != nil {
		return Summary{}, err
	}
	campaign, err := DetectCampaign(sessionCounts, credentialPairSets, WordlistLen)
	if err != nil {
		return Summary{}, err
	}
	aggAll, aggExcluding, err := ComputeAggregateStats(db, campaign.IPs())
	if err != nil {
		return Summary{}, err
	}

	heartbeats, err := FetchHeartbeats(db, sensorID, now.AddDate(0, 0, -30))
	if err != nil {
		return Summary{}, err
	}
	gaps := DetectHeartbeatGaps(heartbeats, 60*time.Second, 5, now)
	var lastHeartbeat *time.Time
	if len(heartbeats) > 0 {
		last := heartbeats[len(heartbeats)-1]
		lastHeartbeat = &last
	}

	return Summary{
		ComputedAt:         now,
		AcceptRateSeries:   series,
		AcceptRateFlags:    flags,
		FieldCardinality:   fields,
		Campaign:           campaign,
		CampaignTiers:      campaign.TierSummary(),
		AggregateAll:       aggAll,
		AggregateExcluding: aggExcluding,
		HeartbeatGaps:      gaps,
		LastHeartbeat:      lastHeartbeat,
	}, nil
}
