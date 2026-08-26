package api

import (
	"time"

	"github.com/mirage-source/mirage-core/internal/validity"
)

// DailyRatePoint is one day's accept-rate observation, with an optional
// drift flag if that day fell outside its trailing band.
type DailyRatePoint struct {
	Date    string   `json:"date"`
	N       int      `json:"n"`
	Rate    float64  `json:"rate"`
	Flagged bool     `json:"flagged"`
	Mean    *float64 `json:"mean,omitempty"`
	StdDev  *float64 `json:"stddev,omitempty"`
}

// FieldCardinalityEntry is one watched field's current cardinality status.
type FieldCardinalityEntry struct {
	Table         string  `json:"table"`
	Column        string  `json:"column"`
	DistinctCount int     `json:"distinct_count"`
	ModalValue    string  `json:"modal_value"`
	ModalShare    float64 `json:"modal_share"`
	BaselineShare float64 `json:"baseline_modal_share"`
	Collapsed     bool    `json:"collapsed"`
}

// CampaignMemberEntry is one confirmed campaign member address.
type CampaignMemberEntry struct {
	IP           string `json:"ip"`
	Tier         int    `json:"tier"`
	SessionCount int    `json:"session_count"`
}

// AggregateStatsEntry is a headline corpus view, with or without the
// detected campaign excluded.
type AggregateStatsEntry struct {
	TotalSessions       int     `json:"total_sessions"`
	ZeroCommandSessions int     `json:"zero_command_sessions"`
	ZeroCommandPct      float64 `json:"zero_command_pct"`
}

// CampaignSection is check 3's full result: membership plus the
// aggregate-with-vs-without-campaign comparison.
type CampaignSection struct {
	Members               []CampaignMemberEntry `json:"members"`
	ExcludedCandidates    []string              `json:"excluded_candidates"`
	TotalCampaignSessions int                   `json:"total_campaign_sessions"`
	AggregateAll          AggregateStatsEntry   `json:"aggregate_all"`
	AggregateExcluding    AggregateStatsEntry   `json:"aggregate_excluding_campaign"`
}

// HeartbeatGapEntry is one detected downtime gap.
type HeartbeatGapEntry struct {
	Start           time.Time `json:"start"`
	End             time.Time `json:"end"`
	DurationSeconds float64   `json:"duration_seconds"`
}

// HeartbeatSection is check 4's full result.
type HeartbeatSection struct {
	Gaps          []HeartbeatGapEntry `json:"gaps"`
	LastHeartbeat *time.Time          `json:"last_heartbeat"`
}

// ValiditySummary is the full /api/validity/summary response.
type ValiditySummary struct {
	Sensor            string                  `json:"sensor"`
	ComputedAt        time.Time               `json:"computed_at"`
	AcceptRate        []DailyRatePoint        `json:"accept_rate"`
	AcceptRateFlagged int                     `json:"accept_rate_flagged_days"`
	FieldCardinality  []FieldCardinalityEntry `json:"field_cardinality"`
	Campaign          CampaignSection         `json:"campaign"`
	Heartbeat         HeartbeatSection        `json:"heartbeat"`
}

// NewValiditySummary converts the internal/validity domain result into the
// wire format. Kept as a separate conversion rather than putting json tags
// directly on internal/validity's types, since that package is meant to
// stay usable (and unit-testable) without any HTTP/JSON concern attached.
func NewValiditySummary(sensor string, s validity.Summary) ValiditySummary {
	flaggedDates := map[string]validity.BandDriftFlag{}
	for _, f := range s.AcceptRateFlags {
		flaggedDates[f.Date.Format("2006-01-02")] = f
	}

	rate := make([]DailyRatePoint, 0, len(s.AcceptRateSeries))
	for _, d := range s.AcceptRateSeries {
		key := d.Date.Format("2006-01-02")
		point := DailyRatePoint{Date: key, N: d.N, Rate: d.Rate}
		if f, ok := flaggedDates[key]; ok {
			point.Flagged = true
			mean, stddev := f.Mean, f.StdDev
			point.Mean, point.StdDev = &mean, &stddev
		}
		rate = append(rate, point)
	}

	fields := make([]FieldCardinalityEntry, 0, len(s.FieldCardinality))
	for _, fc := range s.FieldCardinality {
		fields = append(fields, FieldCardinalityEntry{
			Table:         fc.Field.Table,
			Column:        fc.Field.Column,
			DistinctCount: fc.Current.DistinctCount,
			ModalValue:    fc.Current.ModalValue,
			ModalShare:    fc.Current.ModalShare,
			BaselineShare: fc.Baseline.ModalShare,
			Collapsed:     fc.Collapsed,
		})
	}

	members := make([]CampaignMemberEntry, 0, len(s.Campaign.Members))
	for _, m := range s.Campaign.Members {
		members = append(members, CampaignMemberEntry{IP: m.IP, Tier: m.Tier, SessionCount: m.SessionCount})
	}

	gaps := make([]HeartbeatGapEntry, 0, len(s.HeartbeatGaps))
	for _, g := range s.HeartbeatGaps {
		gaps = append(gaps, HeartbeatGapEntry{Start: g.Start, End: g.End, DurationSeconds: g.Duration.Seconds()})
	}

	return ValiditySummary{
		Sensor:            sensor,
		ComputedAt:        s.ComputedAt,
		AcceptRate:        rate,
		AcceptRateFlagged: len(s.AcceptRateFlags),
		FieldCardinality:  fields,
		Campaign: CampaignSection{
			Members:               members,
			ExcludedCandidates:    s.Campaign.Excluded,
			TotalCampaignSessions: s.Campaign.TotalSessions(),
			AggregateAll: AggregateStatsEntry{
				TotalSessions: s.AggregateAll.TotalSessions, ZeroCommandSessions: s.AggregateAll.ZeroCommandSessions,
				ZeroCommandPct: s.AggregateAll.ZeroCommandPct,
			},
			AggregateExcluding: AggregateStatsEntry{
				TotalSessions: s.AggregateExcluding.TotalSessions, ZeroCommandSessions: s.AggregateExcluding.ZeroCommandSessions,
				ZeroCommandPct: s.AggregateExcluding.ZeroCommandPct,
			},
		},
		Heartbeat: HeartbeatSection{Gaps: gaps, LastHeartbeat: s.LastHeartbeat},
	}
}
