package validity

import (
	"testing"
	"time"
)

func day(offset int) time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, offset)
}

func TestDetectBandDriftSkipsDaysWithoutEnoughHistory(t *testing.T) {
	series := []DailyRate{
		{Date: day(0), N: 100, Rate: 0.02},
		{Date: day(1), N: 100, Rate: 0.90}, // would be a huge outlier, but only 1 prior day
	}
	flags := DetectBandDrift(series, 30, 3, 5)
	if len(flags) != 0 {
		t.Errorf("flags = %v, want none (insufficient trailing history)", flags)
	}
}

func TestDetectBandDriftStableSeriesNoFlags(t *testing.T) {
	series := make([]DailyRate, 0, 20)
	rates := []float64{0.02, 0.03, 0.02, 0.025, 0.018, 0.022, 0.03}
	for i := 0; i < 20; i++ {
		series = append(series, DailyRate{Date: day(i), N: 500, Rate: rates[i%len(rates)]})
	}
	flags := DetectBandDrift(series, 10, 3, 5)
	if len(flags) != 0 {
		t.Errorf("flags = %v, want none for a stable oscillating series", flags)
	}
}

func TestDetectBandDriftFlagsAClearOutlier(t *testing.T) {
	series := make([]DailyRate, 0, 15)
	for i := 0; i < 14; i++ {
		series = append(series, DailyRate{Date: day(i), N: 500, Rate: 0.02})
	}
	// Day 14: rate jumps far outside the (near-zero-variance) trailing band.
	series = append(series, DailyRate{Date: day(14), N: 500, Rate: 0.60})

	flags := DetectBandDrift(series, 10, 3, 5)
	if len(flags) != 1 {
		t.Fatalf("flags = %v, want exactly 1", flags)
	}
	if !flags[0].Date.Equal(day(14)) {
		t.Errorf("flagged date = %v, want %v", flags[0].Date, day(14))
	}
}

func TestDetectBandDriftFlagsTheDayTrafficGoesSilentlyFlat(t *testing.T) {
	// Mirrors the shape of the preprint's bug: a field that's been varying
	// normally suddenly locks to one constant value. The transition day
	// must be flagged even though, once inside the flat run, later days
	// eventually stop looking anomalous against an all-flat trailing window
	// -- a known, documented limitation of a rolling-window control chart,
	// not something this test claims to fix.
	series := make([]DailyRate, 0, 40)
	for i := 0; i < 20; i++ {
		rate := 0.02 + 0.01*float64(i%2) // oscillates 0.02/0.03
		series = append(series, DailyRate{Date: day(i), N: 500, Rate: rate})
	}
	for i := 20; i < 30; i++ {
		series = append(series, DailyRate{Date: day(i), N: 500, Rate: 0.0}) // silently flat
	}

	flags := DetectBandDrift(series, 10, 3, 5)
	if len(flags) == 0 {
		t.Fatalf("flags = none, want at least the transition day (%v) flagged", day(20))
	}
	if !flags[0].Date.Equal(day(20)) {
		t.Errorf("first flagged date = %v, want %v (the transition into the flat run)", flags[0].Date, day(20))
	}
}

func TestDetectBandDriftZeroVarianceHistoryFlagsAnyDeviation(t *testing.T) {
	series := make([]DailyRate, 0, 11)
	for i := 0; i < 10; i++ {
		series = append(series, DailyRate{Date: day(i), N: 500, Rate: 0.0})
	}
	series = append(series, DailyRate{Date: day(10), N: 500, Rate: 0.001})

	flags := DetectBandDrift(series, 10, 3, 5)
	if len(flags) != 1 || !flags[0].Date.Equal(day(10)) {
		t.Errorf("flags = %v, want day 10 flagged (any deviation from a zero-variance history)", flags)
	}
}
