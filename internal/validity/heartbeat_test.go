package validity

import (
	"testing"
	"time"
)

func t0() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

func minutes(n int) time.Duration { return time.Duration(n) * time.Minute }

func TestDetectHeartbeatGapsRegularHeartbeatsNoGaps(t *testing.T) {
	base := t0()
	var beats []time.Time
	for i := 0; i < 20; i++ {
		beats = append(beats, base.Add(time.Duration(i)*time.Minute))
	}
	now := base.Add(minutes(19))
	gaps := DetectHeartbeatGaps(beats, time.Minute, 3, now)
	if len(gaps) != 0 {
		t.Errorf("gaps = %v, want none for regular 1-minute heartbeats", gaps)
	}
}

func TestDetectHeartbeatGapsFindsAClosedGap(t *testing.T) {
	base := t0()
	beats := []time.Time{
		base,
		base.Add(minutes(1)),
		base.Add(minutes(2)),
		base.Add(minutes(12)), // 10-minute gap after the 2-minute mark
		base.Add(minutes(13)),
	}
	now := base.Add(minutes(13))
	gaps := DetectHeartbeatGaps(beats, time.Minute, 3, now)
	if len(gaps) != 1 {
		t.Fatalf("gaps = %v, want exactly 1", gaps)
	}
	g := gaps[0]
	if !g.Start.Equal(base.Add(minutes(2))) || !g.End.Equal(base.Add(minutes(12))) {
		t.Errorf("gap = %+v, want start=%v end=%v", g, base.Add(minutes(2)), base.Add(minutes(12)))
	}
	if g.Duration != minutes(10) {
		t.Errorf("gap.Duration = %v, want 10m", g.Duration)
	}
}

func TestDetectHeartbeatGapsFindsAnOngoingGap(t *testing.T) {
	base := t0()
	beats := []time.Time{base, base.Add(minutes(1))}
	now := base.Add(minutes(30)) // sensor hasn't reported in 29 minutes
	gaps := DetectHeartbeatGaps(beats, time.Minute, 3, now)
	if len(gaps) != 1 {
		t.Fatalf("gaps = %v, want exactly 1 (ongoing)", gaps)
	}
	g := gaps[0]
	if !g.Start.Equal(base.Add(minutes(1))) || !g.End.Equal(now) {
		t.Errorf("gap = %+v, want start=%v end(now)=%v", g, base.Add(minutes(1)), now)
	}
}

func TestDetectHeartbeatGapsEmptyInput(t *testing.T) {
	gaps := DetectHeartbeatGaps(nil, time.Minute, 3, t0())
	if len(gaps) != 0 {
		t.Errorf("gaps = %v, want none for no heartbeat data", gaps)
	}
}

func TestClassifySilenceDowntimeWhenFullyInsideAGap(t *testing.T) {
	base := t0()
	gaps := []Gap{{Start: base, End: base.Add(minutes(10)), Duration: minutes(10)}}
	got := ClassifySilence(base.Add(minutes(2)), base.Add(minutes(8)), gaps)
	if got != SilenceDowntime {
		t.Errorf("ClassifySilence = %v, want %v", got, SilenceDowntime)
	}
}

func TestClassifySilenceGenuineWhenNoOverlappingGap(t *testing.T) {
	base := t0()
	gaps := []Gap{{Start: base, End: base.Add(minutes(10)), Duration: minutes(10)}}
	got := ClassifySilence(base.Add(minutes(20)), base.Add(minutes(25)), gaps)
	if got != SilenceGenuine {
		t.Errorf("ClassifySilence = %v, want %v", got, SilenceGenuine)
	}
}

func TestClassifySilenceDowntimeOnPartialOverlap(t *testing.T) {
	base := t0()
	gaps := []Gap{{Start: base, End: base.Add(minutes(10)), Duration: minutes(10)}}
	got := ClassifySilence(base.Add(minutes(5)), base.Add(minutes(15)), gaps)
	if got != SilenceDowntime {
		t.Errorf("ClassifySilence = %v, want %v", got, SilenceDowntime)
	}
}
