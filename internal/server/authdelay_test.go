package server

import (
	"testing"
	"time"
)

// Measured 2026-10-17 against ubuntu:22.04 openssh-server 8.9p1-3ubuntu0.18:
// a failed password took 2.34s for root, 2.90s for a real user and 3.65s for
// an unknown user, each with ~1ms spread across attempts; a success took
// ~87ms. A fresh random delay per attempt, or one on success, does not look
// like that.
func TestFailureDelayIsStablePerUserAndInRange(t *testing.T) {
	for _, user := range []string{"root", "admin", "ubuntu", "nosuchuser9", ""} {
		first := opensshAuthDelay(user, false)
		if first < 2300*time.Millisecond || first > 3710*time.Millisecond {
			t.Errorf("%q: %v outside 2.3-3.7s", user, first)
		}
		for i := 0; i < 50; i++ {
			d := opensshAuthDelay(user, false)
			if diff := d - first; diff > 10*time.Millisecond || diff < -10*time.Millisecond {
				t.Fatalf("%q: delay moved %v between attempts", user, diff)
			}
		}
	}
}

func TestFailureDelayDiffersAcrossUsers(t *testing.T) {
	seen := map[time.Duration]bool{}
	for _, user := range []string{"root", "admin", "ubuntu", "test", "oracle", "pi", "user", "guest"} {
		seen[opensshAuthDelay(user, false).Round(50*time.Millisecond)] = true
	}
	if len(seen) < 4 {
		t.Errorf("only %d distinct delays across 8 users", len(seen))
	}
}

func TestSuccessIsFast(t *testing.T) {
	for i := 0; i < 50; i++ {
		if d := opensshAuthDelay("root", true); d < 40*time.Millisecond || d > 50*time.Millisecond {
			t.Fatalf("success delay %v, want 42-47ms (plus ~45ms overhead = real sshd's ~90ms)", d)
		}
	}
}
