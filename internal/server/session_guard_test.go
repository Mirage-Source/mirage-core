package server

import (
	"sync"
	"testing"

	"github.com/mirage-source/mirage-core/internal/session"
	"github.com/mirage-source/mirage-core/internal/shell"
)

// Regression test for the cross-channel session race: multiple SSH "session"
// channels on one connection used to append to sess.Commands concurrently
// with no synchronization, corrupting the slice and letting two channels be
// assigned the same SequenceNumber (which then violated the DB's
// UNIQUE(session_id, sequence_number) constraint). Run with -race.
func TestSessionGuardConcurrentAppendCommand(t *testing.T) {
	guard := &sessionGuard{sess: &session.Session{}}

	const goroutines = 20
	const perGoroutine = 25

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				guard.appendCommand(session.Command{
					EventID:     "evt",
					TimestampMS: int64(i),
				}, true)
			}
		}()
	}
	wg.Wait()

	total := goroutines * perGoroutine
	if got := guard.commandCount(); got != total {
		t.Fatalf("expected %d commands, got %d (lost appends under concurrency)", total, got)
	}

	seen := make(map[int]bool, total)
	for _, cmd := range guard.sess.Commands {
		if seen[cmd.SequenceNumber] {
			t.Fatalf("duplicate sequence number %d assigned to two channels", cmd.SequenceNumber)
		}
		seen[cmd.SequenceNumber] = true
	}
	for i := 0; i < total; i++ {
		if !seen[i] {
			t.Fatalf("missing sequence number %d", i)
		}
	}
}

func TestSessionGuardAppendBaitEventsConcurrent(t *testing.T) {
	guard := &sessionGuard{sess: &session.Session{}}

	const goroutines = 15
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			guard.appendBaitEvents("evt", []shell.BaitHit{
				{BaitID: "home-env-file", BaitType: session.BaitTypeEnvFile, AccessType: session.AccessTypeRead},
			})
		}()
	}
	wg.Wait()

	if got := len(guard.sess.BaitEvents); got != goroutines {
		t.Fatalf("expected %d bait events, got %d (lost appends under concurrency)", goroutines, got)
	}
}

func TestSessionGuardRecordOutcomeFirstWins(t *testing.T) {
	guard := &sessionGuard{sess: &session.Session{Outcome: session.OutcomeActive}}

	outcomes := []session.Outcome{
		session.OutcomeCleanDisconnect,
		session.OutcomeTimeout,
		session.OutcomeConnectionReset,
	}

	var wg sync.WaitGroup
	for _, o := range outcomes {
		wg.Add(1)
		go func(o session.Outcome) {
			defer wg.Done()
			guard.recordOutcome(o)
		}(o)
	}
	wg.Wait()

	if guard.sess.Outcome == session.OutcomeActive {
		t.Fatal("outcome was never recorded")
	}
	if guard.sess.Timing.EndMS == nil {
		t.Fatal("EndMS was never set")
	}

	// A second call after a terminal outcome is already set must be a no-op.
	guard.recordOutcome(session.OutcomeAuthFailed)
	if guard.sess.Outcome == session.OutcomeAuthFailed {
		t.Fatal("recordOutcome overwrote an already-recorded terminal outcome")
	}
}
