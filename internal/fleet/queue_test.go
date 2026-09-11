package fleet

import (
	"os"
	"path/filepath"
	"testing"
)

func TestQueueDrainRetriesOnlyUndeliveredLines(t *testing.T) {
	dir := t.TempDir()
	q, err := NewQueue(filepath.Join(dir, "sub", "queue.jsonl"), 0)
	if err != nil {
		t.Fatalf("NewQueue: %v", err)
	}

	for _, payload := range [][]byte{[]byte(`{"session_id":"a"}`), []byte(`{"session_id":"b"}`), []byte(`{"session_id":"c"}`)} {
		if err := q.Enqueue(payload); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}

	var sent []string
	failB := true
	err = q.Drain(func(payload []byte) error {
		sent = append(sent, string(payload))
		if failB && string(payload) == `{"session_id":"b"}` {
			return errFail
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	// Drain stops at the first transient failure: fleet being unreachable
	// means "c" would fail too, one timeout at a time.
	if len(sent) != 2 {
		t.Fatalf("expected the drain to stop at the failed line, got %d: %v", len(sent), sent)
	}

	// Second drain: "b" and "c" are both still queued, in order.
	failB = false
	sent = nil
	err = q.Drain(func(payload []byte) error {
		sent = append(sent, string(payload))
		return nil
	})
	if err != nil {
		t.Fatalf("Drain (2nd): %v", err)
	}
	want := []string{`{"session_id":"b"}`, `{"session_id":"c"}`}
	if !equalLines(sent, want) {
		t.Fatalf("second drain sent %v, want %v", sent, want)
	}

	// File should now be gone (queue fully drained).
	if _, err := os.Stat(q.path); !os.IsNotExist(err) {
		t.Fatalf("expected queue file removed after full drain, stat err = %v", err)
	}
}

func TestQueueDrainOnMissingFileIsNoop(t *testing.T) {
	dir := t.TempDir()
	q, err := NewQueue(filepath.Join(dir, "queue.jsonl"), 0)
	if err != nil {
		t.Fatalf("NewQueue: %v", err)
	}
	if err := q.Drain(func([]byte) error { return nil }); err != nil {
		t.Fatalf("Drain on missing file should be a no-op, got: %v", err)
	}
}

type failError struct{}

func (failError) Error() string { return "simulated send failure" }

var errFail = failError{}
