package fleet

import (
	"os"
	"path/filepath"
	"testing"
)

func TestQueueDrainRetriesOnlyFailedLines(t *testing.T) {
	dir := t.TempDir()
	q, err := NewQueue(filepath.Join(dir, "sub", "queue.jsonl"))
	if err != nil {
		t.Fatalf("NewQueue: %v", err)
	}

	for _, payload := range [][]byte{[]byte(`{"session_id":"a"}`), []byte(`{"session_id":"b"}`), []byte(`{"session_id":"c"}`)} {
		if err := q.Enqueue(payload); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}

	var sent []string
	err = q.Drain(func(payload []byte) error {
		sent = append(sent, string(payload))
		if string(payload) == `{"session_id":"b"}` {
			return errFail // "b" keeps failing
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(sent) != 3 {
		t.Fatalf("expected all 3 lines attempted once, got %d: %v", len(sent), sent)
	}

	// Second drain: only "b" should still be queued.
	sent = nil
	err = q.Drain(func(payload []byte) error {
		sent = append(sent, string(payload))
		return nil
	})
	if err != nil {
		t.Fatalf("Drain (2nd): %v", err)
	}
	if len(sent) != 1 || sent[0] != `{"session_id":"b"}` {
		t.Fatalf("expected only the previously-failed line retried, got %v", sent)
	}

	// File should now be gone (queue fully drained).
	if _, err := os.Stat(q.path); !os.IsNotExist(err) {
		t.Fatalf("expected queue file removed after full drain, stat err = %v", err)
	}
}

func TestQueueDrainOnMissingFileIsNoop(t *testing.T) {
	dir := t.TempDir()
	q, err := NewQueue(filepath.Join(dir, "queue.jsonl"))
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
