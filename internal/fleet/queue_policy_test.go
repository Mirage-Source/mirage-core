package fleet

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestQueue(t *testing.T) *Queue {
	t.Helper()
	q, err := NewQueue(filepath.Join(t.TempDir(), "queue.jsonl"), 0)
	if err != nil {
		t.Fatalf("NewQueue: %v", err)
	}
	return q
}

func enqueueAll(t *testing.T, q *Queue, payloads ...string) {
	t.Helper()
	for _, p := range payloads {
		if err := q.Enqueue([]byte(p)); err != nil {
			t.Fatalf("Enqueue(%s): %v", p, err)
		}
	}
}

func queuedLines(t *testing.T, q *Queue) []string {
	t.Helper()
	raw, err := os.ReadFile(q.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("reading queue file: %v", err)
	}
	trimmed := strings.TrimRight(string(raw), "\n")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

// Fleet rejecting a payload outright (400) will reject it every time. Retrying
// it forever on a 60s tick is what kept the old queue busy; it must be dropped
// and counted instead.
func TestDrainDropsPermanentFailuresAndCountsThem(t *testing.T) {
	q := newTestQueue(t)
	enqueueAll(t, q, `{"id":"a"}`, `{"id":"bad"}`, `{"id":"c"}`)

	var attempted []string
	err := q.Drain(func(payload []byte) error {
		attempted = append(attempted, string(payload))
		if strings.Contains(string(payload), "bad") {
			return PermanentError{Status: 400}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}

	if len(attempted) != 3 {
		t.Fatalf("expected all 3 attempted once, got %v", attempted)
	}
	if left := queuedLines(t, q); len(left) != 0 {
		t.Fatalf("expected an empty queue, still holds %v", left)
	}
	if got := q.Stats().DroppedPermanent; got != 1 {
		t.Errorf("DroppedPermanent = %d, want 1", got)
	}
}

// Fleet being unreachable means every remaining line will fail too. Attempting
// them all burns one timeout each while holding the queue lock.
func TestDrainStopsAtTheFirstTransientFailure(t *testing.T) {
	q := newTestQueue(t)
	enqueueAll(t, q, `{"id":"a"}`, `{"id":"b"}`, `{"id":"c"}`, `{"id":"d"}`)

	var attempted int
	err := q.Drain(func(payload []byte) error {
		attempted++
		if strings.Contains(string(payload), "b") {
			return fmt.Errorf("connection refused")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}

	if attempted != 2 {
		t.Errorf("attempted %d sends, want 2 (stop at the first transient failure)", attempted)
	}
	want := []string{`{"id":"b"}`, `{"id":"c"}`, `{"id":"d"}`}
	if got := queuedLines(t, q); !equalLines(got, want) {
		t.Errorf("queue = %v, want %v (failed line and everything after it, in order)", got, want)
	}
}

// Drain must not hold the lock across its sends, and anything enqueued while
// it runs must survive and stay ordered behind the undelivered lines.
func TestEnqueueDuringDrainIsNeitherBlockedNorLost(t *testing.T) {
	q := newTestQueue(t)
	enqueueAll(t, q, `{"id":"old-1"}`, `{"id":"old-2"}`)

	sending := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = q.Drain(func(payload []byte) error {
			once.Do(func() {
				close(sending)
				<-release
			})
			return fmt.Errorf("fleet is down")
		})
	}()

	<-sending
	done := make(chan error, 1)
	go func() { done <- q.Enqueue([]byte(`{"id":"new"}`)) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Enqueue during Drain: %v", err)
		}
	case <-time.After(2 * time.Second):
		close(release)
		wg.Wait()
		t.Fatal("Enqueue blocked while Drain was sending; the lock is held across network I/O")
	}

	close(release)
	wg.Wait()

	want := []string{`{"id":"old-1"}`, `{"id":"old-2"}`, `{"id":"new"}`}
	if got := queuedLines(t, q); !equalLines(got, want) {
		t.Errorf("queue = %v, want %v", got, want)
	}
}

// Fleet rejects a body over its own limit, so queueing one only buys a
// guaranteed-failing retry. Refuse it at the door and count it.
func TestEnqueueRejectsAnOversizedPayload(t *testing.T) {
	q := newTestQueue(t)
	oversized := append(bytes.Repeat([]byte("A"), maxPayloadBytes), 'B')

	if err := q.Enqueue(oversized); err != nil {
		t.Fatalf("Enqueue should drop an oversized payload, not error: %v", err)
	}
	if left := queuedLines(t, q); len(left) != 0 {
		t.Fatalf("oversized payload was queued anyway: %d line(s)", len(left))
	}
	if got := q.Stats().DroppedOversized; got != 1 {
		t.Errorf("DroppedOversized = %d, want 1", got)
	}
}

// The production case: a queue file written before the guard above existed can
// already hold a line longer than the reader's buffer. It must be skipped, not
// allowed to stall every later line behind it forever.
func TestDrainSkipsAnOversizedLineAlreadyOnDisk(t *testing.T) {
	q := newTestQueue(t)

	var file bytes.Buffer
	file.WriteString(`{"id":"before"}` + "\n")
	file.Write(append(bytes.Repeat([]byte("A"), maxPayloadBytes+64), '\n'))
	file.WriteString(`{"id":"after"}` + "\n")
	if err := os.WriteFile(q.path, file.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	var delivered []string
	if err := q.Drain(func(payload []byte) error {
		delivered = append(delivered, string(payload))
		return nil
	}); err != nil {
		t.Fatalf("Drain: %v", err)
	}

	want := []string{`{"id":"before"}`, `{"id":"after"}`}
	if !equalLines(delivered, want) {
		t.Errorf("delivered %v, want %v", delivered, want)
	}
	if got := q.Stats().DroppedOversized; got != 1 {
		t.Errorf("DroppedOversized = %d, want 1", got)
	}
}

// Fleet being down for a week must not fill the disk and take Postgres with
// it. Oldest goes first: local Postgres is authoritative, so the freshest
// undelivered data is the half worth keeping.
func TestEnqueueEvictsOldestOnceTheQueueIsFull(t *testing.T) {
	q := newTestQueue(t)
	q.maxBytes = 512

	payload := func(i int) string { return fmt.Sprintf(`{"id":%3d,"pad":"%s"}`, i, strings.Repeat("x", 40)) }
	for i := 0; i < 40; i++ {
		if err := q.Enqueue([]byte(payload(i))); err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
	}

	lines := queuedLines(t, q)
	if len(lines) == 0 {
		t.Fatal("queue is empty; eviction dropped everything")
	}

	var size int
	for _, l := range lines {
		size += len(l) + 1
	}
	if size > q.maxBytes {
		t.Errorf("queue is %d bytes, over the %d-byte bound", size, q.maxBytes)
	}
	if last := lines[len(lines)-1]; last != payload(39) {
		t.Errorf("newest line = %q, want %q (eviction took the newest, not the oldest)", last, payload(39))
	}
	if q.Stats().DroppedEvicted == 0 {
		t.Error("DroppedEvicted = 0, want the evicted lines counted")
	}
}

func equalLines(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// The classification that makes the drop policy work at all: a 4xx is fleet's
// final answer, a 5xx or a timeout is not.
func TestPostClassifies4xxAsPermanent(t *testing.T) {
	cases := []struct {
		status    int
		permanent bool
	}{
		{400, true}, {401, true}, {413, true}, {404, true},
		{408, false}, {429, false}, {500, false}, {502, false}, {503, false},
	}

	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
		}))
		c := NewClient(srv.URL, "test-key", 2*time.Second, nil)
		err := c.post("/v1/ingest/sessions", []byte(`{"session_id":"x"}`))
		srv.Close()

		if err == nil {
			t.Errorf("status %d: expected an error", tc.status)
			continue
		}
		var permanent PermanentError
		if got := errors.As(err, &permanent); got != tc.permanent {
			t.Errorf("status %d: permanent = %v, want %v (err: %v)", tc.status, got, tc.permanent, err)
		}
	}
}
