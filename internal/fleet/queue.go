package fleet

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// Queue is an append-only JSONL file of session payloads that failed to reach
// mirage-fleet, replayed until they succeed. This -- not a database -- is the
// durable copy while mirage-fleet is unreachable: each line is one
// already-marshalled session.Session.
//
// Three policies, all of them deliberate (see DECISIONS.md):
//
//   - A payload mirage-fleet will never accept is dropped and counted, not
//     retried forever. Both flavours count: one larger than fleet's own body
//     limit, and one it answers with a 4xx.
//   - The file is bounded. Past maxBytes the oldest lines are evicted, since
//     the local Postgres is authoritative and the freshest undelivered data is
//     the half worth keeping.
//   - Drain claims the file by rename and sends outside the lock, so a long
//     retry run can never block Enqueue -- which runs on the session
//     finalization path, holding a connection slot.
type Queue struct {
	path     string
	maxBytes int

	mu sync.Mutex

	// Only one drain may hold the claimed file at a time; a second would
	// process the same lines concurrently and double-send them.
	draining atomic.Bool

	droppedPermanent atomic.Int64
	droppedOversized atomic.Int64
	droppedEvicted   atomic.Int64
}

// maxPayloadBytes must not exceed mirage-fleet's own request body limit
// (internal/api/handlers.go, maxBodyBytes) -- anything larger is rejected
// there, so queueing it only buys a guaranteed-failing retry.
const maxPayloadBytes = 1 << 20

const defaultMaxQueueBytes = 64 << 20

// PermanentError marks a response mirage-fleet will give again for the same
// payload, so the payload is dropped rather than retried.
type PermanentError struct{ Status int }

func (e PermanentError) Error() string {
	return fmt.Sprintf("permanently rejected with status %d", e.Status)
}

type Stats struct {
	DroppedPermanent int64
	DroppedOversized int64
	DroppedEvicted   int64
}

// NewQueue bounds the file at maxBytes, or defaultMaxQueueBytes when maxBytes
// is not positive.
func NewQueue(path string, maxBytes int) (*Queue, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("creating queue directory: %w", err)
	}
	if maxBytes <= 0 {
		maxBytes = defaultMaxQueueBytes
	}
	return &Queue{path: path, maxBytes: maxBytes}, nil
}

func (q *Queue) Stats() Stats {
	return Stats{
		DroppedPermanent: q.droppedPermanent.Load(),
		DroppedOversized: q.droppedOversized.Load(),
		DroppedEvicted:   q.droppedEvicted.Load(),
	}
}

// countPermanentDrop records a payload rejected on its first attempt, so it
// lands in the same tally as one dropped during a drain.
func (q *Queue) countPermanentDrop() { q.droppedPermanent.Add(1) }

func (q *Queue) Enqueue(payload []byte) error {
	if len(payload) > maxPayloadBytes {
		q.droppedOversized.Add(1)
		return nil
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	f, err := os.OpenFile(q.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("opening queue file: %w", err)
	}
	if _, err := f.Write(append(payload, '\n')); err != nil {
		f.Close()
		return fmt.Errorf("appending to queue file: %w", err)
	}
	size, statErr := f.Seek(0, io.SeekCurrent)
	f.Close()
	if statErr != nil || int(size) <= q.maxBytes {
		return nil
	}
	return q.evictOldestLocked()
}

// evictOldestLocked rewrites the file without its oldest lines, down to 80% of
// the bound so compaction is amortised rather than run on every append.
func (q *Queue) evictOldestLocked() error {
	target := q.maxBytes * 4 / 5

	in, err := os.Open(q.path)
	if err != nil {
		return fmt.Errorf("opening queue file for eviction: %w", err)
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return fmt.Errorf("sizing queue file: %w", err)
	}

	skip := info.Size() - int64(target)
	r := bufio.NewReader(in)
	var evicted int64
	for skip > 0 {
		_, consumed, _, err := readRecord(r)
		if err != nil {
			break
		}
		skip -= consumed
		evicted++
	}

	tmp := q.path + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("creating queue tmp file: %w", err)
	}
	if _, err := io.Copy(out, r); err != nil {
		out.Close()
		return fmt.Errorf("writing queue tmp file: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("closing queue tmp file: %w", err)
	}
	if err := os.Rename(tmp, q.path); err != nil {
		return fmt.Errorf("replacing queue file: %w", err)
	}

	q.droppedEvicted.Add(evicted)
	return nil
}

// Drain attempts every queued line in order, stopping at the first transient
// failure -- mirage-fleet being unreachable means the rest would fail too, one
// timeout at a time.
//
// The file is claimed by rename first, so sends happen with no lock held and
// Enqueue stays available throughout. Whatever was not delivered is put back
// ahead of anything enqueued in the meantime, preserving order.
func (q *Queue) Drain(send func(payload []byte) error) error {
	if !q.draining.CompareAndSwap(false, true) {
		return nil
	}
	defer q.draining.Store(false)

	claimed, err := q.claim()
	if err != nil || claimed == "" {
		return err
	}

	remaining, err := q.sendClaimed(claimed, send)
	if err != nil {
		return err
	}
	return q.restore(claimed, remaining)
}

// claim atomically moves the live file aside. Enqueue immediately starts a
// fresh one, so nothing written during the drain lands in the claimed copy.
func (q *Queue) claim() (string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	claimed := q.path + ".draining"
	if _, err := os.Stat(claimed); err == nil {
		// A previous drain died mid-flight; its file is still the oldest data.
		return claimed, nil
	}
	if err := os.Rename(q.path, claimed); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("claiming queue file: %w", err)
	}
	return claimed, nil
}

// sendClaimed returns the offset of the first line not delivered, or -1 when
// every line was accounted for.
func (q *Queue) sendClaimed(claimed string, send func(payload []byte) error) (int64, error) {
	f, err := os.Open(claimed)
	if err != nil {
		return -1, fmt.Errorf("opening claimed queue file: %w", err)
	}
	defer f.Close()

	r := bufio.NewReader(f)
	var offset int64
	for {
		line, consumed, oversized, err := readRecord(r)
		if err == io.EOF {
			return -1, nil
		}
		if err != nil {
			return offset, fmt.Errorf("reading queue file: %w", err)
		}

		if oversized {
			q.droppedOversized.Add(1)
			offset += consumed
			continue
		}
		if len(line) == 0 {
			offset += consumed
			continue
		}

		if err := send(line); err != nil {
			var permanent PermanentError
			if errors.As(err, &permanent) {
				q.droppedPermanent.Add(1)
				offset += consumed
				continue
			}
			return offset, nil
		}
		offset += consumed
	}
}

// restore puts the undelivered tail back at the head of the live file, then
// drops the claimed copy.
func (q *Queue) restore(claimed string, from int64) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if from < 0 {
		return os.Remove(claimed)
	}

	undelivered, err := os.Open(claimed)
	if err != nil {
		return fmt.Errorf("reopening claimed queue file: %w", err)
	}
	defer undelivered.Close()
	if _, err := undelivered.Seek(from, io.SeekStart); err != nil {
		return fmt.Errorf("seeking claimed queue file: %w", err)
	}

	tmp := q.path + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("creating queue tmp file: %w", err)
	}
	if _, err := io.Copy(out, undelivered); err != nil {
		out.Close()
		return fmt.Errorf("restoring undelivered lines: %w", err)
	}
	if live, err := os.Open(q.path); err == nil {
		_, err = io.Copy(out, live)
		live.Close()
		if err != nil {
			out.Close()
			return fmt.Errorf("appending newer lines: %w", err)
		}
	} else if !os.IsNotExist(err) {
		out.Close()
		return fmt.Errorf("opening live queue file: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("closing queue tmp file: %w", err)
	}
	if err := os.Rename(tmp, q.path); err != nil {
		return fmt.Errorf("replacing queue file: %w", err)
	}
	return os.Remove(claimed)
}

// readRecord reads one newline-terminated record, bounded. A longer record is
// reported as oversized and its bytes discarded -- bufio.Scanner's ErrTooLong
// gave no way to skip past one, so a single long line stalled every line
// behind it permanently. consumed counts the bytes the record occupied on
// disk, newline included, so callers can track file offsets across a skip.
func readRecord(r *bufio.Reader) (line []byte, consumed int64, oversized bool, err error) {
	for {
		chunk, chunkErr := r.ReadSlice('\n')
		line = append(line, chunk...)

		switch chunkErr {
		case nil:
			consumed = int64(len(line))
			return trimNewline(line), consumed, len(line)-1 > maxPayloadBytes, nil

		case bufio.ErrBufferFull:
			if len(line) <= maxPayloadBytes {
				continue
			}
			skipped, skipErr := discardRecord(r)
			return nil, int64(len(line)) + skipped, true, skipErr

		case io.EOF:
			if len(line) == 0 {
				return nil, 0, false, io.EOF
			}
			// A trailing record with no newline: it occupies exactly its own
			// length on disk.
			return line, int64(len(line)), len(line) > maxPayloadBytes, nil

		default:
			return nil, 0, false, chunkErr
		}
	}
}

// discardRecord drops bytes up to and including the next newline, returning
// how many it consumed.
func discardRecord(r *bufio.Reader) (int64, error) {
	var consumed int64
	for {
		chunk, err := r.ReadSlice('\n')
		consumed += int64(len(chunk))
		switch err {
		case nil, io.EOF:
			return consumed, nil
		case bufio.ErrBufferFull:
			continue
		default:
			return consumed, err
		}
	}
}

func trimNewline(line []byte) []byte {
	if n := len(line); n > 0 && line[n-1] == '\n' {
		return line[:n-1]
	}
	return line
}
