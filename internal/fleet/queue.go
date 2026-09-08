package fleet

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Queue is an append-only JSONL file of session payloads that failed to
// reach mirage-fleet, replayed until they succeed. This -- not a database
// -- is the durable copy while mirage-fleet is unreachable: each line is
// one already-marshalled session.Session, one push attempt per line on
// Drain, kept in the file (in original order) if it fails again.
//
// A single mutex-guarded file is enough at this volume (one honeypot's
// worth of sessions); it is not meant to scale past one process writing to
// one file.
type Queue struct {
	path string
	mu   sync.Mutex
}

func NewQueue(path string) (*Queue, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("creating queue directory: %w", err)
	}
	return &Queue{path: path}, nil
}

func (q *Queue) Enqueue(payload []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	f, err := os.OpenFile(q.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("opening queue file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("appending to queue file: %w", err)
	}
	return nil
}

// Drain attempts send on every queued line once, in the order they were
// enqueued, and rewrites the file to contain only the lines that failed
// again. A crash mid-drain loses nothing already durable: the original file
// is only replaced after every line has been attempted.
func (q *Queue) Drain(send func(payload []byte) error) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	f, err := os.Open(q.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("opening queue file: %w", err)
	}

	var remaining [][]byte
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		if len(line) == 0 {
			continue
		}
		if err := send(line); err != nil {
			remaining = append(remaining, line)
		}
	}
	f.Close()
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading queue file: %w", err)
	}

	if len(remaining) == 0 {
		return os.Remove(q.path)
	}

	tmp := q.path + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("creating queue tmp file: %w", err)
	}
	for _, line := range remaining {
		if _, err := out.Write(append(line, '\n')); err != nil {
			out.Close()
			return fmt.Errorf("writing queue tmp file: %w", err)
		}
	}
	out.Close()
	return os.Rename(tmp, q.path)
}
