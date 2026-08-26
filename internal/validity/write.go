package validity

import (
	"database/sql"
	"time"
)

// WriteHeartbeat records one liveness row for sensorID at the current
// time. Meant to be called on a fixed ticker independent of session
// traffic -- see DetectHeartbeatGaps/ClassifySilence for what consumes it.
func WriteHeartbeat(db *sql.DB, sensorID string) error {
	_, err := db.Exec(`INSERT INTO sensor_heartbeats (sensor_id, ts) VALUES ($1, now())`, sensorID)
	return err
}

// StartHeartbeat launches a background goroutine that calls WriteHeartbeat
// every interval until the returned stop func is called. Write failures are
// passed to logf rather than treated as fatal -- a transient DB hiccup on a
// heartbeat write must never bring down the SSH listener it's monitoring.
func StartHeartbeat(db *sql.DB, sensorID string, interval time.Duration, logf func(format string, args ...any)) (stop func()) {
	ticker := time.NewTicker(interval)
	done := make(chan struct{})

	go func() {
		// Written immediately, not just on the first tick, so a fresh
		// deploy doesn't sit heartbeat-less for a full interval.
		if err := WriteHeartbeat(db, sensorID); err != nil {
			logf("validity: heartbeat write failed: %v", err)
		}
		for {
			select {
			case <-ticker.C:
				if err := WriteHeartbeat(db, sensorID); err != nil {
					logf("validity: heartbeat write failed: %v", err)
				}
			case <-done:
				return
			}
		}
	}()

	return func() {
		ticker.Stop()
		close(done)
	}
}
