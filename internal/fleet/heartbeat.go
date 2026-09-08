package fleet

import "time"

// StartHeartbeat launches a background goroutine that, every interval,
// pushes a liveness ping and retries anything left in the local queue.
// Mirrors internal/validity.StartHeartbeat's shape; kept separate because
// this one drives an HTTP client with its own retry queue rather than a DB
// write, and disabling it (no MIRAGE_FLEET_URL/API_KEY) must cost nothing
// per tick beyond the two no-op calls -- see Client.enabled.
func StartHeartbeat(client *Client, interval time.Duration) (stop func()) {
	ticker := time.NewTicker(interval)
	done := make(chan struct{})

	tick := func() {
		client.PushHeartbeat()
		client.DrainQueue()
	}

	go func() {
		tick()
		for {
			select {
			case <-ticker.C:
				tick()
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
