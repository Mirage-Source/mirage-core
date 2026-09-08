// Package fleet pushes this sensor's session and heartbeat data to a
// central mirage-fleet instance, so multiple mirage-core deployments can be
// seen individually and consolidated from one place. See mirage-fleet's
// CLAUDE.md/DECISIONS.md (sibling repo) for why it's shaped this way.
//
// Off by default, and fails safe when on: mirage-fleet being slow,
// unreachable, or never configured must never affect what mirage-core does
// locally -- same principle as deception.Client failing safe to
// ActionMinimal on any error. A Client with no baseURL/apiKey configured is
// a no-op on every method.
package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/mirage-source/mirage-core/internal/session"
)

type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
	queue   *Queue
}

// NewClient returns a Client. baseURL/apiKey empty means disabled -- every
// method becomes a no-op rather than erroring, so callers don't need to
// branch on whether fleet push is configured.
func NewClient(baseURL, apiKey string, timeout time.Duration, queue *Queue) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		http:    &http.Client{Timeout: timeout},
		queue:   queue,
	}
}

func (c *Client) enabled() bool {
	return c.baseURL != "" && c.apiKey != ""
}

// PushSession sends one finished session to mirage-fleet. On any failure
// (network, timeout, non-2xx) the payload is handed to the local retry
// queue instead of being dropped -- see DECISIONS.md "delivery reliability"
// in mirage-fleet. Never returns an error: callers (session finalization)
// must not be slowed down or blocked by fleet's availability.
func (c *Client) PushSession(sess *session.Session) {
	if !c.enabled() {
		return
	}
	body, err := json.Marshal(sess)
	if err != nil {
		log.Printf("fleet: marshalling session %s: %v", sess.SessionID, err)
		return
	}
	if err := c.post("/v1/ingest/sessions", body); err != nil {
		log.Printf("fleet: pushing session %s failed, queuing for retry: %v", sess.SessionID, err)
		if qerr := c.queue.Enqueue(body); qerr != nil {
			log.Printf("fleet: queuing session %s also failed: %v", sess.SessionID, qerr)
		}
	}
}

// PushHeartbeat sends one liveness ping. Unlike sessions, a missed
// heartbeat is not queued for replay -- by the time a retry would land, the
// gap it would have covered has already passed, and mirage-fleet's own
// downtime detection (mirroring mirage-core's local
// internal/validity.HeartbeatGapCheck) is what a missed beat is meant to
// surface in the first place.
func (c *Client) PushHeartbeat() {
	if !c.enabled() {
		return
	}
	if err := c.post("/v1/ingest/heartbeat", nil); err != nil {
		log.Printf("fleet: pushing heartbeat failed: %v", err)
	}
}

// DrainQueue retries every queued session once. Meant to be called on a
// ticker independent of new session traffic.
func (c *Client) DrainQueue() {
	if !c.enabled() {
		return
	}
	if err := c.queue.Drain(func(payload []byte) error {
		return c.post("/v1/ingest/sessions", payload)
	}); err != nil {
		log.Printf("fleet: draining retry queue: %v", err)
	}
}

func (c *Client) post(path string, body []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.http.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}
