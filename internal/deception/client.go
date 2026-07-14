package deception

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// Action names, matching mirage.deception.actions.DeceptionAction exactly
// (see ml/mirage/deception/actions.py). Kept as strings across the wire
// (rather than the enum's integer index) so the two sides can evolve
// independently without a silent index-mismatch bug.
const (
	ActionMinimal     = "MINIMAL"
	ActionEnrich      = "ENRICH"
	ActionSurfaceBait = "SURFACE_BAIT"
	ActionStall       = "STALL"
	ActionFakeSuccess = "FAKE_SUCCESS"
)

// Decision is the inference service's answer for one command.
type Decision struct {
	Action   string `json:"action_name"`
	Category string `json:"category"`
}

// Runtime bundles a Client with whether its decisions are allowed to alter
// shell output (Config.ApplyActions) -- the one value internal/server needs
// to thread through its connection-handling call chain. A nil *Runtime means
// "the feature is off", and every call site in internal/server treats that
// as "behave exactly as before this package existed".
type Runtime struct {
	Client       *Client
	ApplyActions bool
}

// NewRuntime returns nil if cfg.Enabled is false, so callers can construct it
// once at startup and pass the (possibly nil) result down unconditionally.
func NewRuntime(cfg Config) *Runtime {
	if !cfg.Enabled {
		return nil
	}
	return &Runtime{Client: NewClient(cfg), ApplyActions: cfg.ApplyActions}
}

// Client calls the deception inference service (ml/mirage/deception/serve.py).
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// NewClient builds a Client from Config. Callers should only construct one
// when Config.Enabled is true; a nil *Client is treated as "disabled" by
// every call site in internal/server, so there is no need for a separate
// no-op implementation.
func NewClient(cfg Config) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: cfg.Timeout},
		baseURL:    cfg.BaseURL,
	}
}

type decideRequest struct {
	SessionID string `json:"session_id"`
	Command   string `json:"command"`
	BaitHit   bool   `json:"bait_hit"`
}

type decideResponse struct {
	ActionName string `json:"action_name"`
	Category   string `json:"category"`
}

// Decide asks the inference service how to respond to one command.
//
// On ANY failure -- the service is down, the call times out, the response is
// malformed -- Decide fails safe: it returns Decision{Action: ActionMinimal}
// (today's exact behavior) plus a non-nil error for the caller to log. The
// live shell must never depend on this call succeeding, and callers should
// never treat a returned error as fatal.
func (c *Client) Decide(sessionID, command string, baitHit bool) (Decision, error) {
	fallback := Decision{Action: ActionMinimal}

	body, err := json.Marshal(decideRequest{SessionID: sessionID, Command: command, BaitHit: baitHit})
	if err != nil {
		return fallback, fmt.Errorf("deception: marshal request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/decide", bytes.NewReader(body))
	if err != nil {
		return fallback, fmt.Errorf("deception: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fallback, fmt.Errorf("deception: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fallback, fmt.Errorf("deception: service returned status %d", resp.StatusCode)
	}

	var decoded decideResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return fallback, fmt.Errorf("deception: decode response: %w", err)
	}
	if decoded.ActionName == "" {
		decoded.ActionName = ActionMinimal
	}
	return Decision{Action: decoded.ActionName, Category: decoded.Category}, nil
}
