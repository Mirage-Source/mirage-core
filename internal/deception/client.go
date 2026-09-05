package deception

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
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

// Runtime bundles a Client with the switches internal/server needs to thread
// through its connection-handling call chain.
//
// PolicyEnabled and ApplyActions are atomic.Bool, not plain bool: the
// operator console's Control tab can flip either one live (see
// internal/store's runtime_flags table and the poller started in
// internal/server.Start), so any goroutine handling an in-flight command can
// observe a change made mid-session, with no restart. CompletionEnabled
// (the separate LLM shell-completion fallback) is not part of that toggle
// yet and stays a plain bool, fixed at startup.
//
// A *Runtime is never nil once constructed by NewRuntime -- constructing it
// is what makes a later live PolicyEnabled/ApplyActions flip possible even
// when both started false, so "everything off" is represented by the atomic
// bools being false, not by the pointer being nil.
type Runtime struct {
	Client            *Client
	PolicyEnabled     atomic.Bool
	ApplyActions      atomic.Bool
	CompletionEnabled bool
}

// NewRuntime always returns a non-nil Runtime; see the type doc for why.
func NewRuntime(cfg Config) *Runtime {
	rt := &Runtime{
		Client:            NewClient(cfg),
		CompletionEnabled: cfg.CompletionEnabled,
	}
	rt.PolicyEnabled.Store(cfg.Enabled)
	rt.ApplyActions.Store(cfg.ApplyActions)
	return rt
}

// Client calls the deception inference service (ml/mirage/deception/serve.py).
//
// Two HTTP clients, not one: the policy call must stay on a tight budget
// (200ms by default) because it happens on every single command, while a
// completion call is a model round trip and needs seconds. Sharing one
// client would force the slower of the two budgets onto both.
type Client struct {
	httpClient       *http.Client
	completionClient *http.Client
	baseURL          string
}

// NewClient builds a Client from Config. Callers should only construct one
// when at least one feature is enabled; a nil *Client is treated as
// "disabled" by every call site in internal/server, so there is no need for
// a separate no-op implementation.
func NewClient(cfg Config) *Client {
	return &Client{
		httpClient:       &http.Client{Timeout: cfg.Timeout},
		completionClient: &http.Client{Timeout: cfg.CompletionTimeout},
		baseURL:          cfg.BaseURL,
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

type completeRequest struct {
	SessionID string `json:"session_id"`
	Command   string `json:"command"`
}

type completeResponse struct {
	Available bool   `json:"available"`
	Output    string `json:"output"`
	ExitCode  int    `json:"exit_code"`
}

// Complete asks the service for plausible output for one command the shell
// has no builtin for.
//
// ok is false for every reason a completion might not happen -- the service
// is down, the call times out, the response is malformed, the provider
// failed, a budget is exhausted, the circuit breaker is open, or the model
// returned nothing usable. There is deliberately no error return: at every
// call site the response to "no completion" is identical (fall through to
// the interpreter's ordinary command-not-found path), so distinguishing the
// reasons would only invite a caller to treat one of them as fatal. The
// service logs the specific cause on its own side.
func (c *Client) Complete(sessionID, command string) (output string, exitCode int, ok bool) {
	body, err := json.Marshal(completeRequest{SessionID: sessionID, Command: command})
	if err != nil {
		return "", 0, false
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/complete", bytes.NewReader(body))
	if err != nil {
		return "", 0, false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.completionClient.Do(req)
	if err != nil {
		return "", 0, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, false
	}

	var decoded completeResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return "", 0, false
	}
	if !decoded.Available || strings.TrimSpace(decoded.Output) == "" {
		return "", 0, false
	}
	return decoded.Output, decoded.ExitCode, true
}

// ErrUnknownProvider means the named provider is not configured on the
// service -- an operator mistake (a typo, or a stale dashboard listing),
// not a failure of the service itself. Callers should report it as a bad
// request rather than an upstream error.
var ErrUnknownProvider = errors.New("deception: unknown provider")

// Providers fetches the completion service's provider listing (which is
// configured, which is active, and live counters) for the dashboard.
//
// Unlike Decide/Complete this is an operator-facing call, not one on the
// attacker's path, so it returns a real error for the dashboard to surface
// instead of silently degrading. The payload is passed through as raw JSON:
// the API layer only relays it, and re-declaring the service's response
// shape in Go would mean two places to edit every time a counter is added.
func (c *Client) Providers() (json.RawMessage, error) {
	resp, err := c.httpClientFor(c.completionClient).Get(c.baseURL + "/llm-providers")
	if err != nil {
		return nil, fmt.Errorf("deception: provider listing request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("deception: provider listing returned status %d", resp.StatusCode)
	}
	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("deception: decode provider listing: %w", err)
	}
	return raw, nil
}

// SetActiveProvider switches which configured provider serves completions.
func (c *Client) SetActiveProvider(name string) (json.RawMessage, error) {
	body, err := json.Marshal(map[string]string{"name": name})
	if err != nil {
		return nil, fmt.Errorf("deception: marshal provider switch: %w", err)
	}
	resp, err := c.httpClientFor(c.completionClient).Post(
		c.baseURL+"/llm-providers/active", "application/json", bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("deception: provider switch request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusBadRequest {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, name)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("deception: provider switch returned status %d", resp.StatusCode)
	}
	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("deception: decode provider switch response: %w", err)
	}
	return raw, nil
}

// httpClientFor guards against a zero-value Config leaving a client with no
// timeout at all -- an admin call with no deadline could hang a dashboard
// request indefinitely.
func (c *Client) httpClientFor(preferred *http.Client) *http.Client {
	if preferred != nil && preferred.Timeout > 0 {
		return preferred
	}
	return &http.Client{Timeout: 10 * time.Second}
}
