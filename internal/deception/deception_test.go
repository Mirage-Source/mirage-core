package deception

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/mirage-source/mirage-core/internal/shell"
)

func TestConfigFromEnvDefaultsToDisabled(t *testing.T) {
	for _, key := range []string{
		"MIRAGE_DECEPTION_ENABLED",
		"MIRAGE_DECEPTION_URL",
		"MIRAGE_DECEPTION_TIMEOUT_MS",
		"MIRAGE_DECEPTION_APPLY_ACTIONS",
	} {
		os.Unsetenv(key)
	}

	cfg := ConfigFromEnv()
	if cfg.Enabled {
		t.Errorf("Enabled = true, want false (must default off)")
	}
	if cfg.ApplyActions {
		t.Errorf("ApplyActions = true, want false (must default to shadow mode)")
	}
	if cfg.BaseURL != defaultBaseURL {
		t.Errorf("BaseURL = %q, want %q", cfg.BaseURL, defaultBaseURL)
	}
	if cfg.Timeout != defaultTimeout {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout, defaultTimeout)
	}
}

func TestConfigFromEnvReadsOverrides(t *testing.T) {
	t.Setenv("MIRAGE_DECEPTION_ENABLED", "true")
	t.Setenv("MIRAGE_DECEPTION_URL", "http://deception-svc:9000")
	t.Setenv("MIRAGE_DECEPTION_TIMEOUT_MS", "500")
	t.Setenv("MIRAGE_DECEPTION_APPLY_ACTIONS", "1")

	cfg := ConfigFromEnv()
	if !cfg.Enabled {
		t.Errorf("Enabled = false, want true")
	}
	if !cfg.ApplyActions {
		t.Errorf("ApplyActions = false, want true")
	}
	if cfg.BaseURL != "http://deception-svc:9000" {
		t.Errorf("BaseURL = %q, want override", cfg.BaseURL)
	}
	if cfg.Timeout != 500*time.Millisecond {
		t.Errorf("Timeout = %v, want 500ms", cfg.Timeout)
	}
}

func TestConfigFromEnvIgnoresGarbageValues(t *testing.T) {
	t.Setenv("MIRAGE_DECEPTION_ENABLED", "not-a-bool")
	t.Setenv("MIRAGE_DECEPTION_TIMEOUT_MS", "not-a-number")

	cfg := ConfigFromEnv()
	if cfg.Enabled {
		t.Errorf("Enabled = true for garbage input, want fallback false")
	}
	if cfg.Timeout != defaultTimeout {
		t.Errorf("Timeout = %v for garbage input, want fallback %v", cfg.Timeout, defaultTimeout)
	}
}

func TestNewRuntimeNeverReturnsNil(t *testing.T) {
	rt := NewRuntime(Config{})
	if rt == nil {
		t.Fatal("NewRuntime(Config{}) = nil, want a non-nil Runtime with everything off -- the console's Control tab needs a live target to flip on later")
	}
	if rt.PolicyEnabled.Load() {
		t.Error("PolicyEnabled = true, want false for a zero-value Config")
	}
	if rt.ApplyActions.Load() {
		t.Error("ApplyActions = true, want false for a zero-value Config")
	}
}

func TestRuntimeFlagsToggleAfterConstruction(t *testing.T) {
	rt := NewRuntime(Config{Enabled: false, ApplyActions: false})

	rt.PolicyEnabled.Store(true)
	if !rt.PolicyEnabled.Load() {
		t.Error("PolicyEnabled did not stick after Store(true) -- this is exactly what watchRuntimeFlags relies on to apply a console toggle without a restart")
	}

	rt.ApplyActions.Store(true)
	if !rt.ApplyActions.Load() {
		t.Error("ApplyActions did not stick after Store(true)")
	}
}

func TestApplyStallAddsDelayLeavesResponseUnchanged(t *testing.T) {
	response, code, delay := Apply(ActionStall, "hello", 0)
	if response != "hello" || code != 0 {
		t.Errorf("Apply(STALL) changed response/code: got (%q, %d)", response, code)
	}
	if delay < 200*time.Millisecond || delay > 900*time.Millisecond {
		t.Errorf("Apply(STALL) delay = %v, want in [200ms, 900ms]", delay)
	}
}

func TestApplyFakeSuccessOverridesFailingExitCode(t *testing.T) {
	response, code, delay := Apply(ActionFakeSuccess, "bash: foo: command not found", 127)
	if code != 0 {
		t.Errorf("Apply(FAKE_SUCCESS) code = %d, want 0", code)
	}
	if response != "" {
		t.Errorf("Apply(FAKE_SUCCESS) response = %q, want empty", response)
	}
	if delay != 0 {
		t.Errorf("Apply(FAKE_SUCCESS) delay = %v, want 0", delay)
	}
}

func TestApplyFakeSuccessLeavesAlreadySuccessfulCommandsAlone(t *testing.T) {
	response, code, _ := Apply(ActionFakeSuccess, "output", 0)
	if response != "output" || code != 0 {
		t.Errorf("Apply(FAKE_SUCCESS) on already-successful command changed it: (%q, %d)", response, code)
	}
}

func TestApplyFakeSuccessNeverOverridesExitSentinel(t *testing.T) {
	// This is the one behavior that must never regress: FAKE_SUCCESS must not
	// rewrite the "attacker typed exit" sentinel to 0, or sessions would never
	// close on exit while this action happened to be selected.
	response, code, _ := Apply(ActionFakeSuccess, "", shell.ExitRequested)
	if code != shell.ExitRequested {
		t.Errorf("Apply(FAKE_SUCCESS) overrode ExitRequested: code = %d, want %d", code, shell.ExitRequested)
	}
	_ = response
}

func TestApplyPassthroughActions(t *testing.T) {
	for _, action := range []string{ActionMinimal, ActionEnrich, ActionSurfaceBait, "", "totally-unknown-action"} {
		response, code, delay := Apply(action, "unchanged", 42)
		if response != "unchanged" || code != 42 || delay != 0 {
			t.Errorf("Apply(%q) = (%q, %d, %v), want passthrough (\"unchanged\", 42, 0)", action, response, code, delay)
		}
	}
}

func TestClientDecideSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req decideRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.SessionID != "sess-1" || req.Command != "cat /etc/shadow" || !req.BaitHit {
			t.Errorf("unexpected request body: %+v", req)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(decideResponse{ActionName: ActionSurfaceBait, Category: "read_sensitive"})
	}))
	defer srv.Close()

	client := NewClient(Config{BaseURL: srv.URL, Timeout: time.Second})
	decision, err := client.Decide("sess-1", "cat /etc/shadow", true)
	if err != nil {
		t.Fatalf("Decide returned error: %v", err)
	}
	if decision.Action != ActionSurfaceBait || decision.Category != "read_sensitive" {
		t.Errorf("Decide() = %+v, want {SURFACE_BAIT read_sensitive}", decision)
	}
}

func TestClientDecideFailsSafeOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := NewClient(Config{BaseURL: srv.URL, Timeout: time.Second})
	decision, err := client.Decide("sess-1", "ls", false)
	if err == nil {
		t.Fatal("Decide() returned nil error on HTTP 500, want non-nil")
	}
	if decision.Action != ActionMinimal {
		t.Errorf("Decide() fallback action = %q, want MINIMAL", decision.Action)
	}
}

func TestClientDecideFailsSafeOnMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{not json"))
	}))
	defer srv.Close()

	client := NewClient(Config{BaseURL: srv.URL, Timeout: time.Second})
	decision, err := client.Decide("sess-1", "ls", false)
	if err == nil {
		t.Fatal("Decide() returned nil error on malformed JSON, want non-nil")
	}
	if decision.Action != ActionMinimal {
		t.Errorf("Decide() fallback action = %q, want MINIMAL", decision.Action)
	}
}

func TestClientDecideFailsSafeOnConnectionRefused(t *testing.T) {
	// Port 1 is reserved and nothing should be listening there.
	client := NewClient(Config{BaseURL: "http://127.0.0.1:1", Timeout: 200 * time.Millisecond})
	decision, err := client.Decide("sess-1", "ls", false)
	if err == nil {
		t.Fatal("Decide() returned nil error on connection refused, want non-nil")
	}
	if decision.Action != ActionMinimal {
		t.Errorf("Decide() fallback action = %q, want MINIMAL", decision.Action)
	}
}

func TestClientDecideFailsSafeOnTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(decideResponse{ActionName: ActionEnrich})
	}))
	defer srv.Close()

	client := NewClient(Config{BaseURL: srv.URL, Timeout: 10 * time.Millisecond})
	decision, err := client.Decide("sess-1", "ls", false)
	if err == nil {
		t.Fatal("Decide() returned nil error on timeout, want non-nil")
	}
	if decision.Action != ActionMinimal {
		t.Errorf("Decide() fallback action = %q, want MINIMAL", decision.Action)
	}
}
