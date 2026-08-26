package deception

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientCompleteSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req completeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.SessionID != "sess-1" || req.Command != "uptime" {
			t.Errorf("unexpected request body: %+v", req)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(completeResponse{
			Available: true,
			Output:    " 09:14:02 up 41 days,  3:11,  1 user,  load average: 0.08, 0.03, 0.01",
			ExitCode:  0,
		})
	}))
	defer srv.Close()

	client := NewClient(Config{BaseURL: srv.URL, CompletionTimeout: time.Second})
	out, code, ok := client.Complete("sess-1", "uptime")
	if !ok {
		t.Fatal("Complete() ok = false, want true")
	}
	if code != 0 {
		t.Errorf("Complete() code = %d, want 0", code)
	}
	if out == "" {
		t.Error("Complete() returned empty output on success")
	}
}

// TestClientCompleteRespectsAvailableFalse covers the service's own
// backpressure: budget exhausted, circuit breaker open, or no provider
// configured all come back as HTTP 200 with available=false, which must be
// treated as "fall back to command not found", not as output.
func TestClientCompleteRespectsAvailableFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(completeResponse{Available: false})
	}))
	defer srv.Close()

	client := NewClient(Config{BaseURL: srv.URL, CompletionTimeout: time.Second})
	if _, _, ok := client.Complete("sess-1", "uptime"); ok {
		t.Error("Complete() ok = true for available=false, want false")
	}
}

func TestClientCompleteRejectsEmptyOutput(t *testing.T) {
	// available=true with nothing to show is not a usable completion; the
	// attacker would see a blank line where a real tool prints something.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(completeResponse{Available: true, Output: "   "})
	}))
	defer srv.Close()

	client := NewClient(Config{BaseURL: srv.URL, CompletionTimeout: time.Second})
	if _, _, ok := client.Complete("sess-1", "uptime"); ok {
		t.Error("Complete() ok = true for blank output, want false")
	}
}

func TestClientCompleteFailsSafeOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := NewClient(Config{BaseURL: srv.URL, CompletionTimeout: time.Second})
	if _, _, ok := client.Complete("sess-1", "uptime"); ok {
		t.Error("Complete() ok = true on HTTP 500, want false")
	}
}

func TestClientCompleteFailsSafeOnMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{not json"))
	}))
	defer srv.Close()

	client := NewClient(Config{BaseURL: srv.URL, CompletionTimeout: time.Second})
	if _, _, ok := client.Complete("sess-1", "uptime"); ok {
		t.Error("Complete() ok = true on malformed JSON, want false")
	}
}

func TestClientCompleteFailsSafeOnConnectionRefused(t *testing.T) {
	// Port 1 is reserved and nothing should be listening there.
	client := NewClient(Config{BaseURL: "http://127.0.0.1:1", CompletionTimeout: 200 * time.Millisecond})
	if _, _, ok := client.Complete("sess-1", "uptime"); ok {
		t.Error("Complete() ok = true on connection refused, want false")
	}
}

// TestClientCompleteFailsSafeOnTimeout is the case that matters most on the
// live path: a slow provider must not hold an attacker's shell open past the
// configured budget, it must give up and let the ordinary path answer.
func TestClientCompleteFailsSafeOnTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		json.NewEncoder(w).Encode(completeResponse{Available: true, Output: "too late"})
	}))
	defer srv.Close()

	client := NewClient(Config{BaseURL: srv.URL, CompletionTimeout: 50 * time.Millisecond})
	start := time.Now()
	_, _, ok := client.Complete("sess-1", "uptime")
	elapsed := time.Since(start)

	if ok {
		t.Error("Complete() ok = true past its timeout, want false")
	}
	if elapsed > 400*time.Millisecond {
		t.Errorf("Complete() took %v, want it to abandon the call near its 50ms budget", elapsed)
	}
}

// TestCompleteUsesCompletionTimeoutNotPolicyTimeout locks in the two-client
// split: a completion that takes longer than the (much tighter) policy
// budget must still succeed.
func TestCompleteUsesCompletionTimeoutNotPolicyTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(120 * time.Millisecond)
		json.NewEncoder(w).Encode(completeResponse{Available: true, Output: "ok", ExitCode: 0})
	}))
	defer srv.Close()

	client := NewClient(Config{
		BaseURL:           srv.URL,
		Timeout:           20 * time.Millisecond,
		CompletionTimeout: 2 * time.Second,
	})
	if _, _, ok := client.Complete("sess-1", "uptime"); !ok {
		t.Error("Complete() ok = false -- it appears to be using the policy timeout")
	}
}
