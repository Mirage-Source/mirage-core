// Package deception talks to the Python deception-policy inference service
// (ml/mirage/deception/serve.py) and turns its decisions into concrete
// changes to a command's response.
//
// Disabled by default: nothing about the live shell's behavior changes unless
// MIRAGE_DECEPTION_ENABLED is explicitly set. When enabled, every call fails
// safe -- any error, timeout, or malformed response from the inference
// service falls back to ActionMinimal, today's exact behavior -- because the
// honeypot must keep working perfectly well whether or not the Python
// service is up.
//
// Two independent knobs, intentionally separate:
//
//   - MIRAGE_DECEPTION_ENABLED -- whether to call the inference service and
//     record its decision at all (the "is the brain wired in" switch).
//   - MIRAGE_DECEPTION_APPLY_ACTIONS -- whether a decision is allowed to
//     change shell output/timing (the "is the brain allowed to act" switch).
//
// Running with ENABLED=true, APPLY_ACTIONS=false is "shadow mode": every
// command gets a real decision from the trained policy, and it is logged
// against the session (see session.Command.DeceptionAction) for later
// analysis, but the attacker sees exactly the same shell they always have.
// That is the recommended way to turn this on for the first time on a
// server that is already live and being watched.
package deception

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config controls whether/how the server calls out to the inference service.
type Config struct {
	Enabled      bool
	BaseURL      string
	Timeout      time.Duration
	ApplyActions bool
}

const (
	defaultBaseURL = "http://127.0.0.1:8787"
	defaultTimeout = 200 * time.Millisecond
)

// ConfigFromEnv reads MIRAGE_DECEPTION_* environment variables. Every
// variable has a safe (disabled/no-op) default, so an operator who has never
// heard of this feature sees no change at all.
func ConfigFromEnv() Config {
	return Config{
		Enabled:      envBool("MIRAGE_DECEPTION_ENABLED", false),
		BaseURL:      envString("MIRAGE_DECEPTION_URL", defaultBaseURL),
		Timeout:      envMillis("MIRAGE_DECEPTION_TIMEOUT_MS", defaultTimeout),
		ApplyActions: envBool("MIRAGE_DECEPTION_APPLY_ACTIONS", false),
	}
}

func envBool(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func envString(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}

func envMillis(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	ms, err := strconv.Atoi(v)
	if err != nil || ms <= 0 {
		return fallback
	}
	return time.Duration(ms) * time.Millisecond
}
