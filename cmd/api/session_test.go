package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const testKey = "test-api-key-0123456789"

func requestWithCookie(value string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	r.AddCookie(&http.Cookie{Name: dashboardCookie, Value: value})
	return r
}

func TestIssuedSessionVerifies(t *testing.T) {
	now := time.Now()
	value, maxAge := issueSession(testKey, now)

	if !validSession(testKey, value, now) {
		t.Error("a freshly issued session did not verify")
	}
	if maxAge != int(dashboardSessionTTL.Seconds()) {
		t.Errorf("maxAge = %d, want %d", maxAge, int(dashboardSessionTTL.Seconds()))
	}
}

func TestSessionExpires(t *testing.T) {
	now := time.Now()
	value, _ := issueSession(testKey, now)

	if validSession(testKey, value, now.Add(dashboardSessionTTL+time.Second)) {
		t.Error("an expired session still verifies")
	}
}

// The cookie is signed with API_KEY itself, so rotating the key must revoke
// every outstanding cookie without any server-side session store to clear.
func TestRotatingTheAPIKeyInvalidatesOutstandingSessions(t *testing.T) {
	now := time.Now()
	value, _ := issueSession(testKey, now)

	if validSession("a-different-key", value, now) {
		t.Error("a cookie issued under the old key still verifies after rotation")
	}
}

func TestForgedSessionsAreRejected(t *testing.T) {
	now := time.Now()
	valid, _ := issueSession(testKey, now)
	future := now.Add(dashboardSessionTTL).Unix()

	for name, token := range map[string]string{
		"empty":            "",
		"no separator":     "12345678901",
		"expiry only":      "99999999999",
		"unsigned":         "99999999999.",
		"bad signature":    "99999999999.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"non-numeric":      "later." + signSession(testKey, future),
		"signature reused": "99999999999." + signSession(testKey, future),
	} {
		if validSession(testKey, token, now) {
			t.Errorf("%s: forged token accepted", name)
		}
	}

	if !validSession(testKey, valid, now) {
		t.Error("the control token should still verify")
	}
}

// The whole point of the change: a key in a URL lands in access logs, shell
// history, browser history and any Referer the page emits.
func TestAPIKeyInTheQueryStringIsNotAccepted(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/stats?api_key="+testKey, nil)
	if authenticate(r, testKey, time.Now()) {
		t.Error("?api_key= still authenticates")
	}
}

func TestAuthenticateAcceptsHeaderBearerAndCookie(t *testing.T) {
	now := time.Now()
	value, _ := issueSession(testKey, now)

	header := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	header.Header.Set("X-API-Key", testKey)
	if !authenticate(header, testKey, now) {
		t.Error("X-API-Key was rejected")
	}

	bearer := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	bearer.Header.Set("Authorization", "Bearer "+testKey)
	if !authenticate(bearer, testKey, now) {
		t.Error("Authorization: Bearer was rejected")
	}

	if !authenticate(requestWithCookie(value), testKey, now) {
		t.Error("a valid dashboard cookie was rejected")
	}
}

func TestAuthenticateRejectsWrongCredentials(t *testing.T) {
	now := time.Now()

	bad := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	bad.Header.Set("X-API-Key", "wrong")
	if authenticate(bad, testKey, now) {
		t.Error("a wrong key authenticated")
	}

	if authenticate(httptest.NewRequest(http.MethodGet, "/api/stats", nil), testKey, now) {
		t.Error("a request with no credentials authenticated")
	}

	stale, _ := issueSession(testKey, now.Add(-2*dashboardSessionTTL))
	if authenticate(requestWithCookie(stale), testKey, now) {
		t.Error("an expired cookie authenticated")
	}
}

func TestGateRedirectsBrowsersAndRejectsAPICallers(t *testing.T) {
	reached := false
	handler := gate(testKey)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	cases := []struct {
		name, method, path string
		want               int
	}{
		{"dashboard navigation", http.MethodGet, "/dashboard", http.StatusSeeOther},
		{"api call", http.MethodGet, "/api/stats", http.StatusUnauthorized},
		{"api write", http.MethodPut, "/api/config", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		reached = false
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, w.Code, tc.want)
		}
		if reached {
			t.Errorf("%s: reached the handler unauthenticated", tc.name)
		}
	}

	// With a cookie, the same navigation goes through.
	value, _ := issueSession(testKey, time.Now())
	reached = false
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: dashboardCookie, Value: value})
	handler.ServeHTTP(w, r)
	if !reached {
		t.Errorf("an authenticated dashboard request was blocked (status %d)", w.Code)
	}
}
