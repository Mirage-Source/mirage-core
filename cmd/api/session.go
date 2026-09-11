package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The dashboard is a plain browser navigation, which cannot set X-API-Key.
// That used to be served by accepting ?api_key= on every route, which put the
// key into access logs, shell history, browser history and any Referer the
// page emits. Instead POST /dashboard/login trades the key once for a
// short-lived HttpOnly cookie, and the key never appears in a URL.
const dashboardCookie = "mirage_dashboard"

const dashboardSessionTTL = 12 * time.Hour

// signSession derives the cookie's key from API_KEY itself, so there is no
// second secret to configure or rotate: changing API_KEY invalidates every
// outstanding cookie, which is the behaviour you want from a key rotation.
func signSession(apiKey string, expiry int64) string {
	mac := hmac.New(sha256.New, []byte(apiKey))
	mac.Write([]byte(strconv.FormatInt(expiry, 10)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func issueSession(apiKey string, now time.Time) (value string, maxAge int) {
	expiry := now.Add(dashboardSessionTTL).Unix()
	return strconv.FormatInt(expiry, 10) + "." + signSession(apiKey, expiry), int(dashboardSessionTTL.Seconds())
}

func validSession(apiKey, token string, now time.Time) bool {
	expiry, sig, found := strings.Cut(token, ".")
	if !found {
		return false
	}
	exp, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil || now.Unix() >= exp {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sig), []byte(signSession(apiKey, exp))) == 1
}

// authenticate reports whether a request carries either the API key or a valid
// dashboard cookie.
func authenticate(r *http.Request, apiKey string, now time.Time) bool {
	presented := r.Header.Get("X-API-Key")
	if presented == "" {
		presented = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if presented != "" && subtle.ConstantTimeCompare([]byte(presented), []byte(apiKey)) == 1 {
		return true
	}

	cookie, err := r.Cookie(dashboardCookie)
	return err == nil && validSession(apiKey, cookie.Value, now)
}

// gate rejects anything without the key or a valid cookie. A browser
// navigating to the dashboard is sent to the login form instead of a bare
// 401, which it has no way to act on.
func gate(apiKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if authenticate(r, apiKey, time.Now()) {
				next.ServeHTTP(w, r)
				return
			}
			if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/dashboard") {
				http.Redirect(w, r, "/dashboard/login", http.StatusSeeOther)
				return
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		})
	}
}

// loginPage is the one thing an unauthenticated browser may see: a form that
// POSTs the key so it lands in a request body rather than a URL.
var loginPage = []byte(`<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>MIRAGE</title>
<style>
  body{background:#0d1117;color:#c9d1d9;font:15px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;
       display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
  form{display:flex;flex-direction:column;gap:.75rem;width:min(22rem,90vw)}
  h1{font-size:1rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;margin:0 0 .25rem}
  input,button{font:inherit;padding:.6rem .7rem;border-radius:3px;border:1px solid #30363d}
  input{background:#010409;color:#c9d1d9}
  button{background:#1f6feb;border-color:#1f6feb;color:#fff;cursor:pointer}
</style>
<form method="post" action="/dashboard/login">
  <h1>MIRAGE</h1>
  <label for="k">API key</label>
  <input id="k" name="api_key" type="password" autocomplete="current-password" autofocus>
  <button type="submit">Sign in</button>
</form>
`)
