package main

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mirage-source/mirage-core/internal/api"
	"github.com/mirage-source/mirage-core/internal/deception"
	"github.com/mirage-source/mirage-core/internal/store"
	"github.com/mirage-source/mirage-core/internal/validity"
)

// validityCache holds the last computed ValiditySummary per sensor.
// Populated by a background ticker (see refreshValidity below), never
// computed inline in a request handler -- campaign decomposition alone is
// an O(sessions) scan over the whole corpus, and a dashboard load must
// stay fast regardless of corpus size.
type validityCache struct {
	mu   sync.RWMutex
	data map[string]api.ValiditySummary
}

func (c *validityCache) get(sensor string) (api.ValiditySummary, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.data[sensor]
	return s, ok
}

func (c *validityCache) set(sensor string, s api.ValiditySummary) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.data == nil {
		c.data = map[string]api.ValiditySummary{}
	}
	c.data[sensor] = s
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("encoding JSON response: %v", err)
	}
}

func main() {
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		log.Fatal("API_KEY environment variable is required")
	}

	db, err := store.Connect()
	if err != nil {
		log.Fatalf("connecting to database: %v", err)
	}
	defer db.Close()

	sensors, err := store.LoadSensors(db)
	if err != nil {
		log.Fatalf("loading sensor configuration: %v", err)
	}
	if len(sensors) == 0 {
		log.Fatal("no sensors configured; every route below is keyed on at least one")
	}
	sensorNames := make([]string, len(sensors))
	for i, s := range sensors {
		sensorNames[i] = s.Name
	}

	vcache := &validityCache{}
	refreshValidity := func() {
		for _, sn := range sensors {
			summary, err := validity.Compute(sn.DB, sn.Name, time.Now())
			if err != nil {
				log.Printf("computing validity summary for sensor %q: %v", sn.Name, err)
				continue
			}
			vcache.set(sn.Name, api.NewValiditySummary(sn.Name, summary))
		}
	}
	refreshValidity()
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			refreshValidity()
		}
	}()

	// Read-only view onto the deception service for the dashboard's LLM
	// panel. Built from the same env config the SSH server uses, but only
	// its BaseURL/timeouts matter here -- this process never asks for a
	// policy decision or a completion, only the operator-facing listing.
	deceptionClient := deception.NewClient(deception.ConfigFromEnv())

	// Read once at startup: the page is embedded in the binary, so a
	// per-request read would buy nothing and a failure here should stop the
	// process rather than 500 on every dashboard load.
	//
	// Served directly rather than through http.FileServer: the route is the
	// exact path "/dashboard", and FileServer resolves the request path
	// against the FS, so it would look for a file named "dashboard" and 404
	// on the index.html that is actually there.
	dashboardPage, err := dashboardFS.ReadFile("dashboard/index.html")
	if err != nil {
		log.Fatalf("loading embedded dashboard page: %v", err)
	}

	r := chi.NewRouter()

	// Trades the API key for the dashboard cookie. Outside the gate below,
	// since presenting the key is how a caller gets through it.
	r.Post("/dashboard/login", func(w http.ResponseWriter, r *http.Request) {
		presented := r.FormValue("api_key")
		if presented == "" {
			presented = r.Header.Get("X-API-Key")
		}
		if subtle.ConstantTimeCompare([]byte(presented), []byte(apiKey)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		value, maxAge := issueSession(apiKey, time.Now())
		http.SetCookie(w, &http.Cookie{
			Name:     dashboardCookie,
			Value:    value,
			Path:     "/",
			MaxAge:   maxAge,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		})
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	})

	r.Get("/dashboard/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := w.Write(loginPage); err != nil {
			log.Printf("writing login page: %v", err)
		}
	})

	r.Group(func(r chi.Router) {
		r.Use(gate(apiKey))
		routes(r, db, apiKey, sensorNames, vcache, deceptionClient, dashboardPage)
	})

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           r,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Println("API server listening on :8080")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("starting server: %v", err)
	}
}

func routes(
	r chi.Router,
	db *sql.DB,
	apiKey string,
	sensorNames []string,
	vcache *validityCache,
	deceptionClient *deception.Client,
	dashboardPage []byte,
) {
	r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := w.Write(dashboardPage); err != nil {
			log.Printf("writing dashboard page: %v", err)
		}
	})

	r.Get("/api/sensors", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"sensors": sensorNames, "default": sensorNames[0]})
	})

	validitySummaryFor := func(w http.ResponseWriter, r *http.Request) (api.ValiditySummary, bool) {
		name := r.URL.Query().Get("sensor")
		if name == "" {
			name = sensorNames[0]
		}
		s, ok := vcache.get(name)
		if !ok {
			http.Error(w, "sensor not found or not yet computed", http.StatusNotFound)
		}
		return s, ok
	}

	r.Get("/api/validity/summary", func(w http.ResponseWriter, r *http.Request) {
		if s, ok := validitySummaryFor(w, r); ok {
			writeJSON(w, s)
		}
	})
	r.Get("/api/validity/accept-rate", func(w http.ResponseWriter, r *http.Request) {
		s, ok := validitySummaryFor(w, r)
		if !ok {
			return
		}
		series := s.AcceptRate
		if raw := r.URL.Query().Get("days"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 && n < len(series) {
				series = series[len(series)-n:]
			}
		}
		writeJSON(w, series)
	})
	r.Get("/api/validity/fields", func(w http.ResponseWriter, r *http.Request) {
		if s, ok := validitySummaryFor(w, r); ok {
			writeJSON(w, s.FieldCardinality)
		}
	})
	r.Get("/api/validity/campaign", func(w http.ResponseWriter, r *http.Request) {
		if s, ok := validitySummaryFor(w, r); ok {
			writeJSON(w, s.Campaign)
		}
	})
	r.Get("/api/validity/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		if s, ok := validitySummaryFor(w, r); ok {
			writeJSON(w, s.Heartbeat)
		}
	})

	r.Get("/api/llm-shell/providers", func(w http.ResponseWriter, r *http.Request) {
		listing, err := deceptionClient.Providers()
		if err != nil {
			log.Printf("fetching LLM provider listing: %v", err)
			// The deception service being unreachable is an expected state
			// (it is optional and has no depends_on), so the dashboard gets
			// a well-formed "not configured" rather than an error banner.
			writeJSON(w, map[string]any{"configured": false, "providers": []any{}, "active": nil, "reachable": false})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(listing); err != nil {
			log.Printf("writing LLM provider listing: %v", err)
		}
	})

	r.Post("/api/llm-shell/active", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
			http.Error(w, "expected a JSON body with a non-empty name", http.StatusBadRequest)
			return
		}
		listing, err := deceptionClient.SetActiveProvider(body.Name)
		if err != nil {
			log.Printf("switching LLM provider to %q: %v", body.Name, err)
			// A name the service doesn't know is the caller's mistake, not an
			// upstream failure -- reporting both as 502 would tell an operator
			// their deception service is down when they merely typo'd a name.
			if errors.Is(err, deception.ErrUnknownProvider) {
				http.Error(w, "unknown provider", http.StatusBadRequest)
				return
			}
			http.Error(w, "failed to switch provider", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(listing); err != nil {
			log.Printf("writing provider switch response: %v", err)
		}
	})

	// The two flags this endpoint owns are exactly the console's Control tab
	// switches marked writable in mirage-web docs/API-GAPS.md §4 -- everything
	// else on that tab (llm_shell_enabled, stix_enabled, intel_use_llm, the
	// rate/timeout limits) is still env-only, owned by other containers, and
	// mirage-web fills those in itself from its own environment. See
	// DECISIONS.md for why this stayed scoped to just these two.
	writeRuntimeConfig := func(w http.ResponseWriter, flags store.RuntimeFlags) {
		writeJSON(w, map[string]any{
			"deception_enabled":       flags.DeceptionEnabled,
			"deception_apply_actions": flags.DeceptionApplyActions,
			"updated_at":              flags.UpdatedAt,
			"updated_by":              flags.UpdatedBy,
		})
	}

	r.Get("/api/config", func(w http.ResponseWriter, r *http.Request) {
		flags, err := store.LoadRuntimeFlags(db)
		if err != nil {
			log.Printf("loading runtime flags: %v", err)
			http.Error(w, "failed to load runtime configuration", http.StatusInternalServerError)
			return
		}
		writeRuntimeConfig(w, flags)
	})

	r.Put("/api/config", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			DeceptionEnabled      *bool  `json:"deception_enabled"`
			DeceptionApplyActions *bool  `json:"deception_apply_actions"`
			UpdatedBy             string `json:"updated_by"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if body.DeceptionEnabled == nil && body.DeceptionApplyActions == nil {
			http.Error(w, "expected at least one of deception_enabled, deception_apply_actions", http.StatusBadRequest)
			return
		}
		updatedBy := body.UpdatedBy
		if updatedBy == "" {
			updatedBy = "console"
		}
		if body.DeceptionEnabled != nil {
			if err := store.SetRuntimeFlag(db, "deception_enabled", *body.DeceptionEnabled, updatedBy); err != nil {
				log.Printf("setting deception_enabled: %v", err)
				http.Error(w, "failed to save runtime configuration", http.StatusInternalServerError)
				return
			}
		}
		if body.DeceptionApplyActions != nil {
			if err := store.SetRuntimeFlag(db, "deception_apply_actions", *body.DeceptionApplyActions, updatedBy); err != nil {
				log.Printf("setting deception_apply_actions: %v", err)
				http.Error(w, "failed to save runtime configuration", http.StatusInternalServerError)
				return
			}
		}
		flags, err := store.LoadRuntimeFlags(db)
		if err != nil {
			log.Printf("reloading runtime flags after write: %v", err)
			http.Error(w, "saved, but failed to read back the new configuration", http.StatusInternalServerError)
			return
		}
		writeRuntimeConfig(w, flags)
	})

	r.Get("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		stats, err := store.GetStats(db)
		if err != nil {
			http.Error(
				w,
				"failed to retrieve stats",
				http.StatusInternalServerError,
			)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(stats); err != nil {
			log.Printf("encoding stats response: %v", err)
		}
	})

	r.Get("/api/sessions", func(w http.ResponseWriter, r *http.Request) {
		limit := 50
		offset := 0

		if value := r.URL.Query().Get("limit"); value != "" {
			if parsed, err := strconv.Atoi(value); err == nil {
				limit = parsed
			}
		}

		if value := r.URL.Query().Get("offset"); value != "" {
			if parsed, err := strconv.Atoi(value); err == nil {
				offset = parsed
			}
		}

		if limit < 1 {
			limit = 1
		}

		if limit > 100 {
			limit = 100
		}

		if offset < 0 {
			offset = 0
		}

		sessions, err := store.GetSessions(
			db,
			limit,
			offset,
		)
		if err != nil {
			http.Error(
				w,
				"failed to retrieve sessions",
				http.StatusInternalServerError,
			)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(sessions); err != nil {
			log.Printf("encoding sessions response: %v", err)
		}
	})

	r.Get("/api/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		sessionID := chi.URLParam(r, "id")
		if sessionID == "" {
			http.Error(w, "missing session id", http.StatusBadRequest)
			return
		}
		sess, err := store.GetSessionByID(db, sessionID)
		if err != nil {
			if errors.Is(err, store.ErrSessionNotFound) {
				http.Error(w, "session not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to retrieve session", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(sess); err != nil {
			log.Printf("encoding session response: %v", err)
		}
	})
	r.Get("/api/sessions/{id}/report", func(w http.ResponseWriter, r *http.Request) {
		sessionID := chi.URLParam(r, "id")
		if sessionID == "" {
			http.Error(w, "missing session id", http.StatusBadRequest)
			return
		}
		report, err := store.GetSessionReport(db, sessionID)
		if err != nil {
			if errors.Is(err, store.ErrSessionNotFound) {
				http.Error(w, "session not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to generate report", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(report); err != nil {
			log.Printf("encoding report response: %v", err)
		}
	})

	// A "limit" asks for one page; without one the caller gets the whole
	// corpus, streamed page by page. The full dump is kept as the default so
	// existing consumers (mirage-web's corpus cache, the dataset publisher)
	// keep working unchanged while they move onto cursors.
	r.Get("/api/export", func(w http.ResponseWriter, r *http.Request) {
		fetch := func(after string, limit int) (*api.ExportResponse, error) {
			return store.GetExportPage(db, after, limit)
		}

		if raw := r.URL.Query().Get("limit"); raw != "" {
			limit, err := strconv.Atoi(raw)
			if err != nil || limit <= 0 {
				http.Error(w, "invalid limit", http.StatusBadRequest)
				return
			}
			page, err := fetch(r.URL.Query().Get("after"), limit)
			if err != nil {
				if errors.Is(err, store.ErrInvalidCursor) {
					http.Error(w, "invalid cursor", http.StatusBadRequest)
					return
				}
				log.Printf("generating export page: %v", err)
				http.Error(w, "failed to generate export", http.StatusInternalServerError)
				return
			}
			writeJSON(w, page)
			return
		}

		// The full dump outlasts the server-wide WriteTimeout on a corpus this
		// size, and that timeout truncates the body mid-JSON rather than
		// failing cleanly. Extend it for this one route.
		if rc := http.NewResponseController(w); rc != nil {
			if err := rc.SetWriteDeadline(time.Now().Add(exportWriteTimeout)); err != nil {
				log.Printf("extending export write deadline: %v", err)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if err := streamExport(w, fmt.Sprintf("%d", time.Now().UnixMilli()), fetch); err != nil {
			// Headers are already sent, so this cannot become a status code.
			// The truncated body fails the client's parse, which is visible.
			log.Printf("streaming export: %v", err)
		}
	})

	r.Get("/api/export/commands", func(w http.ResponseWriter, r *http.Request) {
		after := r.URL.Query().Get("after")
		limit := 0
		if raw := r.URL.Query().Get("limit"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				http.Error(w, "invalid limit", http.StatusBadRequest)
				return
			}
			limit = parsed
		}

		export, err := store.GetCommandExport(db, after, limit)
		if err != nil {
			if errors.Is(err, store.ErrInvalidCursor) {
				http.Error(w, "invalid cursor", http.StatusBadRequest)
				return
			}
			http.Error(
				w,
				"failed to generate commands export",
				http.StatusInternalServerError,
			)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(export); err != nil {
			log.Printf("encoding commands export response: %v", err)
		}
	})

}
