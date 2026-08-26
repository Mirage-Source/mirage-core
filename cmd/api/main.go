package main

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mirage-source/mirage-core/internal/api"
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

	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			presented := r.Header.Get("X-API-Key")
			if presented == "" {
				presented = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			}
			if presented == "" {
				// The dashboard page itself is a plain browser navigation,
				// which can't set a custom header -- accepted here as a
				// deliberate, documented trade-off (see DECISIONS.md) so
				// /dashboard?api_key=... works, not a general bypass: the
				// header/bearer path above is still tried first.
				presented = r.URL.Query().Get("api_key")
			}
			if subtle.ConstantTimeCompare([]byte(presented), []byte(apiKey)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	})

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
			if err.Error() == "session not found" {
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
			if err.Error() == "session not found" {
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

	r.Get("/api/export", func(w http.ResponseWriter, r *http.Request) {
		export, err := store.GetExportData(db)
		if err != nil {
			http.Error(
				w,
				"failed to generate export",
				http.StatusInternalServerError,
			)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(export); err != nil {
			log.Printf("encoding export response: %v", err)
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
			if strings.HasPrefix(err.Error(), "invalid cursor") {
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
