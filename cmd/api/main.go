package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/mirage-source/mirage-core/internal/store"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

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

	// Prometheus metrics
	var (
		sessionsTotal = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "mirage_sessions_total",
			Help: "Total SSH sessions captured.",
		}, func() float64 {
			var count float64
			db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&count)
			return count
		})
		sessions24h = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "mirage_sessions_24h",
			Help: "Sessions in the last 24 hours.",
		}, func() float64 {
			var count float64
			db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE start_ms >= (EXTRACT(EPOCH FROM NOW() - INTERVAL '24 hours') * 1000)`).Scan(&count)
			return count
		})
		uniqueIPs = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "mirage_unique_ips_total",
			Help: "Unique attacker IPs observed.",
		}, func() float64 {
			var count float64
			db.QueryRow(`SELECT COUNT(DISTINCT client_ip) FROM sessions`).Scan(&count)
			return count
		})
		authAttempts = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "mirage_auth_attempts_total",
			Help: "Total authentication attempts.",
		}, func() float64 {
			var count float64
			db.QueryRow(`SELECT COUNT(*) FROM auth_attempts`).Scan(&count)
			return count
		})
		enrichedSessions = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "mirage_enriched_sessions_total",
			Help: "Sessions with ML intelligence populated.",
		}, func() float64 {
			var count float64
			db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE attacker_class IS NOT NULL`).Scan(&count)
			return count
		})
	)

	prometheus.MustRegister(sessionsTotal, sessions24h, uniqueIPs, authAttempts, enrichedSessions)

	r := chi.NewRouter()

	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-API-Key") != apiKey {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
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

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.Handle("/", r)

	log.Println("API server listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("starting server: %v", err)
	}
}
