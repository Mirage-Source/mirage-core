package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"

	"github.com/mirage-source/mirage-core/internal/store"
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

	log.Println("API server listening on :8080")

	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatalf("starting server: %v", err)
	}
}
