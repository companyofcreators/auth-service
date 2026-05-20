package http

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/companyofcreators/auth-service/internal/interfaces/http/handler"
)

type rateLimitStore struct {
	mu      sync.Mutex
	entries map[string][]time.Time
}

func newRateLimitStore() *rateLimitStore {
	s := &rateLimitStore{
		entries: make(map[string][]time.Time),
	}
	go s.cleanup()
	return s
}

func (s *rateLimitStore) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		for ip, times := range s.entries {
			cutoff := time.Now().Add(-1 * time.Minute)
			var valid []time.Time
			for _, t := range times {
				if t.After(cutoff) {
					valid = append(valid, t)
				}
			}
			if len(valid) == 0 {
				delete(s.entries, ip)
			} else {
				s.entries[ip] = valid
			}
		}
		s.mu.Unlock()
	}
}

func (s *rateLimitStore) Allow(ip string, limit int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-1 * time.Minute)

	times := s.entries[ip]
	var valid []time.Time
	for _, t := range times {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= limit {
		return false
	}

	valid = append(valid, now)
	s.entries[ip] = valid
	return true
}

func LoginRateLimiter(store *rateLimitStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
				ip = forwarded
			}

			if !store.Allow(ip, 5) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":"слишком много запросов","message":"превышен лимит запросов, попробуйте позже"}`))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func NewRouter(authHandler *handler.AuthHandler) chi.Router {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	rateLimitStore := newRateLimitStore()

	r.Get("/internal/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"service": "auth-service",
		})
	})

	r.Route("/api/v1/auth", func(r chi.Router) {
		r.With(LoginRateLimiter(rateLimitStore)).Post("/login", authHandler.Login)
		r.With(LoginRateLimiter(rateLimitStore)).Post("/register", authHandler.Register)
		r.Post("/refresh", authHandler.Refresh)
		r.Delete("/logout", authHandler.Logout)
		r.Get("/verify-email", authHandler.VerifyEmail)
	})

	return r
}
