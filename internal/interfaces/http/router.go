package http

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/companyofcreators/auth-service/internal/interfaces/http/handler"
	"github.com/companyofcreators/auth-service/pkg/header_auth"
)

func NewRouter(authHandler *handler.AuthHandler, adminHandler *handler.AdminHandler, signer *header_auth.HeaderSigner) chi.Router {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(signer.VerifyMiddleware)

	r.Get("/internal/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"service": "auth-service",
		})
	})

	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Post("/login", authHandler.Login)
		r.Post("/register", authHandler.Register)
		r.Post("/refresh", authHandler.Refresh)
		r.Delete("/logout", authHandler.Logout)
		r.Get("/verify-email", authHandler.VerifyEmail)
		r.Post("/resend-verification", authHandler.ResendVerification)
	})

	// Internal admin routes called from the API gateway.
	r.Route("/api/v1/admin", func(r chi.Router) {
		r.Post("/users/{id}/ban", adminHandler.BanUser)
		r.Post("/users/{id}/unban", adminHandler.UnbanUser)
		r.Delete("/users/{id}", adminHandler.DeleteUser)
	})

	// Internal role sync routes called from user-service.
	r.Route("/internal/users/{id}/roles", func(r chi.Router) {
		r.Post("/{role}", adminHandler.AddRole)
		r.Delete("/{role}", adminHandler.RemoveRole)
	})

	return r
}

// bodySizeLimiter returns middleware that wraps http.MaxBytesReader to limit
// request body size and prevent memory exhaustion attacks.
func bodySizeLimiter(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}
