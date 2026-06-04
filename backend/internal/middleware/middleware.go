// Package middleware contains the JWT auth middleware and a small request
// logger. They are plain http.Handler wrappers — chi's middleware contract is
// the standard library's, which means no framework lock-in.
package middleware

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/braidman/tenexai-assessment/backend/internal/auth"
)

// statusRecorder lets us read the response status after the handler has run,
// since http.ResponseWriter doesn't expose it.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Logger emits one structured log line per request using slog. We chose slog
// (stdlib since Go 1.21) over zerolog/logrus because it's the language
// standard now and the JSON output plays well with Datadog/Loki.
func Logger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: 200}
			next.ServeHTTP(rec, r)
			log.Info("http",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

// RequireJWT validates Authorization: Bearer <token> and stuffs the claims
// into the request context. On failure we return 401 with no body — never
// leak whether the token was missing vs. expired vs. malformed.
func RequireJWT(m *auth.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if !strings.HasPrefix(h, "Bearer ") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(h, "Bearer ")
			claims, err := m.Parse(token)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := auth.WithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CORS lets the React dev server (localhost:5173) talk to the Go server.
// In production you'd front this with a reverse proxy on the same origin.
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
