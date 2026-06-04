// server is the HTTP entrypoint. It reads config from env, opens a pgxpool,
// runs migrations, seeds the admin user if missing, mounts handlers behind
// chi middleware, and serves.
//
// Build: go build ./cmd/server
// Run:   DATABASE_URL=... JWT_SECRET=... ./server
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/braidman/tenexai-assessment/backend/internal/ai"
	"github.com/braidman/tenexai-assessment/backend/internal/auth"
	"github.com/braidman/tenexai-assessment/backend/internal/handlers"
	mymw "github.com/braidman/tenexai-assessment/backend/internal/middleware"
	"github.com/braidman/tenexai-assessment/backend/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg := loadConfig()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	pool, err := openPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer pool.Close()

	if err := runMigrations(ctx, pool, cfg.MigrationsDir, log); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	store := storage.NewPostgresStore(pool)
	if err := seedUser(ctx, store, cfg.SeedUsername, cfg.SeedPassword, log); err != nil {
		return fmt.Errorf("seed: %w", err)
	}

	jwtMgr := auth.NewManager(cfg.JWTSecret, 24*time.Hour)

	// AI is optional. If the key isn't set, aiClient stays nil and the AI
	// endpoints respond with 503 — the rest of the app keeps working.
	var aiClient ai.Client
	if c, err := ai.NewAnthropicClient(cfg.AnthropicAPIKey, cfg.AnthropicModel); err == nil {
		aiClient = c
		log.Info("AI enabled", "model", cfg.AnthropicModel)
	} else {
		log.Info("AI disabled", "reason", err.Error())
	}

	h := handlers.New(store, jwtMgr, aiClient, log)
	r := buildRouter(h, jwtMgr, log)

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
		// Header timeout is short — Slowloris defense. Body timeout is
		// generous because uploads can be up to 50MB and we don't want to
		// rug-pull a legitimate slow client. WriteTimeout caps how long the
		// response body can take to drain to the client; 60s leaves headroom
		// over the AI client's 30s ceiling so a slow LLM response can't trip
		// the server's WriteTimeout right as the response is being flushed.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		<-ctx.Done()
		log.Info("shutting down")
		shutdownCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Info("listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("listen: %w", err)
	}
	return nil
}

// --- config ---

type config struct {
	DatabaseURL     string
	JWTSecret       string
	SeedUsername    string
	SeedPassword    string
	Port            string
	MigrationsDir   string
	AnthropicAPIKey string
	AnthropicModel  string
}

func loadConfig() config {
	return config{
		DatabaseURL:     getEnv("DATABASE_URL", "postgres://tenex:tenex@localhost:5432/tenex?sslmode=disable"),
		JWTSecret:       getEnv("JWT_SECRET", "dev-secret-change-me"),
		SeedUsername:    getEnv("SEED_USERNAME", "admin"),
		SeedPassword:    getEnv("SEED_PASSWORD", "admin123"),
		Port:            getEnv("PORT", "8080"),
		MigrationsDir:   getEnv("MIGRATIONS_DIR", "db/migrations"),
		AnthropicAPIKey: getEnv("ANTHROPIC_API_KEY", ""),
		AnthropicModel:  getEnv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001"),
	}
}

func getEnv(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

// --- db ---

func openPool(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 10
	// Retry on boot — docker-compose may bring us up just before Postgres
	// is fully ready for queries even after the healthcheck passes.
	var pool *pgxpool.Pool
	for i := 0; i < 10; i++ {
		pool, err = pgxpool.NewWithConfig(ctx, cfg)
		if err == nil {
			if pErr := pool.Ping(ctx); pErr == nil {
				return pool, nil
			} else {
				pool.Close()
				err = pErr
			}
		}
		time.Sleep(time.Duration(i+1) * 500 * time.Millisecond)
	}
	return nil, err
}

// runMigrations is intentionally tiny: we read every .sql file from the dir
// in lexical order and execute each as one statement batch. For a production
// app you'd use golang-migrate or atlas to track which were applied.
// Our migrations use IF NOT EXISTS so re-running is safe.
func runMigrations(ctx context.Context, pool *pgxpool.Pool, dir string, log *slog.Logger) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".sql" {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	for _, f := range files {
		path := filepath.Join(dir, f)
		sql, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("exec %s: %w", f, err)
		}
		log.Info("migration applied", "file", f)
	}
	return nil
}

func seedUser(ctx context.Context, s storage.Store, username, password string, log *slog.Logger) error {
	n, err := s.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	hash, err := auth.Hash(password)
	if err != nil {
		return err
	}
	if _, err := s.CreateUser(ctx, username, hash); err != nil {
		return err
	}
	log.Info("seeded admin user", "username", username)
	return nil
}

// --- router ---

func buildRouter(h *handlers.Handler, jwtMgr *auth.Manager, log *slog.Logger) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer) // chi's built-in panic-to-500 — like a Spring exception handler
	r.Use(mymw.CORS)
	r.Use(mymw.Logger(log))

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	r.Route("/api", func(r chi.Router) {
		r.Post("/auth/login", h.Login)

		r.Group(func(r chi.Router) {
			r.Use(mymw.RequireJWT(jwtMgr))
			r.Get("/auth/me", h.Me)
			r.Post("/uploads", h.Upload)
			r.Get("/uploads", h.ListUploads)
			r.Get("/uploads/{id}", h.GetUpload)
			r.Get("/uploads/{id}/entries", h.ListEntries)
			r.Get("/uploads/{id}/anomalies", h.ListAnomalies)
			r.Get("/uploads/{id}/summary", h.Summary)
			r.Get("/uploads/{id}/briefing", h.GetBriefing)
			r.Post("/uploads/{id}/briefing", h.PostBriefing)
			r.Post("/anomalies/{id}/explain", h.PostAnomalyExplain)
		})
	})
	return r
}
