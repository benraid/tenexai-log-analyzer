// Package storage hides Postgres behind a small interface. The handlers depend
// only on Store, which makes the code easy to unit-test (swap a fake in tests)
// and shields the rest of the app from pgx specifics.
//
// In Java/Spring terms: Store is a Repository, and PostgresStore is the
// JdbcTemplate-backed implementation we wire at startup.
package storage

import (
	"context"
	"time"

	"github.com/braidman/tenexai-assessment/backend/internal/models"
	"github.com/google/uuid"
)

type Store interface {
	// Users
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	CreateUser(ctx context.Context, username, passwordHash string) (*models.User, error)
	CountUsers(ctx context.Context) (int, error)

	// Uploads
	CreateUpload(ctx context.Context, u *models.Upload) error
	ListUploads(ctx context.Context, userID int) ([]models.Upload, error)
	GetUpload(ctx context.Context, id uuid.UUID, userID int) (*models.Upload, error)

	// Log entries
	BulkInsertEntries(ctx context.Context, entries []models.LogEntry) ([]int64, error)
	ListEntries(ctx context.Context, uploadID uuid.UUID, anomalousOnly bool, limit, offset int) ([]models.LogEntry, int, error)

	// Anomalies
	BulkInsertAnomalies(ctx context.Context, anomalies []models.Anomaly) error
	ListAnomalies(ctx context.Context, uploadID uuid.UUID) ([]models.Anomaly, error)
	CountAnomalies(ctx context.Context, uploadID uuid.UUID) (int, error)

	// Summary aggregations
	Summary(ctx context.Context, uploadID uuid.UUID) (*Summary, error)

	// AI-generated content caches. Stored alongside the parent rows so
	// re-renders are free and we can invalidate by clearing the column.
	GetBriefing(ctx context.Context, uploadID uuid.UUID, userID int) (*CachedBriefing, error)
	SaveBriefing(ctx context.Context, uploadID uuid.UUID, markdown string) error

	GetAnomalyWithEntry(ctx context.Context, anomalyID int64, userID int) (*models.Anomaly, *models.LogEntry, error)
	GetAnomalyExplanation(ctx context.Context, anomalyID int64, userID int) (*CachedExplanation, error)
	SaveAnomalyExplanation(ctx context.Context, anomalyID int64, markdown string) error
}

// CachedBriefing pairs the markdown with its generation timestamp so the UI
// can show "generated 2 minutes ago." Empty Markdown means no briefing cached.
type CachedBriefing struct {
	Markdown    string    `json:"markdown"`
	GeneratedAt time.Time `json:"generated_at"`
}

// CachedExplanation is the per-anomaly equivalent of CachedBriefing.
type CachedExplanation struct {
	Markdown    string    `json:"markdown"`
	GeneratedAt time.Time `json:"generated_at"`
}

// Summary is the response shape for the dashboard's SOC view.
type Summary struct {
	TotalEntries    int              `json:"total_entries"`
	BlockedEntries  int              `json:"blocked_entries"`
	UniqueSrcIPs    int              `json:"unique_src_ips"`
	AnomalyCount    int              `json:"anomaly_count"`
	TopCategories   []CountPair      `json:"top_categories"`
	TopSrcIPs       []CountPair      `json:"top_src_ips"`
	TopThreats      []CountPair      `json:"top_threats"`
	Timeline        []TimelineBucket `json:"timeline"`
}

type CountPair struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type TimelineBucket struct {
	BucketStart   time.Time `json:"bucket_start"`
	TotalCount    int       `json:"total_count"`
	BlockedCount  int       `json:"blocked_count"`
	AnomalyCount  int       `json:"anomaly_count"`
}
