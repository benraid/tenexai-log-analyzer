package storage

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/braidman/tenexai-assessment/backend/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore implements Store against a pgxpool connection pool.
// pgxpool is the modern pgx equivalent of HikariCP — pooled, context-aware,
// supports COPY and prepared statements without database/sql's overhead.
type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

var ErrNotFound = errors.New("not found")

// --- Users ---

func (s *PostgresStore) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, username, password_hash, created_at FROM users WHERE username = $1`, username)
	var u models.User
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get user: %w", err)
	}
	return &u, nil
}

func (s *PostgresStore) CreateUser(ctx context.Context, username, passwordHash string) (*models.User, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO users (username, password_hash) VALUES ($1, $2)
		 RETURNING id, username, password_hash, created_at`, username, passwordHash)
	var u models.User
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt); err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return &u, nil
}

func (s *PostgresStore) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

// --- Uploads ---

func (s *PostgresStore) CreateUpload(ctx context.Context, u *models.Upload) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO uploads (id, user_id, filename, total_rows, parsed_rows, uploaded_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		u.ID, u.UserID, u.Filename, u.TotalRows, u.ParsedRows, u.UploadedAt)
	if err != nil {
		return fmt.Errorf("create upload: %w", err)
	}
	return nil
}

func (s *PostgresStore) ListUploads(ctx context.Context, userID int) ([]models.Upload, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, filename, total_rows, parsed_rows, uploaded_at
		 FROM uploads WHERE user_id = $1 ORDER BY uploaded_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("list uploads: %w", err)
	}
	defer rows.Close()
	var out []models.Upload
	for rows.Next() {
		var u models.Upload
		if err := rows.Scan(&u.ID, &u.UserID, &u.Filename, &u.TotalRows, &u.ParsedRows, &u.UploadedAt); err != nil {
			return nil, fmt.Errorf("scan upload: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *PostgresStore) GetUpload(ctx context.Context, id uuid.UUID, userID int) (*models.Upload, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, user_id, filename, total_rows, parsed_rows, uploaded_at
		 FROM uploads WHERE id = $1 AND user_id = $2`, id, userID)
	var u models.Upload
	if err := row.Scan(&u.ID, &u.UserID, &u.Filename, &u.TotalRows, &u.ParsedRows, &u.UploadedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get upload: %w", err)
	}
	return &u, nil
}

// --- Log entries ---

// BulkInsertEntries uses pgx.CopyFrom under the hood: Postgres' COPY protocol
// streams rows in a single round-trip per batch, an order of magnitude faster
// than individual INSERTs. We RETURN no IDs from COPY, so we re-query the IDs
// after insert by ordering on the BIGSERIAL — this works because COPY preserves
// row order on a single connection. For the prototype's data sizes this is fine.
func (s *PostgresStore) BulkInsertEntries(ctx context.Context, entries []models.LogEntry) ([]int64, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	cols := []string{"upload_id", "ts", "username", "src_ip", "dst_ip", "url",
		"url_category", "action", "threat_name", "threat_category",
		"bytes_in", "bytes_out", "user_agent", "referer"}

	src := pgx.CopyFromSlice(len(entries), func(i int) ([]any, error) {
		e := entries[i]
		return []any{
			e.UploadID, e.Timestamp, nullIfEmpty(e.Username),
			parseInet(e.SrcIP), parseInet(e.DstIP),
			nullIfEmpty(e.URL), nullIfEmpty(e.URLCategory), nullIfEmpty(e.Action),
			nullIfEmpty(e.ThreatName), nullIfEmpty(e.ThreatCategory),
			e.BytesIn, e.BytesOut,
			nullIfEmpty(e.UserAgent), nullIfEmpty(e.Referer),
		}, nil
	})

	uploadID := entries[0].UploadID
	if _, err := s.pool.CopyFrom(ctx, pgx.Identifier{"log_entries"}, cols, src); err != nil {
		return nil, fmt.Errorf("copy log_entries: %w", err)
	}

	// Read back the IDs in insertion order so callers (the detector) can
	// reference specific entries from anomaly rows.
	rows, err := s.pool.Query(ctx,
		`SELECT id FROM log_entries WHERE upload_id = $1 ORDER BY id ASC`, uploadID)
	if err != nil {
		return nil, fmt.Errorf("read back ids: %w", err)
	}
	defer rows.Close()
	ids := make([]int64, 0, len(entries))
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *PostgresStore) ListEntries(ctx context.Context, uploadID uuid.UUID, anomalousOnly bool, limit, offset int) ([]models.LogEntry, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	// Count first (filtered) so the frontend can paginate without a second call.
	var total int
	if anomalousOnly {
		err := s.pool.QueryRow(ctx,
			`SELECT COUNT(DISTINCT le.id) FROM log_entries le
			 JOIN anomalies a ON a.log_entry_id = le.id
			 WHERE le.upload_id = $1`, uploadID).Scan(&total)
		if err != nil {
			return nil, 0, fmt.Errorf("count entries: %w", err)
		}
	} else {
		err := s.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM log_entries WHERE upload_id = $1`, uploadID).Scan(&total)
		if err != nil {
			return nil, 0, fmt.Errorf("count entries: %w", err)
		}
	}

	q := `SELECT le.id, le.upload_id, le.ts, COALESCE(le.username,''),
	             COALESCE(host(le.src_ip),''), COALESCE(host(le.dst_ip),''),
	             COALESCE(le.url,''), COALESCE(le.url_category,''),
	             COALESCE(le.action,''), COALESCE(le.threat_name,''),
	             COALESCE(le.threat_category,''),
	             COALESCE(le.bytes_in,0), COALESCE(le.bytes_out,0),
	             COALESCE(le.user_agent,''), COALESCE(le.referer,'')
	      FROM log_entries le `
	if anomalousOnly {
		q += `WHERE le.upload_id = $1 AND EXISTS (
		        SELECT 1 FROM anomalies a WHERE a.log_entry_id = le.id
		      )`
	} else {
		q += `WHERE le.upload_id = $1`
	}
	q += ` ORDER BY le.ts ASC LIMIT $2 OFFSET $3`

	rows, err := s.pool.Query(ctx, q, uploadID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list entries: %w", err)
	}
	defer rows.Close()
	out := make([]models.LogEntry, 0, limit)
	for rows.Next() {
		var e models.LogEntry
		if err := rows.Scan(&e.ID, &e.UploadID, &e.Timestamp, &e.Username,
			&e.SrcIP, &e.DstIP, &e.URL, &e.URLCategory, &e.Action,
			&e.ThreatName, &e.ThreatCategory, &e.BytesIn, &e.BytesOut,
			&e.UserAgent, &e.Referer); err != nil {
			return nil, 0, fmt.Errorf("scan entry: %w", err)
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// --- Anomalies ---

func (s *PostgresStore) BulkInsertAnomalies(ctx context.Context, anomalies []models.Anomaly) error {
	if len(anomalies) == 0 {
		return nil
	}
	cols := []string{"upload_id", "log_entry_id", "rule_name", "explanation", "confidence"}
	src := pgx.CopyFromSlice(len(anomalies), func(i int) ([]any, error) {
		a := anomalies[i]
		var entryID any
		if a.LogEntryID == 0 {
			entryID = nil
		} else {
			entryID = a.LogEntryID
		}
		return []any{a.UploadID, entryID, a.RuleName, a.Explanation, a.Confidence}, nil
	})
	if _, err := s.pool.CopyFrom(ctx, pgx.Identifier{"anomalies"}, cols, src); err != nil {
		return fmt.Errorf("copy anomalies: %w", err)
	}
	return nil
}

func (s *PostgresStore) ListAnomalies(ctx context.Context, uploadID uuid.UUID) ([]models.Anomaly, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, upload_id, COALESCE(log_entry_id,0), rule_name, explanation, confidence
		 FROM anomalies WHERE upload_id = $1 ORDER BY confidence DESC, id ASC`, uploadID)
	if err != nil {
		return nil, fmt.Errorf("list anomalies: %w", err)
	}
	defer rows.Close()
	var out []models.Anomaly
	for rows.Next() {
		var a models.Anomaly
		if err := rows.Scan(&a.ID, &a.UploadID, &a.LogEntryID, &a.RuleName, &a.Explanation, &a.Confidence); err != nil {
			return nil, fmt.Errorf("scan anomaly: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CountAnomalies(ctx context.Context, uploadID uuid.UUID) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM anomalies WHERE upload_id = $1`, uploadID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count anomalies: %w", err)
	}
	return n, nil
}

// --- Summary ---

func (s *PostgresStore) Summary(ctx context.Context, uploadID uuid.UUID) (*Summary, error) {
	sum := &Summary{}

	// Headline counts in one round-trip.
	err := s.pool.QueryRow(ctx, `
		SELECT
		  (SELECT COUNT(*) FROM log_entries WHERE upload_id = $1),
		  (SELECT COUNT(*) FROM log_entries WHERE upload_id = $1 AND action = 'blocked'),
		  (SELECT COUNT(DISTINCT src_ip) FROM log_entries WHERE upload_id = $1 AND src_ip IS NOT NULL),
		  (SELECT COUNT(*) FROM anomalies WHERE upload_id = $1)
	`, uploadID).Scan(&sum.TotalEntries, &sum.BlockedEntries, &sum.UniqueSrcIPs, &sum.AnomalyCount)
	if err != nil {
		return nil, fmt.Errorf("summary headline: %w", err)
	}

	sum.TopCategories, err = topN(ctx, s.pool, uploadID,
		`SELECT COALESCE(url_category,'(none)'), COUNT(*) c FROM log_entries
		 WHERE upload_id = $1 GROUP BY 1 ORDER BY c DESC LIMIT 5`)
	if err != nil {
		return nil, fmt.Errorf("top categories: %w", err)
	}
	sum.TopSrcIPs, err = topN(ctx, s.pool, uploadID,
		`SELECT host(src_ip), COUNT(*) c FROM log_entries
		 WHERE upload_id = $1 AND src_ip IS NOT NULL
		 GROUP BY 1 ORDER BY c DESC LIMIT 5`)
	if err != nil {
		return nil, fmt.Errorf("top src ips: %w", err)
	}
	sum.TopThreats, err = topN(ctx, s.pool, uploadID,
		`SELECT threat_name, COUNT(*) c FROM log_entries
		 WHERE upload_id = $1 AND threat_name IS NOT NULL AND threat_name <> ''
		 GROUP BY 1 ORDER BY c DESC LIMIT 5`)
	if err != nil {
		return nil, fmt.Errorf("top threats: %w", err)
	}

	// 5-minute timeline buckets via date_bin (Postgres 14+).
	// We aggregate log_entries and anomalies in *separate* CTEs and then
	// outer-join the aggregates. A naive `FROM buckets LEFT JOIN anomalies`
	// multiplies a row by the number of anomalies attached to it, which
	// inflates total_count/blocked_count when a single row fires multiple
	// detector rules (e.g., threat_hit AND malicious_category).
	rows, err := s.pool.Query(ctx, `
		WITH buckets AS (
		  SELECT date_bin('5 minutes', ts, TIMESTAMPTZ '2000-01-01') AS bucket_start,
		         id, action FROM log_entries WHERE upload_id = $1
		),
		totals AS (
		  SELECT bucket_start,
		         COUNT(*) AS total_count,
		         COUNT(*) FILTER (WHERE action = 'blocked') AS blocked_count
		  FROM buckets
		  GROUP BY bucket_start
		),
		anoms AS (
		  SELECT b.bucket_start, COUNT(a.id) AS anomaly_count
		  FROM buckets b
		  JOIN anomalies a ON a.log_entry_id = b.id
		  GROUP BY b.bucket_start
		)
		SELECT t.bucket_start,
		       t.total_count,
		       t.blocked_count,
		       COALESCE(an.anomaly_count, 0) AS anomaly_count
		FROM totals t
		LEFT JOIN anoms an USING (bucket_start)
		ORDER BY t.bucket_start ASC
	`, uploadID)
	if err != nil {
		return nil, fmt.Errorf("timeline: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var t TimelineBucket
		if err := rows.Scan(&t.BucketStart, &t.TotalCount, &t.BlockedCount, &t.AnomalyCount); err != nil {
			return nil, fmt.Errorf("scan bucket: %w", err)
		}
		sum.Timeline = append(sum.Timeline, t)
	}
	return sum, rows.Err()
}

// --- AI cache ---

// GetBriefing returns the cached briefing for an upload, or ErrNotFound if
// it was never generated (or the upload itself doesn't belong to the user).
func (s *PostgresStore) GetBriefing(ctx context.Context, uploadID uuid.UUID, userID int) (*CachedBriefing, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT COALESCE(ai_briefing, ''), COALESCE(ai_briefing_at, 'epoch'::timestamptz)
		FROM uploads WHERE id = $1 AND user_id = $2`, uploadID, userID)
	var c CachedBriefing
	if err := row.Scan(&c.Markdown, &c.GeneratedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get briefing: %w", err)
	}
	return &c, nil
}

func (s *PostgresStore) SaveBriefing(ctx context.Context, uploadID uuid.UUID, markdown string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE uploads SET ai_briefing = $2, ai_briefing_at = now() WHERE id = $1`,
		uploadID, markdown)
	if err != nil {
		return fmt.Errorf("save briefing: %w", err)
	}
	return nil
}

// GetAnomalyWithEntry fetches an anomaly + its related log entry, both scoped
// to the caller's uploads. The LogEntry is nil if the anomaly is upload-wide
// (log_entry_id NULL — none of the current rules emit those, but the schema
// allows it). Ownership is verified via the upload's user_id.
func (s *PostgresStore) GetAnomalyWithEntry(ctx context.Context, anomalyID int64, userID int) (*models.Anomaly, *models.LogEntry, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT a.id, a.upload_id, COALESCE(a.log_entry_id, 0), a.rule_name, a.explanation, a.confidence
		FROM anomalies a
		JOIN uploads u ON u.id = a.upload_id
		WHERE a.id = $1 AND u.user_id = $2`, anomalyID, userID)
	var a models.Anomaly
	if err := row.Scan(&a.ID, &a.UploadID, &a.LogEntryID, &a.RuleName, &a.Explanation, &a.Confidence); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, fmt.Errorf("get anomaly: %w", err)
	}
	if a.LogEntryID == 0 {
		return &a, nil, nil
	}
	entryRow := s.pool.QueryRow(ctx, `
		SELECT id, upload_id, ts, COALESCE(username,''),
		       COALESCE(host(src_ip),''), COALESCE(host(dst_ip),''),
		       COALESCE(url,''), COALESCE(url_category,''),
		       COALESCE(action,''), COALESCE(threat_name,''),
		       COALESCE(threat_category,''),
		       COALESCE(bytes_in,0), COALESCE(bytes_out,0),
		       COALESCE(user_agent,''), COALESCE(referer,'')
		FROM log_entries WHERE id = $1`, a.LogEntryID)
	var e models.LogEntry
	if err := entryRow.Scan(&e.ID, &e.UploadID, &e.Timestamp, &e.Username,
		&e.SrcIP, &e.DstIP, &e.URL, &e.URLCategory, &e.Action,
		&e.ThreatName, &e.ThreatCategory, &e.BytesIn, &e.BytesOut,
		&e.UserAgent, &e.Referer); err != nil {
		// If the related entry is gone, return just the anomaly.
		if errors.Is(err, pgx.ErrNoRows) {
			return &a, nil, nil
		}
		return nil, nil, fmt.Errorf("get entry: %w", err)
	}
	return &a, &e, nil
}

func (s *PostgresStore) GetAnomalyExplanation(ctx context.Context, anomalyID int64, userID int) (*CachedExplanation, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT COALESCE(a.ai_explanation, ''), COALESCE(a.ai_explanation_at, 'epoch'::timestamptz)
		FROM anomalies a
		JOIN uploads u ON u.id = a.upload_id
		WHERE a.id = $1 AND u.user_id = $2`, anomalyID, userID)
	var c CachedExplanation
	if err := row.Scan(&c.Markdown, &c.GeneratedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get explanation: %w", err)
	}
	return &c, nil
}

func (s *PostgresStore) SaveAnomalyExplanation(ctx context.Context, anomalyID int64, markdown string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE anomalies SET ai_explanation = $2, ai_explanation_at = now() WHERE id = $1`,
		anomalyID, markdown)
	if err != nil {
		return fmt.Errorf("save explanation: %w", err)
	}
	return nil
}

func topN(ctx context.Context, pool *pgxpool.Pool, uploadID uuid.UUID, q string) ([]CountPair, error) {
	rows, err := pool.Query(ctx, q, uploadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CountPair
	for rows.Next() {
		var p CountPair
		if err := rows.Scan(&p.Key, &p.Count); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// --- helpers ---

// nullIfEmpty lets pgx send a SQL NULL instead of an empty string. Postgres
// distinguishes the two; using NULL keeps aggregations like COUNT(col) honest.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// parseInet validates the address before sending to Postgres' INET column.
// Returning nil on parse failure means we accept garbage rows by storing NULL
// instead of erroring out the whole upload — a sensible prototype trade-off.
func parseInet(s string) any {
	if s == "" {
		return nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return nil
	}
	return addr.String()
}
