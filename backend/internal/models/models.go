// Package models defines the core data types passed between the storage, parser,
// detector, and handler layers. Keeping them in one tiny package avoids import
// cycles and gives the rest of the codebase a single place to look for shapes.
package models

import (
	"time"

	"github.com/google/uuid"
)

// User is what we persist about a login. PasswordHash is bcrypt and never
// leaves the storage layer.
type User struct {
	ID           int
	Username     string
	PasswordHash string
	CreatedAt    time.Time
}

// Upload is the metadata row for a single uploaded log file. Each upload owns
// many LogEntry rows and (optionally) many Anomaly rows.
type Upload struct {
	ID          uuid.UUID `json:"id"`
	UserID      int       `json:"-"`
	Filename    string    `json:"filename"`
	TotalRows   int       `json:"total_rows"`
	ParsedRows  int       `json:"parsed_rows"`
	UploadedAt  time.Time `json:"uploaded_at"`
}

// LogEntry is one parsed Zscaler-style record. We use pointer/nullable-friendly
// types only where the column is genuinely optional in the source CSV.
// `ID` is zero until the row is persisted.
type LogEntry struct {
	ID             int64     `json:"id"`
	UploadID       uuid.UUID `json:"upload_id"`
	Timestamp      time.Time `json:"timestamp"`
	Username       string    `json:"username"`
	SrcIP          string    `json:"src_ip"`
	DstIP          string    `json:"dst_ip"`
	URL            string    `json:"url"`
	URLCategory    string    `json:"url_category"`
	Action         string    `json:"action"`
	ThreatName     string    `json:"threat_name"`
	ThreatCategory string    `json:"threat_category"`
	BytesIn        int64     `json:"bytes_in"`
	BytesOut       int64     `json:"bytes_out"`
	UserAgent      string    `json:"user_agent"`
	Referer        string    `json:"referer"`
}

// Anomaly is one detector finding. LogEntryID may be 0 for upload-wide findings
// (e.g., "this IP made 47 blocked requests" — the anomaly is about an IP, not a
// single row), but most rules attach to a specific entry.
type Anomaly struct {
	ID          int64     `json:"id"`
	UploadID    uuid.UUID `json:"upload_id"`
	LogEntryID  int64     `json:"log_entry_id"`
	RuleName    string    `json:"rule_name"`
	Explanation string    `json:"explanation"`
	Confidence  float32   `json:"confidence"`
}
