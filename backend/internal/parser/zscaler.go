// Package parser reads our Zscaler-NSS-Web subset CSV files into LogEntry
// structs. We stream rows so a 100MB upload doesn't materialize as a single
// in-memory slice during parsing — though we do collect them all before bulk
// insert. For a real product, you'd stream straight into pgx.CopyFrom.
//
// Expected header (case-insensitive):
//   timestamp,username,src_ip,dst_ip,url,url_category,action,threat_name,
//   threat_category,bytes_in,bytes_out,user_agent,referer
package parser

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/braidman/tenexai-assessment/backend/internal/models"
	"github.com/google/uuid"
)

// Result is what the upload handler needs to persist the upload row.
type Result struct {
	Entries     []models.LogEntry
	TotalRows   int // header excluded
	ParsedRows  int // successfully parsed
	SkippedRows int // failed validation/format
}

// Parse reads the CSV from r and produces entries tagged with uploadID.
// We accept either ISO-8601 (`2006-01-02T15:04:05Z`) or Zscaler's space form
// (`2006-01-02 15:04:05`) for the timestamp to be tolerant of common variants.
func Parse(r io.Reader, uploadID uuid.UUID) (*Result, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1 // tolerate slightly-ragged rows; we validate per-row
	cr.TrimLeadingSpace = true
	// Real Zscaler NSS exports often contain bare quotes inside User-Agent
	// and Referer fields. LazyQuotes lets us tolerate those instead of failing
	// the whole upload on one ErrBareQuote — the offending row is still parsed.
	cr.LazyQuotes = true

	headerRow, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	idx, err := indexHeaders(headerRow)
	if err != nil {
		return nil, err
	}

	res := &Result{}
	for {
		row, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A truly malformed CSV (e.g., unmatched quote) breaks the rest of
			// the stream; bail out so the user sees the upload failed.
			return nil, fmt.Errorf("read row: %w", err)
		}
		res.TotalRows++

		e, ok := parseRow(row, idx, uploadID)
		if !ok {
			res.SkippedRows++
			continue
		}
		res.Entries = append(res.Entries, e)
		res.ParsedRows++
	}
	return res, nil
}

// indexHeaders maps the expected logical names to physical column positions,
// so reordered columns still parse correctly.
func indexHeaders(headers []string) (map[string]int, error) {
	required := []string{"timestamp", "src_ip", "url"}
	idx := make(map[string]int, len(headers))
	for i, h := range headers {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	for _, r := range required {
		if _, ok := idx[r]; !ok {
			return nil, fmt.Errorf("missing required column %q", r)
		}
	}
	return idx, nil
}

func parseRow(row []string, idx map[string]int, uploadID uuid.UUID) (models.LogEntry, bool) {
	get := func(name string) string {
		i, ok := idx[name]
		if !ok || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}

	tsRaw := get("timestamp")
	ts, ok := parseTime(tsRaw)
	if !ok {
		return models.LogEntry{}, false
	}

	return models.LogEntry{
		UploadID:       uploadID,
		Timestamp:      ts,
		Username:       get("username"),
		SrcIP:          get("src_ip"),
		DstIP:          get("dst_ip"),
		URL:            get("url"),
		URLCategory:    get("url_category"),
		Action:         strings.ToLower(get("action")),
		ThreatName:     get("threat_name"),
		ThreatCategory: get("threat_category"),
		BytesIn:        atoi64(get("bytes_in")),
		BytesOut:       atoi64(get("bytes_out")),
		UserAgent:      get("user_agent"),
		Referer:        get("referer"),
	}, true
}

func parseTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	layouts := []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02 15:04:05"}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func atoi64(s string) int64 {
	if s == "" {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}
