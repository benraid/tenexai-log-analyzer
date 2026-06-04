// Package detector runs a set of pure-function rules over a slice of LogEntry
// and returns the resulting Anomaly records. Rules are intentionally simple,
// deterministic, and explainable — each finding carries a human-readable
// "explanation" string a SOC analyst can act on without reading code.
//
// We chose rule-based + statistical (z-score) over an LLM call because:
//   1. Explainability: every flag has a reason text and a clear threshold.
//   2. Determinism: the same input always produces the same output (easy tests).
//   3. Cost & latency: no external API call inside the upload path.
//
// An LLM is a strong fit on top of this — to *narrate* the anomalies into a
// natural-language summary — but it's a poor primary detector for this task.
package detector

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/braidman/tenexai-assessment/backend/internal/models"
	"github.com/google/uuid"
)

// Detect applies every rule and returns the flat slice of anomalies. The
// caller bulk-inserts via storage.BulkInsertAnomalies.
//
// `entryIDs` is parallel to `entries` (same length, same order) and is the
// list of database IDs assigned by storage after the COPY. Rule outputs that
// pertain to a specific row use this to set Anomaly.LogEntryID.
func Detect(uploadID uuid.UUID, entries []models.LogEntry, entryIDs []int64) []models.Anomaly {
	if len(entries) == 0 || len(entries) != len(entryIDs) {
		return nil
	}
	var out []models.Anomaly
	out = append(out, ruleThreatHit(uploadID, entries, entryIDs)...)
	out = append(out, ruleMaliciousCategory(uploadID, entries, entryIDs)...)
	out = append(out, ruleBlockedSpikePerIP(uploadID, entries, entryIDs)...)
	out = append(out, ruleHighRequestRate(uploadID, entries, entryIDs)...)
	out = append(out, ruleDataExfiltration(uploadID, entries, entryIDs)...)
	out = append(out, ruleOffHoursActivity(uploadID, entries, entryIDs)...)
	out = append(out, ruleRareUserAgent(uploadID, entries, entryIDs)...)
	return out
}

// Rule 1: any entry with a non-empty threat_name was already flagged by the
// proxy itself. High confidence — this is ground truth from the vendor.
func ruleThreatHit(uploadID uuid.UUID, entries []models.LogEntry, ids []int64) []models.Anomaly {
	var out []models.Anomaly
	for i, e := range entries {
		if strings.TrimSpace(e.ThreatName) == "" {
			continue
		}
		out = append(out, models.Anomaly{
			UploadID:    uploadID,
			LogEntryID:  ids[i],
			RuleName:    "threat_hit",
			Explanation: fmt.Sprintf("Vendor flagged threat %q (category %q) on %s", e.ThreatName, e.ThreatCategory, e.URL),
			Confidence:  0.95,
		})
	}
	return out
}

// Rule 2: requests to URL categories that are inherently risky.
func ruleMaliciousCategory(uploadID uuid.UUID, entries []models.LogEntry, ids []int64) []models.Anomaly {
	bad := map[string]bool{
		"malware":             true,
		"malware-sites":       true,
		"phishing":            true,
		"botnet":              true,
		"command-and-control": true,
		"spyware":             true,
		"cryptomining":        true,
	}
	var out []models.Anomaly
	for i, e := range entries {
		cat := strings.ToLower(strings.TrimSpace(e.URLCategory))
		if !bad[cat] {
			continue
		}
		out = append(out, models.Anomaly{
			UploadID:    uploadID,
			LogEntryID:  ids[i],
			RuleName:    "malicious_category",
			Explanation: fmt.Sprintf("Request to %s — URL category %q is on the high-risk list", e.URL, e.URLCategory),
			Confidence:  0.9,
		})
	}
	return out
}

// Rule 3: a single source IP racks up many `blocked` actions in the dataset.
// This indicates either a misconfigured client or an attacker probing
// repeatedly through the proxy. We flag the IP once and attach to its
// highest-bytes_out blocked entry as a representative row.
func ruleBlockedSpikePerIP(uploadID uuid.UUID, entries []models.LogEntry, ids []int64) []models.Anomaly {
	const threshold = 10
	type bucket struct {
		count   int
		repIdx  int
		repBOut int64
	}
	per := map[string]*bucket{}
	for i, e := range entries {
		if e.Action != "blocked" || e.SrcIP == "" {
			continue
		}
		b := per[e.SrcIP]
		if b == nil {
			b = &bucket{repIdx: i, repBOut: e.BytesOut}
			per[e.SrcIP] = b
		}
		b.count++
		if e.BytesOut > b.repBOut {
			b.repIdx = i
			b.repBOut = e.BytesOut
		}
	}
	var out []models.Anomaly
	for ip, b := range per {
		if b.count <= threshold {
			continue
		}
		out = append(out, models.Anomaly{
			UploadID:    uploadID,
			LogEntryID:  ids[b.repIdx],
			RuleName:    "blocked_spike_per_ip",
			Explanation: fmt.Sprintf("IP %s had %d blocked requests (> threshold of %d)", ip, b.count, threshold),
			Confidence:  0.8,
		})
	}
	return out
}

// Rule 4: a per-IP request rate well above the population mean. We bucket
// requests into 5-minute windows, compute mean and stddev of per-IP-per-bucket
// counts, and flag any bucket > mean + 3*sigma. This is the classic z-score
// approach — straightforward to defend in an interview ("statistical
// outlier on a Gaussian assumption; we'd validate the distribution in prod").
func ruleHighRequestRate(uploadID uuid.UUID, entries []models.LogEntry, ids []int64) []models.Anomaly {
	type key struct {
		ip     string
		bucket int64 // unix seconds, floored to 5-min
	}
	type cell struct {
		count  int
		repIdx int
	}
	cells := map[key]*cell{}
	for i, e := range entries {
		if e.SrcIP == "" {
			continue
		}
		bucket := e.Timestamp.Unix() - (e.Timestamp.Unix() % 300)
		k := key{ip: e.SrcIP, bucket: bucket}
		c := cells[k]
		if c == nil {
			c = &cell{repIdx: i}
			cells[k] = c
		}
		c.count++
	}
	if len(cells) < 5 {
		// Too small a sample to compute a meaningful z-score.
		return nil
	}
	counts := make([]float64, 0, len(cells))
	for _, c := range cells {
		counts = append(counts, float64(c.count))
	}
	mean, std := meanStd(counts)
	threshold := mean + 3*std
	if threshold < 5 {
		// Avoid flagging tiny absolute counts ("12 reqs in 5 min" isn't
		// suspicious even if it's a statistical outlier).
		threshold = 5
	}
	var out []models.Anomaly
	for k, c := range cells {
		if float64(c.count) <= threshold {
			continue
		}
		ts := time.Unix(k.bucket, 0).UTC()
		out = append(out, models.Anomaly{
			UploadID:    uploadID,
			LogEntryID:  ids[c.repIdx],
			RuleName:    "high_request_rate",
			Explanation: fmt.Sprintf("IP %s issued %d requests in the 5-min bucket starting %s (mean=%.1f, threshold=%.1f)", k.ip, c.count, ts.Format(time.RFC3339), mean, threshold),
			Confidence:  0.7,
		})
	}
	return out
}

// Rule 5: large outbound transfers. Same z-score idea on bytes_out, plus an
// absolute floor so we don't flag tiny files.
func ruleDataExfiltration(uploadID uuid.UUID, entries []models.LogEntry, ids []int64) []models.Anomaly {
	if len(entries) < 20 {
		return nil
	}
	vals := make([]float64, 0, len(entries))
	for _, e := range entries {
		vals = append(vals, float64(e.BytesOut))
	}
	mean, std := meanStd(vals)
	threshold := mean + 3*std
	if threshold < 1_000_000 { // require at least 1MB
		threshold = 1_000_000
	}
	var out []models.Anomaly
	for i, e := range entries {
		if float64(e.BytesOut) <= threshold {
			continue
		}
		out = append(out, models.Anomaly{
			UploadID:    uploadID,
			LogEntryID:  ids[i],
			RuleName:    "data_exfiltration",
			Explanation: fmt.Sprintf("Outbound transfer of %d bytes to %s (mean=%.0f, threshold=%.0f) — possible data exfiltration", e.BytesOut, e.URL, mean, threshold),
			Confidence:  0.75,
		})
	}
	return out
}

// Rule 6: requests during 02:00-04:59 UTC where the same user has no traffic
// during normal business hours (08:00-18:00 UTC). Off-hours alone is a weak
// signal; off-hours-only is stronger. Medium confidence.
func ruleOffHoursActivity(uploadID uuid.UUID, entries []models.LogEntry, ids []int64) []models.Anomaly {
	const offStart, offEnd = 2, 5
	const onStart, onEnd = 8, 18
	type stats struct {
		off, on int
		idx     int
	}
	per := map[string]*stats{}
	for i, e := range entries {
		if e.Username == "" {
			continue
		}
		hr := e.Timestamp.UTC().Hour()
		s := per[e.Username]
		if s == nil {
			s = &stats{idx: i}
			per[e.Username] = s
		}
		switch {
		case hr >= offStart && hr < offEnd:
			s.off++
			s.idx = i
		case hr >= onStart && hr < onEnd:
			s.on++
		}
	}
	var out []models.Anomaly
	for user, s := range per {
		if s.off < 3 || s.on > 0 {
			continue
		}
		out = append(out, models.Anomaly{
			UploadID:    uploadID,
			LogEntryID:  ids[s.idx],
			RuleName:    "off_hours_activity",
			Explanation: fmt.Sprintf("User %q has %d requests between 02:00-05:00 UTC and 0 during business hours", user, s.off),
			Confidence:  0.5,
		})
	}
	return out
}

// Rule 7: a user-agent string that's uncommon in the dataset (< 2%) but
// appears at least 5 times. Filters out one-offs (which are usually legitimate
// non-browser tools) and surfaces "this script ran from one IP repeatedly"
// patterns — the classic shape of an automated scanner.
func ruleRareUserAgent(uploadID uuid.UUID, entries []models.LogEntry, ids []int64) []models.Anomaly {
	total := float64(len(entries))
	type stats struct {
		count  int
		repIdx int
	}
	uas := map[string]*stats{}
	for i, e := range entries {
		ua := strings.TrimSpace(e.UserAgent)
		if ua == "" {
			continue
		}
		s := uas[ua]
		if s == nil {
			s = &stats{repIdx: i}
			uas[ua] = s
		}
		s.count++
	}
	var out []models.Anomaly
	for ua, s := range uas {
		frac := float64(s.count) / total
		if !(frac < 0.02 && s.count >= 5) {
			continue
		}
		short := ua
		if len(short) > 80 {
			short = short[:77] + "..."
		}
		out = append(out, models.Anomaly{
			UploadID:    uploadID,
			LogEntryID:  ids[s.repIdx],
			RuleName:    "rare_user_agent",
			Explanation: fmt.Sprintf("Rare User-Agent %q seen %d times (%.3f%% of traffic)", short, s.count, frac*100),
			Confidence:  0.55,
		})
	}
	// Stable order for tests / reproducible output.
	sort.Slice(out, func(i, j int) bool { return out[i].Explanation < out[j].Explanation })
	return out
}

// meanStd returns sample mean and population standard deviation.
// We use population stddev (divide by N) so a uniform distribution returns 0
// instead of an undefined value for N=1. For the rule's purpose, it's fine.
func meanStd(xs []float64) (mean, std float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean = sum / float64(len(xs))
	var sq float64
	for _, x := range xs {
		d := x - mean
		sq += d * d
	}
	std = math.Sqrt(sq / float64(len(xs)))
	return mean, std
}
