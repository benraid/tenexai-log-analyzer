// Tests for the 7 detection rules + the meanStd helper.
//
// Same-package tests (package detector, not detector_test) so we can exercise
// each rule function directly without exposing them. Pure-function rules
// make this trivial — no DB, no HTTP, no mocks.
package detector

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/braidman/tenexai-assessment/backend/internal/models"
	"github.com/google/uuid"
)

// --- test helpers ---

var (
	testUpload = uuid.MustParse("00000000-0000-0000-0000-000000000001")
	// 14:00 UTC on a Saturday — well within business hours, away from the
	// off-hours window the rules care about.
	baseTime = time.Date(2026, 1, 3, 14, 0, 0, 0, time.UTC)
)

// option is a functional option for the entry builder. Keeps test cases
// short — only the fields each test cares about appear in the test source.
type option func(*models.LogEntry)

func entry(opts ...option) models.LogEntry {
	e := models.LogEntry{
		UploadID:  testUpload,
		Timestamp: baseTime,
		SrcIP:     "10.0.0.1",
		Action:    "allowed",
		UserAgent: "Mozilla/5.0",
	}
	for _, o := range opts {
		o(&e)
	}
	return e
}

func at(t time.Time) option         { return func(e *models.LogEntry) { e.Timestamp = t } }
func srcIP(ip string) option        { return func(e *models.LogEntry) { e.SrcIP = ip } }
func user(u string) option          { return func(e *models.LogEntry) { e.Username = u } }
func category(c string) option      { return func(e *models.LogEntry) { e.URLCategory = c } }
func action(a string) option        { return func(e *models.LogEntry) { e.Action = a } }
func threat(name string) option     { return func(e *models.LogEntry) { e.ThreatName = name } }
func bytesOut(n int64) option       { return func(e *models.LogEntry) { e.BytesOut = n } }
func ua(s string) option            { return func(e *models.LogEntry) { e.UserAgent = s } }

// idsFor builds a parallel-slice of IDs the same length as entries. The
// detector's rules use these to attach anomalies to specific entries.
func idsFor(entries []models.LogEntry) []int64 {
	ids := make([]int64, len(entries))
	for i := range entries {
		ids[i] = int64(i + 1)
	}
	return ids
}

// --- meanStd ---

func TestMeanStd(t *testing.T) {
	tests := []struct {
		name     string
		xs       []float64
		wantMean float64
		wantStd  float64
	}{
		{"empty returns zero/zero", nil, 0, 0},
		{"single element has zero stddev", []float64{42}, 42, 0},
		{"all equal values have zero stddev", []float64{5, 5, 5, 5}, 5, 0},
		// Known: mean=3, population stddev = sqrt(2) ≈ 1.4142
		{"known values", []float64{1, 2, 3, 4, 5}, 3, math.Sqrt(2)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mean, std := meanStd(tt.xs)
			if math.Abs(mean-tt.wantMean) > 1e-9 {
				t.Errorf("mean = %v, want %v", mean, tt.wantMean)
			}
			if math.Abs(std-tt.wantStd) > 1e-9 {
				t.Errorf("std = %v, want %v", std, tt.wantStd)
			}
		})
	}
}

// --- Rule 1: threat_hit ---

func TestRuleThreatHit(t *testing.T) {
	tests := []struct {
		name    string
		entries []models.LogEntry
		want    int
	}{
		{"empty input → no anomalies", nil, 0},
		{"empty threat_name → not flagged", []models.LogEntry{entry()}, 0},
		{"non-empty threat → flagged", []models.LogEntry{entry(threat("Trojan.Win32.Generic"))}, 1},
		{"whitespace-only threat → not flagged", []models.LogEntry{entry(threat("   "))}, 0},
		{"two threats → two anomalies", []models.LogEntry{
			entry(threat("Trojan.Win32.Generic")),
			entry(threat("Phishing.Generic")),
		}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ruleThreatHit(testUpload, tt.entries, idsFor(tt.entries))
			if len(got) != tt.want {
				t.Fatalf("len = %d, want %d", len(got), tt.want)
			}
			for _, a := range got {
				if a.RuleName != "threat_hit" {
					t.Errorf("RuleName = %q, want threat_hit", a.RuleName)
				}
				if a.Confidence != 0.95 {
					t.Errorf("Confidence = %v, want 0.95", a.Confidence)
				}
			}
		})
	}
}

// --- Rule 2: malicious_category ---

func TestRuleMaliciousCategory(t *testing.T) {
	tests := []struct {
		name    string
		entries []models.LogEntry
		want    int
	}{
		{"empty input → no anomalies", nil, 0},
		{"benign category → not flagged", []models.LogEntry{entry(category("News"))}, 0},
		{"malware → flagged", []models.LogEntry{entry(category("Malware"))}, 1},
		{"phishing → flagged", []models.LogEntry{entry(category("phishing"))}, 1},
		{"case-insensitive matching", []models.LogEntry{entry(category("BOTNET"))}, 1},
		{"command-and-control → flagged", []models.LogEntry{entry(category("command-and-control"))}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ruleMaliciousCategory(testUpload, tt.entries, idsFor(tt.entries))
			if len(got) != tt.want {
				t.Fatalf("len = %d, want %d", len(got), tt.want)
			}
			for _, a := range got {
				if a.RuleName != "malicious_category" {
					t.Errorf("RuleName = %q, want malicious_category", a.RuleName)
				}
			}
		})
	}
}

// --- Rule 3: blocked_spike_per_ip ---

func TestRuleBlockedSpikePerIP(t *testing.T) {
	// Helper: N blocked entries from one IP.
	blockedFrom := func(ip string, n int) []models.LogEntry {
		out := make([]models.LogEntry, n)
		for i := 0; i < n; i++ {
			out[i] = entry(srcIP(ip), action("blocked"))
		}
		return out
	}

	t.Run("threshold boundary: 10 blocked → not flagged (rule is > 10)", func(t *testing.T) {
		got := ruleBlockedSpikePerIP(testUpload, blockedFrom("10.0.0.1", 10), idsFor(blockedFrom("10.0.0.1", 10)))
		if len(got) != 0 {
			t.Errorf("len = %d, want 0", len(got))
		}
	})

	t.Run("threshold boundary: 11 blocked → flagged", func(t *testing.T) {
		entries := blockedFrom("10.0.0.1", 11)
		got := ruleBlockedSpikePerIP(testUpload, entries, idsFor(entries))
		if len(got) != 1 {
			t.Fatalf("len = %d, want 1", len(got))
		}
		if got[0].RuleName != "blocked_spike_per_ip" {
			t.Errorf("RuleName = %q", got[0].RuleName)
		}
		if !strings.Contains(got[0].Explanation, "10.0.0.1") {
			t.Errorf("Explanation %q missing IP", got[0].Explanation)
		}
	})

	t.Run("allowed actions don't count", func(t *testing.T) {
		// 25 ALLOWED requests should not trigger the rule.
		entries := make([]models.LogEntry, 25)
		for i := range entries {
			entries[i] = entry(srcIP("10.0.0.1"), action("allowed"))
		}
		got := ruleBlockedSpikePerIP(testUpload, entries, idsFor(entries))
		if len(got) != 0 {
			t.Errorf("len = %d, want 0", len(got))
		}
	})

	t.Run("split across two IPs → neither over threshold", func(t *testing.T) {
		entries := append(blockedFrom("10.0.0.1", 9), blockedFrom("10.0.0.2", 9)...)
		got := ruleBlockedSpikePerIP(testUpload, entries, idsFor(entries))
		if len(got) != 0 {
			t.Errorf("len = %d, want 0", len(got))
		}
	})
}

// --- Rule 4: high_request_rate ---

func TestRuleHighRequestRate(t *testing.T) {
	t.Run("too few buckets → no z-score computed", func(t *testing.T) {
		// 3 entries = 3 buckets = below the 5-bucket guard.
		entries := []models.LogEntry{
			entry(srcIP("10.0.0.1"), at(baseTime)),
			entry(srcIP("10.0.0.2"), at(baseTime.Add(10*time.Minute))),
			entry(srcIP("10.0.0.3"), at(baseTime.Add(20*time.Minute))),
		}
		got := ruleHighRequestRate(testUpload, entries, idsFor(entries))
		if len(got) != 0 {
			t.Errorf("len = %d, want 0", len(got))
		}
	})

	t.Run("clear outlier IP → flagged", func(t *testing.T) {
		// Baseline: 30 quiet (ip, bucket) cells each with count=1. Need a
		// big enough baseline that the outlier doesn't pull mean+3σ up to
		// itself — with a tiny population, a single huge outlier becomes
		// its own threshold (the well-known weakness of z-score for outlier
		// detection at low N).
		var entries []models.LogEntry
		for i := 0; i < 30; i++ {
			entries = append(entries, entry(
				srcIP("10.0.1."+itoa(i)),
				at(baseTime.Add(time.Duration(i*10)*time.Minute)),
			))
		}
		// Outlier: 20 requests from one IP all in the same 5-min bucket.
		burstStart := baseTime.Add(48 * time.Hour) // disjoint from baseline
		for i := 0; i < 20; i++ {
			entries = append(entries, entry(
				srcIP("10.0.99.99"),
				at(burstStart.Add(time.Duration(i*2)*time.Second)),
			))
		}
		got := ruleHighRequestRate(testUpload, entries, idsFor(entries))
		if len(got) == 0 {
			t.Fatalf("expected at least one anomaly, got 0")
		}
		if !strings.Contains(got[0].Explanation, "10.0.99.99") {
			t.Errorf("expected outlier IP in explanation, got %q", got[0].Explanation)
		}
	})
}

// --- Rule 5: data_exfiltration ---

func TestRuleDataExfiltration(t *testing.T) {
	t.Run("below the 20-entry guard → not run", func(t *testing.T) {
		// One huge entry but only 5 total — guard returns nil.
		entries := []models.LogEntry{
			entry(bytesOut(100_000_000)),
		}
		for i := 0; i < 4; i++ {
			entries = append(entries, entry(bytesOut(100)))
		}
		got := ruleDataExfiltration(testUpload, entries, idsFor(entries))
		if len(got) != 0 {
			t.Errorf("len = %d, want 0", len(got))
		}
	})

	t.Run("huge transfer in a noisy population → flagged", func(t *testing.T) {
		entries := make([]models.LogEntry, 30)
		for i := 0; i < 29; i++ {
			entries[i] = entry(bytesOut(500))
		}
		// One ~50MB transfer well above the 1MB floor.
		entries[29] = entry(bytesOut(50_000_000))
		got := ruleDataExfiltration(testUpload, entries, idsFor(entries))
		if len(got) != 1 {
			t.Fatalf("len = %d, want 1", len(got))
		}
		if got[0].RuleName != "data_exfiltration" {
			t.Errorf("RuleName = %q", got[0].RuleName)
		}
	})

	t.Run("everyone's a statistical outlier but under 1MB → floor saves us", func(t *testing.T) {
		// Most entries 100 bytes, a few 10k. 10k is a stats outlier but
		// well under the 1MB absolute floor.
		entries := make([]models.LogEntry, 30)
		for i := 0; i < 27; i++ {
			entries[i] = entry(bytesOut(100))
		}
		for i := 27; i < 30; i++ {
			entries[i] = entry(bytesOut(10_000))
		}
		got := ruleDataExfiltration(testUpload, entries, idsFor(entries))
		if len(got) != 0 {
			t.Errorf("len = %d, want 0 (floor should suppress small outliers)", len(got))
		}
	})
}

// --- Rule 6: off_hours_activity ---

func TestRuleOffHoursActivity(t *testing.T) {
	atHour := func(h int) time.Time {
		return time.Date(2026, 1, 3, h, 30, 0, 0, time.UTC)
	}

	t.Run("user with only off-hours and ≥3 reqs → flagged", func(t *testing.T) {
		entries := []models.LogEntry{
			entry(user("ghost"), at(atHour(2))),
			entry(user("ghost"), at(atHour(3))),
			entry(user("ghost"), at(atHour(4))),
		}
		got := ruleOffHoursActivity(testUpload, entries, idsFor(entries))
		if len(got) != 1 {
			t.Fatalf("len = %d, want 1", len(got))
		}
		if !strings.Contains(got[0].Explanation, "ghost") {
			t.Errorf("Explanation %q missing username", got[0].Explanation)
		}
	})

	t.Run("off-hours + business hours → not flagged", func(t *testing.T) {
		entries := []models.LogEntry{
			entry(user("normal"), at(atHour(3))),
			entry(user("normal"), at(atHour(3))),
			entry(user("normal"), at(atHour(3))),
			entry(user("normal"), at(atHour(10))), // business-hours req kills it
		}
		got := ruleOffHoursActivity(testUpload, entries, idsFor(entries))
		if len(got) != 0 {
			t.Errorf("len = %d, want 0", len(got))
		}
	})

	t.Run("only 2 off-hours requests → below threshold", func(t *testing.T) {
		entries := []models.LogEntry{
			entry(user("ghost"), at(atHour(2))),
			entry(user("ghost"), at(atHour(3))),
		}
		got := ruleOffHoursActivity(testUpload, entries, idsFor(entries))
		if len(got) != 0 {
			t.Errorf("len = %d, want 0", len(got))
		}
	})
}

// --- Rule 7: rare_user_agent ---

func TestRuleRareUserAgent(t *testing.T) {
	// Baseline of 100 common-UA entries.
	commonUA := "Mozilla/5.0 (Chrome)"
	baseline := func() []models.LogEntry {
		out := make([]models.LogEntry, 100)
		for i := range out {
			out[i] = entry(ua(commonUA))
		}
		return out
	}

	t.Run("rare UA at <2% with count ≥ 5 → flagged", func(t *testing.T) {
		// Threshold: frac < 2% AND count ≥ 5. Need a large enough common
		// baseline that 5 rare-UA hits stay under the fraction threshold:
		// 5 / (400 + 5) ≈ 1.23% < 2%.
		entries := make([]models.LogEntry, 400)
		for i := range entries {
			entries[i] = entry(ua(commonUA))
		}
		for i := 0; i < 5; i++ {
			entries = append(entries, entry(ua("BadBot/1.0 (custom scanner)")))
		}
		got := ruleRareUserAgent(testUpload, entries, idsFor(entries))
		if len(got) != 1 {
			t.Fatalf("len = %d, want 1", len(got))
		}
		if !strings.Contains(got[0].Explanation, "BadBot") {
			t.Errorf("Explanation %q missing UA", got[0].Explanation)
		}
	})

	t.Run("UA appears only 3× → under count threshold", func(t *testing.T) {
		entries := baseline()
		for i := 0; i < 3; i++ {
			entries = append(entries, entry(ua("BadBot/1.0")))
		}
		got := ruleRareUserAgent(testUpload, entries, idsFor(entries))
		if len(got) != 0 {
			t.Errorf("len = %d, want 0 (count ≥ 5 not met)", len(got))
		}
	})

	t.Run("empty UA strings are ignored", func(t *testing.T) {
		entries := baseline()
		for i := 0; i < 10; i++ {
			entries = append(entries, entry(ua("")))
		}
		got := ruleRareUserAgent(testUpload, entries, idsFor(entries))
		if len(got) != 0 {
			t.Errorf("len = %d, want 0", len(got))
		}
	})
}

// --- Integration: Detect() against a synthetic dataset ---

// TestDetect_Integration runs the full detector against a small dataset
// designed to trigger every rule at least once. Mirrors the contract the
// sample-log generator exercises end-to-end.
func TestDetect_Integration(t *testing.T) {
	burstStart := baseTime.Add(2 * time.Hour)
	offBase := time.Date(2026, 1, 4, 3, 0, 0, 0, time.UTC)

	var entries []models.LogEntry

	// Baseline noise — 500 normal entries spread across many (ip, 5-min
	// bucket) cells so the high_request_rate rule has enough population to
	// compute a meaningful z-score AND so the rare_user_agent rule's <2%
	// fraction threshold can be satisfied by a 6-request anomalous UA.
	for i := 0; i < 500; i++ {
		// Vary IP across 50 addresses → 50 distinct IPs in the baseline.
		// Vary timestamp by 1 minute → spread baseline across many 5-min
		// buckets so we get ≥ 30 (ip, bucket) cells.
		entries = append(entries, entry(
			srcIP("10.0.5."+itoa(i%50)),
			at(baseTime.Add(time.Duration(i)*time.Minute)),
			user("normal"),
		))
	}
	// Rule 1: threat_hit
	entries = append(entries, entry(threat("Trojan.Win32.Generic"), category("Malware")))
	// Rule 2: malicious_category (already on the row above; add a second pure-category hit)
	entries = append(entries, entry(category("phishing")))
	// Rule 3: blocked_spike_per_ip — 15 blocked from 10.0.4.99
	for i := 0; i < 15; i++ {
		entries = append(entries, entry(srcIP("10.0.4.99"), action("blocked")))
	}
	// Rule 4: high_request_rate — 40 reqs from 10.0.4.42 in one 5-min bucket
	for i := 0; i < 40; i++ {
		entries = append(entries, entry(
			srcIP("10.0.4.42"),
			at(burstStart.Add(time.Duration(i*2)*time.Second)),
		))
	}
	// Rule 5: data_exfiltration — 50MB transfer
	entries = append(entries, entry(bytesOut(50_000_000)))
	// Rule 6: off_hours_activity — user "ghost" only between 02-05 UTC
	for i := 0; i < 4; i++ {
		entries = append(entries, entry(
			user("ghost"),
			at(offBase.Add(time.Duration(i*15)*time.Minute)),
		))
	}
	// Rule 7: rare_user_agent — 6 BadBot requests
	for i := 0; i < 6; i++ {
		entries = append(entries, entry(ua("BadBot/1.0 (custom scanner)")))
	}

	got := Detect(testUpload, entries, idsFor(entries))

	// Verify every rule fired at least once.
	seen := map[string]bool{}
	for _, a := range got {
		seen[a.RuleName] = true
		if a.Confidence <= 0 || a.Confidence > 1 {
			t.Errorf("anomaly %q has out-of-range confidence %v", a.RuleName, a.Confidence)
		}
		if a.UploadID != testUpload {
			t.Errorf("anomaly %q has wrong upload_id", a.RuleName)
		}
	}
	expected := []string{
		"threat_hit",
		"malicious_category",
		"blocked_spike_per_ip",
		"high_request_rate",
		"data_exfiltration",
		"off_hours_activity",
		"rare_user_agent",
	}
	for _, rule := range expected {
		if !seen[rule] {
			t.Errorf("rule %q did not fire", rule)
		}
	}
}

// --- helpers ---

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var sb strings.Builder
	for n > 0 {
		sb.WriteByte(byte('0' + n%10))
		n /= 10
	}
	// reverse
	s := sb.String()
	out := make([]byte, len(s))
	for i := range s {
		out[i] = s[len(s)-1-i]
	}
	return string(out)
}
