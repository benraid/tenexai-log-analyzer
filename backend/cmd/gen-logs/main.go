// gen-logs writes two sample Zscaler-style CSVs to the working directory:
//   - zscaler_clean.csv:           normal-looking traffic, no anomalies expected
//   - zscaler_with_anomalies.csv:  plants at least one row that triggers each
//                                  of the 7 detector rules
//
// Run: go run ./cmd/gen-logs ./sample-logs
package main

import (
	"encoding/csv"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

var header = []string{
	"timestamp", "username", "src_ip", "dst_ip", "url", "url_category",
	"action", "threat_name", "threat_category", "bytes_in", "bytes_out",
	"user_agent", "referer",
}

func main() {
	outDir := "."
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	rng := rand.New(rand.NewSource(42))

	if err := writeCSV(filepath.Join(outDir, "zscaler_clean.csv"), generateClean(rng, 600)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := writeCSV(filepath.Join(outDir, "zscaler_with_anomalies.csv"), generateWithAnomalies(rng, 600)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("wrote sample logs to", outDir)
}

func writeCSV(path string, rows [][]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write(header); err != nil {
		return err
	}
	return w.WriteAll(rows)
}

// --- Clean traffic: 5 users, 3 IPs, mostly News/Search/Business categories,
// all "allowed", normal-sized payloads, business hours UTC.
func generateClean(rng *rand.Rand, n int) [][]string {
	users := []string{"jsmith", "akhan", "lchen", "rmiller", "tperez"}
	ips := []string{"10.0.4.21", "10.0.4.22", "10.0.4.23", "10.0.4.24", "10.0.4.25"}
	cats := []string{"News", "Search Engines", "Business", "Technology", "Education"}
	uas := []string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Firefox/123.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0",
	}

	base := time.Date(2026, 5, 30, 13, 0, 0, 0, time.UTC) // 1 PM UTC start
	var rows [][]string
	for i := 0; i < n; i++ {
		ts := base.Add(time.Duration(i*30) * time.Second) // ~30s between
		rows = append(rows, []string{
			ts.Format(time.RFC3339),
			users[rng.Intn(len(users))],
			ips[rng.Intn(len(ips))],
			fmt.Sprintf("52.84.12.%d", rng.Intn(254)+1),
			fmt.Sprintf("https://example-%s.com/page%d", cats[rng.Intn(len(cats))], i),
			cats[rng.Intn(len(cats))],
			"allowed",
			"", "",
			itoa(int64(500 + rng.Intn(2000))),
			itoa(int64(800 + rng.Intn(4000))),
			uas[rng.Intn(len(uas))],
			"https://www.google.com/",
		})
	}
	return rows
}

// --- Anomalous traffic: starts from a clean baseline then plants rows for
// every rule. Each planted block is annotated with the rule it triggers.
func generateWithAnomalies(rng *rand.Rand, n int) [][]string {
	rows := generateClean(rng, n)
	base := time.Date(2026, 5, 30, 13, 0, 0, 0, time.UTC)

	// (1) threat_hit — a vendor-flagged malware detection on user akhan
	rows = append(rows, []string{
		base.Add(45 * time.Minute).Format(time.RFC3339),
		"akhan", "10.0.4.22", "185.10.20.30",
		"https://malicious-site.io/payload.bin",
		"Malicious Content", "blocked",
		"Trojan.Win32.Generic", "Trojan",
		"412", "8123",
		"Mozilla/5.0 Chrome/121", "",
	})

	// (2) malicious_category — a phishing-category request, allowed (slipped through)
	rows = append(rows, []string{
		base.Add(50 * time.Minute).Format(time.RFC3339),
		"lchen", "10.0.4.23", "194.55.66.77",
		"https://login-microsoftt.support/account",
		"Phishing", "allowed",
		"", "", "1450", "920",
		"Mozilla/5.0 Chrome/121", "",
	})

	// (3) blocked_spike_per_ip — 25 blocked requests from a single IP (10.0.4.99)
	for i := 0; i < 25; i++ {
		t := base.Add(time.Duration(60+i) * time.Minute)
		rows = append(rows, []string{
			t.Format(time.RFC3339),
			"contractor1", "10.0.4.99",
			fmt.Sprintf("203.0.113.%d", 10+i),
			fmt.Sprintf("https://suspicious-cdn.example/r%d", i),
			"Miscellaneous or Unknown", "blocked",
			"", "", "200", "0",
			"curl/8.4.0", "",
		})
	}

	// (4) high_request_rate — 60 requests from 10.0.4.42 in the same 5-min bucket
	burstStart := base.Add(90 * time.Minute)
	for i := 0; i < 60; i++ {
		t := burstStart.Add(time.Duration(i*4) * time.Second) // 4s apart -> all in one 5-min bucket
		rows = append(rows, []string{
			t.Format(time.RFC3339),
			"jsmith", "10.0.4.42",
			fmt.Sprintf("172.217.0.%d", i%200),
			fmt.Sprintf("https://api.example.com/poll?seq=%d", i),
			"Technology", "allowed",
			"", "", "180", "320",
			"Mozilla/5.0 Chrome/121", "",
		})
	}

	// (5) data_exfiltration — one giant outbound transfer (50MB)
	rows = append(rows, []string{
		base.Add(100 * time.Minute).Format(time.RFC3339),
		"rmiller", "10.0.4.24", "94.130.50.50",
		"https://upload.transferanywhere.io/dump",
		"File Sharing", "allowed",
		"", "", "1200", "52428800",
		"Mozilla/5.0 Chrome/121", "",
	})

	// (6) off_hours_activity — user "ghost" only active 02:00-04:00 UTC, no daytime traffic
	offBase := time.Date(2026, 5, 31, 2, 30, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		t := offBase.Add(time.Duration(i*15) * time.Minute)
		rows = append(rows, []string{
			t.Format(time.RFC3339),
			"ghost", "10.0.4.77", "198.51.100.10",
			fmt.Sprintf("https://internal-wiki.example.com/page%d", i),
			"Business", "allowed",
			"", "", "300", "600",
			"Mozilla/5.0 Chrome/121", "",
		})
	}

	// (7) rare_user_agent — a custom UA appearing 8 times across mixed users
	for i := 0; i < 8; i++ {
		t := base.Add(time.Duration(110+i) * time.Minute)
		rows = append(rows, []string{
			t.Format(time.RFC3339),
			"akhan", "10.0.4.22",
			fmt.Sprintf("52.84.12.%d", 50+i),
			fmt.Sprintf("https://api.example.com/data%d", i),
			"Technology", "allowed",
			"", "", "200", "400",
			"BadBot/1.0 (custom scanner)", "",
		})
	}

	return rows
}

func itoa(n int64) string { return fmt.Sprintf("%d", n) }
