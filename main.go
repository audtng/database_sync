package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	apiBase           = "https://api.github.com/advisories"
	recordFileName    = "latest_advisory.json"
	httpTimeout       = 15 * time.Second
	ecosystem         = "go"
	advisoryType      = "reviewed"
	userAgent         = "GHSA-Monitor-Go/2.0"
	perPage           = 100
	maxPagesPerQuery  = 50
	defaultFetchDelay = 1200 * time.Millisecond
	maxDiffBytes      = 5 * 1024 * 1024
	apiVersion        = "2026-03-10"
)

var (
	cwesFlag       string
	severitiesFlag string
	tokenFlag      string
)

// --- Shared Data Types ---

type Advisory struct {
	GHSAID             string    `json:"ghsa_id"`
	Summary            string    `json:"summary"`
	Severity           string    `json:"severity"`
	SourceCodeLocation string    `json:"source_code_location"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type AdvisoryDetail struct {
	GHSAID      string   `json:"ghsa_id"`
	Summary     string   `json:"summary"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	References  []string `json:"references"`
}

type Record struct {
	GHSAID    string    `json:"ghsa_id"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Output struct {
	GHSAID   string `json:"ghsa_id"`
	Summary  string `json:"summary"`
	Severity string `json:"severity"`
	Diff     string `json:"diff"`
}

// --- CLI Setup ---

func main() {
	var rootCmd = &cobra.Command{
		Use:   "advisory-monitor",
		Short: "Monitors GitHub Security Advisories for Go packages",
		SilenceUsage: true,
	}

	rootCmd.PersistentFlags().StringVar(&cwesFlag, "cwes", envOrDefault("CWES", "CWE-22"), "Comma-separated list of CWEs")
	rootCmd.PersistentFlags().StringVar(&severitiesFlag, "severities", envOrDefault("SEVERITIES", "high,critical"), "Comma-separated severities")
	rootCmd.PersistentFlags().StringVar(&tokenFlag, "token", os.Getenv("GITHUB_TOKEN"), "GitHub API Token (recommended)")

	var watchCmd = &cobra.Command{
		Use:   "watch",
		Short: "Check for new advisories since the last run",
		RunE:  runWatcher,
	}

	var backfillCmd = &cobra.Command{
		Use:   "backfill",
		Short: "Fetch all historical advisories matching criteria",
		RunE:  runBackfill,
	}

	rootCmd.AddCommand(watchCmd, backfillCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// --- Watcher Logic ---

func runWatcher(cmd *cobra.Command, args []string) error {
	client := &http.Client{Timeout: httpTimeout}
	cwes := parseCWEs(cwesFlag)
	var errs []error

	for _, cwe := range cwes {
		if err := watchCWE(client, cwe); err != nil {
			errs = append(errs, fmt.Errorf("[%s] %v", cwe, err))
		}
	}

	if len(errs) > 0 {
		for _, e := range errs {
			log.Println("error:", e)
		}
		return fmt.Errorf("watcher completed with %d errors", len(errs))
	}
	return nil
}

func watchCWE(client *http.Client, cwe string) error {
	if err := os.MkdirAll(cwe, 0755); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	recordPath := filepath.Join(cwe, recordFileName)
	existing, err := loadRecord(recordPath)
	if err != nil {
		return fmt.Errorf("loading existing record: %w", err)
	}

	var since *time.Time
	if existing != nil {
		since = &existing.UpdatedAt
	}

	advisories, err := fetchMatchingAdvisories(client, cwe, since)
	if err != nil {
		return fmt.Errorf("fetching advisories: %w", err)
	}

	if len(advisories) == 0 {
		log.Printf("[%s] no new advisories match the criteria", cwe)
		return nil
	}

	sort.Slice(advisories, func(i, j int) bool {
		return advisories[i].UpdatedAt.After(advisories[j].UpdatedAt)
	})
	latest := advisories[0]

	if existing != nil && existing.GHSAID == latest.GHSAID {
		log.Printf("[%s] no new advisory: %s is already the latest known match", cwe, latest.GHSAID)
		return nil
	}

	log.Printf("[%s] new matching advisory detected: %s — %s", cwe, latest.GHSAID, latest.Summary)

	// Fetch details synchronously instead of spawning a new process
	if latest.SourceCodeLocation != "" {
		if err := fetchAndSaveDetails(client, cwe, latest.GHSAID, latest.SourceCodeLocation); err != nil {
			log.Printf("[%s] warning: failed to fetch details for %s: %v", cwe, latest.GHSAID, err)
		}
	} else {
		log.Printf("[%s] warning: %s has no source_code_location", cwe, latest.GHSAID)
	}

	if err := saveRecord(recordPath, Record{GHSAID: latest.GHSAID, UpdatedAt: latest.UpdatedAt}); err != nil {
		return fmt.Errorf("saving updated record: %w", err)
	}

	return nil
}

func fetchMatchingAdvisories(client *http.Client, cwe string, since *time.Time) ([]Advisory, error) {
	var matched []Advisory
	seen := make(map[string]bool)

	for _, sev := range parseSeverities(severitiesFlag) {
		reqURL := buildAdvisoriesURL(cwe, sev, 1, since)
		batch, err := fetchAdvisories(client, reqURL)
		if err != nil {
			return nil, fmt.Errorf("severity=%s: %w", sev, err)
		}

		for _, a := range batch {
			if !seen[a.GHSAID] {
				matched = append(matched, a)
				seen[a.GHSAID] = true
			}
		}
	}
	return matched, nil
}

// --- Backfill Logic ---

func runBackfill(cmd *cobra.Command, args []string) error {
	if tokenFlag == "" {
		log.Println("warning: API token not set. Unauthenticated rate limit is 60 req/hr.")
	}

	client := &http.Client{Timeout: httpTimeout}
	delay := fetchDelay()
	var errs []error

	for _, cwe := range parseCWEs(cwesFlag) {
		if err := backfillCWE(client, delay, cwe); err != nil {
			errs = append(errs, fmt.Errorf("[%s] %v", cwe, err))
		}
	}

	if len(errs) > 0 {
		// THIS LOOP WAS MISSING: Print the actual errors!
		for _, e := range errs {
			log.Println("error:", e)
		}
		return fmt.Errorf("backfill completed with %d errors", len(errs))
	}
	return nil
}

func backfillCWE(client *http.Client, delay time.Duration, cwe string) error {
	if err := os.MkdirAll(cwe, 0755); err != nil {
		return err
	}

	var matched []Advisory
	seen := make(map[string]bool)

	for _, sev := range parseSeverities(severitiesFlag) {
		for page := 1; page <= maxPagesPerQuery; page++ {
			reqURL := buildAdvisoriesURL(cwe, sev, page, nil)
			batch, err := fetchAdvisories(client, reqURL)
			if err != nil {
				return err
			}
			if len(batch) == 0 {
				break
			}
			for _, a := range batch {
				if !seen[a.GHSAID] {
					matched = append(matched, a)
					seen[a.GHSAID] = true
				}
			}
			if len(batch) < perPage {
				break
			}
		}
	}

	if len(matched) == 0 {
		log.Printf("[%s] no advisories currently match", cwe)
		return nil
	}

	sort.Slice(matched, func(i, j int) bool {
		return matched[i].UpdatedAt.Before(matched[j].UpdatedAt)
	})

	var fetched, skipped, failed int
	for _, a := range matched {
		outPath := filepath.Join(cwe, fmt.Sprintf("advisory_%s.json", a.GHSAID))
		if _, err := os.Stat(outPath); err == nil {
			skipped++
			continue
		}

		if a.SourceCodeLocation == "" {
			failed++
			continue
		}

		if err := fetchAndSaveDetails(client, cwe, a.GHSAID, a.SourceCodeLocation); err != nil {
			log.Printf("[%s] failed details for %s: %v", cwe, a.GHSAID, err)
			failed++
		} else {
			fetched++
		}
		time.Sleep(delay)
	}

	log.Printf("[%s] complete: %d fetched, %d skipped, %d failed", cwe, fetched, skipped, failed)

	latest := matched[len(matched)-1]
	recordPath := filepath.Join(cwe, recordFileName)
	return advanceRecord(recordPath, Record{GHSAID: latest.GHSAID, UpdatedAt: latest.UpdatedAt})
}

// --- Detail Fetching Logic (previously fetch_advisory_details.go) ---

func fetchAndSaveDetails(client *http.Client, cweDir, ghsaID, repoURL string) error {
	detail, err := fetchAdvisoryDetail(client, ghsaID)
	if err != nil {
		return err
	}

	diff, err := fetchFixDiff(client, detail, repoURL)
	if err != nil {
		log.Printf("[%s] warning: could not retrieve diff for %s: %v", cweDir, ghsaID, err)
		diff = "" // Proceed without diff
	}

	out := Output{
		GHSAID:   detail.GHSAID,
		Summary:  detail.Summary,
		Severity: detail.Severity,
		Diff:     diff,
	}

	outPath := filepath.Join(cweDir, fmt.Sprintf("advisory_%s.json", ghsaID))
	data, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		return err
	}

	log.Printf("[%s] wrote details to %s", cweDir, outPath)
	return nil
}

func fetchAdvisoryDetail(client *http.Client, ghsaID string) (*AdvisoryDetail, error) {
	reqURL := fmt.Sprintf("%s/%s", apiBase, ghsaID)
	req, _ := http.NewRequest(http.MethodGet, reqURL, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("User-Agent", userAgent)
	if tokenFlag != "" {
		req.Header.Set("Authorization", "Bearer "+tokenFlag)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var detail AdvisoryDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return nil, err
	}
	return &detail, nil
}

func fetchFixDiff(client *http.Client, detail *AdvisoryDetail, repoURL string) (string, error) {
	repoURL = strings.TrimSuffix(repoURL, "/")
	var ref string
	for _, r := range detail.References {
		if strings.HasPrefix(r, repoURL) && (strings.Contains(r, "/commit/") || strings.Contains(r, "/pull/")) {
			ref = r
			break
		}
	}
	if ref == "" {
		return "", fmt.Errorf("no commit/pull reference found")
	}

	diffURL := strings.TrimSuffix(ref, "/") + ".diff"
	req, _ := http.NewRequest(http.MethodGet, diffURL, nil)
	req.Header.Set("User-Agent", userAgent)
	if tokenFlag != "" {
		req.Header.Set("Authorization", "Bearer "+tokenFlag)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected diff status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiffBytes))
	return string(body), err
}

// --- Shared API & File Helpers ---

func buildAdvisoriesURL(cwe, severity string, page int, since *time.Time) string {
	q := url.Values{}
	q.Set("type", advisoryType)
	q.Set("ecosystem", ecosystem)
	q.Set("severity", severity)
	
	// FIX: The correct parameter is "cwes" and it expects just the digits (e.g., "22")
	cweNum := strings.TrimPrefix(strings.ToUpper(cwe), "CWE-")
	q.Set("cwes", cweNum)
	
	q.Set("sort", "updated")
	q.Set("direction", "desc")
	q.Set("per_page", strconv.Itoa(perPage))
	q.Set("page", strconv.Itoa(page))
	if since != nil {
		q.Set("updated", ">"+since.Format(time.RFC3339))
	}
	return apiBase + "?" + q.Encode()
}

func fetchAdvisories(client *http.Client, reqURL string) ([]Advisory, error) {
	req, _ := http.NewRequest(http.MethodGet, reqURL, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("User-Agent", userAgent)
	if tokenFlag != "" {
		req.Header.Set("Authorization", "Bearer "+tokenFlag)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, reqURL)
	}

	var advisories []Advisory
	json.NewDecoder(resp.Body).Decode(&advisories)
	return advisories, nil
}

func loadRecord(path string) (*Record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var rec Record
	json.Unmarshal(data, &rec)
	return &rec, nil
}

func saveRecord(path string, rec Record) error {
	data, _ := json.MarshalIndent(rec, "", "  ")
	return os.WriteFile(path, data, 0644)
}

func advanceRecord(path string, candidate Record) error {
	existing, err := loadRecord(path)
	if err != nil {
		return err
	}
	if existing != nil && !candidate.UpdatedAt.After(existing.UpdatedAt) {
		return nil
	}
	return saveRecord(path, candidate)
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseCWEs(raw string) []string {
	var out []string
	for _, s := range strings.Split(raw, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, strings.ToUpper(s))
		}
	}
	return out
}

func parseSeverities(raw string) []string {
	var out []string
	for _, s := range strings.Split(raw, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, strings.ToLower(s)) // GitHub API strictly requires lowercase
		}
	}
	return out
}

func fetchDelay() time.Duration {
	raw := os.Getenv("FETCH_DELAY_MS")
	if ms, err := strconv.Atoi(raw); err == nil && ms >= 0 {
		return time.Duration(ms) * time.Millisecond
	}
	return defaultFetchDelay
}
