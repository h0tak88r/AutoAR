package reflection

import (
	"bufio"
	"context"
	"fmt"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/scanner/urls"
	dalfoxtool "github.com/h0tak88r/AutoAR/internal/tools/dalfox"
	kxsstool "github.com/h0tak88r/AutoAR/internal/tools/kxss"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// Result holds reflection scan results
type Result struct {
	Domain      string
	Reflections int
	OutputFile  string
}

// Options holds reflection scan options
type Options struct {
	Domain     string
	Subdomain  string // Single subdomain to scan (alternative to Domain)
	Threads    int
	Timeout    time.Duration
	URLThreads int // Concurrency for URL collection
}

// ScanReflection runs reflection scanning using kxss with timeout and concurrency support
func ScanReflection(domain string) (*Result, error) {
	return ScanReflectionWithOptions(Options{
		Domain:     domain,
		Threads:    50,               // Default concurrency for kxss scanning
		Timeout:    15 * time.Minute, // Default 15 minute timeout
		URLThreads: 150,              // Higher concurrency for URL collection
	})
}

// ScanReflectionWithOptions runs reflection scanning with custom options
func ScanReflectionWithOptions(opts Options) (*Result, error) {
	if opts.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	if opts.Threads <= 0 {
		opts.Threads = 50
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Minute
	}
	if opts.URLThreads <= 0 {
		opts.URLThreads = 150
	}

	// Determine which target to use and whether to skip subdomain enumeration
	var target string
	skipSubdomainEnum := false

	if opts.Subdomain != "" {
		// Use subdomain mode: work with the specific subdomain
		target = strings.TrimPrefix(strings.TrimPrefix(opts.Subdomain, "http://"), "https://")
		skipSubdomainEnum = true
	} else {
		// Use domain mode: full enumeration
		target = opts.Domain
		skipSubdomainEnum = false
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, opts.Domain)
	outFile := filepath.Join(domainDir, "vulnerabilities", "kxss-results.txt")

	if err := utils.EnsureDir(filepath.Dir(outFile)); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %w", err)
	}

	// Get an ephemeral temp file with the URL corpus for this domain.
	urlsFile, cleanupURLs, urlErr := utils.WriteTempURLFile(opts.Domain)
	if urlErr != nil {
		logger.GetLogger().Infof("[INFO] URLs file missing, collecting URLs for %s (threads: %d)", target, opts.URLThreads)
		urlCtx, urlCancel := context.WithTimeout(ctx, 10*time.Minute)
		defer urlCancel()
		urlErrChan := make(chan error, 1)
		go func() {
			_, err := urls.CollectURLs(target, opts.URLThreads, skipSubdomainEnum)
			urlErrChan <- err
		}()
		select {
		case err := <-urlErrChan:
			if err != nil {
				logger.GetLogger().Infof("[WARN] Failed to collect URLs: %v", err)
				return nil, fmt.Errorf("failed to get URLs for %s: %w", target, err)
			}
		case <-urlCtx.Done():
			logger.GetLogger().Infof("[WARN] URL collection timed out after 10 minutes")
			return nil, fmt.Errorf("URL collection timed out for %s", target)
		}
		// Retry after collection
		urlsFile, cleanupURLs, urlErr = utils.WriteTempURLFile(opts.Domain)
		if urlErr != nil {
			if mkErr := os.MkdirAll(filepath.Dir(outFile), 0755); mkErr != nil {
				return nil, fmt.Errorf("failed to create output directory: %w", mkErr)
			}
			_ = utils.WriteFile(outFile, []byte(""))
			return &Result{Domain: opts.Domain, Reflections: 0, OutputFile: outFile}, nil
		}
	}
	defer cleanupURLs()

	// Read URLs from file
	urlLines, err := readLines(urlsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read URLs file: %w", err)
	}

	// Filter out empty lines
	var validURLs []string
	for _, url := range urlLines {
		if strings.TrimSpace(url) != "" {
			validURLs = append(validURLs, url)
		}
	}

	// Run embedded kxss engine with concurrency and timeout
	logger.GetLogger().Infof("[INFO] Running embedded kxss reflection scan for %s (threads: %d, timeout: %v)", target, opts.Threads, opts.Timeout)
	logger.GetLogger().Infof("[INFO] Scanning %d URL(s) for reflection points", len(validURLs))

	// Scan URLs with concurrency and timeout
	kxssResults, err := scanURLsWithConcurrency(ctx, validURLs, opts.Threads)
	findings := make([]xssFinding, 0, len(kxssResults))
	for _, r := range kxssResults {
		if r.URL == "" || r.Param == "" || len(r.Chars) == 0 {
			continue
		}
		charsStr := fmt.Sprintf("%v", r.Chars)
		label := fmt.Sprintf("xss @ %s | Unfiltered: %s", r.Param, charsStr)
		findings = append(findings, xssFinding{
			TemplateID: label,
			MatchedAt:  r.URL,
			Severity:   "medium",
			Param:      r.Param,
			Unfiltered: r.Chars,
		})
	}
	if err != nil {
		if err == context.DeadlineExceeded {
			logger.GetLogger().Infof("[WARN] kxss scan timed out after %v", opts.Timeout)
		} else {
			logger.GetLogger().Infof("[WARN] kxss scan failed: %v", err)
		}
		// Create empty file to keep downstream logic consistent
		if err := utils.WriteFile(outFile, []byte("")); err != nil {
			return nil, fmt.Errorf("failed to create empty output file: %w", err)
		}
		logger.GetLogger().Infof("[INFO] No reflection points found after scanning %d URL(s)", len(validURLs))
	} else {
		// Write results in the same text format as original kxss
		var lines []string
		for _, f := range findings {
			lines = append(lines, fmt.Sprintf("URL: %s Param: %s Unfiltered: %v ", f.MatchedAt, f.Param, f.Unfiltered))
		}
		logger.GetLogger().Infof("[OK] Found %d reflection point(s) out of %d URL(s) scanned", len(findings), len(validURLs))
		if err := utils.WriteFile(outFile, []byte(strings.Join(lines, "\n"))); err != nil {
			return nil, fmt.Errorf("failed to write kxss results: %w", err)
		}
		// Filter out empty results as before
		if err := filterEmptyLines(outFile); err != nil {
			logger.GetLogger().Infof("[WARN] Failed to filter empty lines: %v", err)
		}
	}

	reflectionCount := len(findings)
	if reflectionCount > 0 {
		logger.GetLogger().Infof("[OK] Found %d reflection points", reflectionCount)
	} else {
		logger.GetLogger().Infof("[INFO] No reflection points found")
	}

	// Write structured JSON for the dashboard — one object per kxss finding.
	if scanID := utils.GetCurrentScanID(); scanID != "" {
		if len(findings) > 0 {
			if err := utils.WriteJSONToScanDir(scanID, "xss-reflection-vulnerabilities.json", findings); err != nil {
				logger.GetLogger().Infof("[WARN] Failed to write reflection JSON: %v", err)
			}
		} else {
			_ = utils.WriteNoFindingsJSON(scanID, opts.Domain, "xss-detection", "xss-reflection-vulnerabilities.json")
		}
	}

	return &Result{
		Domain:      opts.Domain,
		Reflections: reflectionCount,
		OutputFile:  outFile,
	}, nil
}

// RunDalfoxPhase reads the kxss results for a domain, filters URLs where {<} or {>}
// was unfiltered, and runs dalfox on those candidates as a separate pipeline phase.
// Returns a non-nil error only on configuration failures (not on "no findings").
func RunDalfoxPhase(domain string) error {
	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, domain)
	kxssFile := filepath.Join(domainDir, "vulnerabilities", "kxss-results.txt")

	// Parse kxss text output: "URL: <url> Param: <p> Unfiltered: [{<} {>} ...]"
	data, err := os.ReadFile(kxssFile)
	if err != nil || len(strings.TrimSpace(string(data))) == 0 {
		scanID := utils.GetCurrentScanID()
		if scanID != "" {
			_ = utils.WriteNoFindingsJSON(scanID, domain, "xss-detection", "dalfox-xss-results.json")
		}
		return nil
	}

	// Collect URLs where angle brackets were unfiltered
	seen := make(map[string]struct{})
	var candidates []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		hasAngle := strings.Contains(line, "{<}") || strings.Contains(line, "{>}")
		if !hasAngle {
			continue
		}
		// Extract the URL part: "URL: <url> Param: ..."
		urlPart := ""
		if idx := strings.Index(line, "URL: "); idx >= 0 {
			rest := line[idx+5:]
			if end := strings.Index(rest, " Param:"); end >= 0 {
				urlPart = strings.TrimSpace(rest[:end])
			} else {
				urlPart = strings.TrimSpace(rest)
			}
		}
		if urlPart != "" {
			if _, ok := seen[urlPart]; !ok {
				seen[urlPart] = struct{}{}
				candidates = append(candidates, urlPart)
			}
		}
	}

	if len(candidates) == 0 {
		logger.GetLogger().Infof("[INFO] Dalfox: no angle-bracket candidates from kxss for %s", domain)
		if scanID := utils.GetCurrentScanID(); scanID != "" {
			_ = utils.WriteNoFindingsJSON(scanID, domain, "xss-detection", "dalfox-xss-results.json")
		}
		return nil
	}

	logger.GetLogger().Infof("[INFO] Dalfox: running on %d kxss angle-bracket candidates for %s", len(candidates), domain)
	runDalfoxOnURLs(candidates, domain, 50)
	return nil
}

// xssFinding is one structured kxss result persisted to the dashboard.
type xssFinding struct {
	TemplateID string   `json:"template-id"`
	MatchedAt  string   `json:"matched-at"`
	Severity   string   `json:"severity"`
	Param      string   `json:"param"`
	Unfiltered []string `json:"unfiltered"`
}

// extractAngleBracketURLs returns unique URLs from kxss findings where
// either '{<}' or '{>}' (or both) was unfiltered — the strongest XSS signal.
func extractAngleBracketURLs(findings []xssFinding) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, f := range findings {
		for _, ch := range f.Unfiltered {
			if ch == "{<}" || ch == "{>}" {
				if _, ok := seen[f.MatchedAt]; !ok {
					seen[f.MatchedAt] = struct{}{}
					out = append(out, f.MatchedAt)
				}
				break
			}
		}
	}
	return out
}

// runDalfoxOnURLs writes the candidate URLs to a temp file, runs dalfox (Go package)
// and persists results as 'dalfox-xss-results.json' — a separate dashboard module.
func runDalfoxOnURLs(candidateURLs []string, domain string, threads int) {
	if threads <= 0 {
		threads = 50
	}
	// Write URLs to a temp file for dalfoxtool.ScanFile
	tmpFile, err := os.CreateTemp("", "dalfox-targets-*.txt")
	if err != nil {
		logger.GetLogger().Infof("[WARN] dalfox: failed to create temp file: %v", err)
		return
	}
	defer os.Remove(tmpFile.Name())
	for _, u := range candidateURLs {
		_, _ = fmt.Fprintln(tmpFile, u)
	}
	tmpFile.Close()

	results, err := dalfoxtool.ScanFile(tmpFile.Name(), dalfoxtool.Options{Threads: threads})
	if err != nil {
		logger.GetLogger().Infof("[WARN] dalfox scan failed: %v", err)
		return
	}

	scanID := utils.GetCurrentScanID()
	if scanID == "" {
		return
	}

	if len(results) == 0 {
		_ = utils.WriteNoFindingsJSON(scanID, domain, "xss-detection", "dalfox-xss-results.json")
		return
	}

	type dalfoxFinding struct {
		TemplateID string `json:"template-id"`
		MatchedAt  string `json:"matched-at"`
		Severity   string `json:"severity"`
		Type       string `json:"type,omitempty"`
		Parameter  string `json:"parameter,omitempty"`
		Payload    string `json:"payload,omitempty"`
		Module     string `json:"module"`
	}

	seen := make(map[string]struct{})
	var dfindings []dalfoxFinding
	for _, r := range results {
		fType := strings.TrimSpace(r.Type)
		if fType == "" {
			fType = "xss"
		}
		sev := strings.TrimSpace(strings.ToLower(r.Severity))
		if sev == "" {
			sev = "high"
		}
		label := fmt.Sprintf("XSS (%s)", strings.ToUpper(fType))
		key := label + "|" + r.Target + "|" + r.Parameter
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		dfindings = append(dfindings, dalfoxFinding{
			TemplateID: label,
			MatchedAt:  r.Target,
			Severity:   sev,
			Type:       fType,
			Parameter:  r.Parameter,
			Payload:    r.Payload,
			Module:     "xss-detection",
		})
	}

	if len(dfindings) > 0 {
		logger.GetLogger().Infof("[OK] Dalfox confirmed %d XSS finding(s)", len(dfindings))
		if err := utils.WriteJSONToScanDir(scanID, "dalfox-xss-results.json", dfindings); err != nil {
			logger.GetLogger().Infof("[WARN] Failed to write dalfox-xss JSON: %v", err)
		}
	} else {
		logger.GetLogger().Infof("[INFO] Dalfox found no confirmed XSS from kxss candidates")
		_ = utils.WriteNoFindingsJSON(scanID, domain, "xss-detection", "dalfox-xss-results.json")
	}
}

// scanURLsWithConcurrency scans URLs with concurrency and context timeout
func scanURLsWithConcurrency(ctx context.Context, urls []string, concurrency int) ([]kxsstool.Result, error) {
	if len(urls) == 0 {
		return []kxsstool.Result{}, nil
	}

	// Limit concurrency
	if concurrency > len(urls) {
		concurrency = len(urls)
	}

	type job struct {
		url string
		idx int
	}

	jobs := make(chan job, len(urls))
	results := make(chan kxsstool.Result, len(urls))

	// Create worker pool
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				// Check context cancellation
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Scan single URL
				urlResults, err := kxsstool.ScanURLs([]string{j.url})
				if err == nil && len(urlResults) > 0 {
					for _, r := range urlResults {
						select {
						case results <- r:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}()
	}

	// Send jobs
	go func() {
		defer close(jobs)
		for i, u := range urls {
			select {
			case jobs <- job{url: u, idx: i}:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for workers and close results channel
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var allResults []kxsstool.Result
	for r := range results {
		allResults = append(allResults, r)
	}

	// Check if context was cancelled
	if ctx.Err() != nil {
		return allResults, ctx.Err()
	}

	return allResults, nil
}

func filterEmptyLines(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	var filtered []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.Contains(trimmed, "Unfiltered: []") {
			filtered = append(filtered, line)
		}
	}

	return os.WriteFile(filePath, []byte(strings.Join(filtered, "\n")), 0644)
}

// readLines is a small helper to read non-empty lines from a file.
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func countLines(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	count := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count, nil
}
