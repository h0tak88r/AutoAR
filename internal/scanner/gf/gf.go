package gf

import (
	"fmt"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	gflib "github.com/h0tak88r/AutoAR/internal/tools/gf"
	"github.com/h0tak88r/AutoAR/internal/scanner/fastlook"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// Result holds GF scan results
type Result struct {
	Domain       string
	TotalMatches int
	ResultFiles  []string
}

// ResultFileForPattern returns the GF output filename for a pattern directory
// (e.g. img-traversal → gf-img-traversal-results.txt).
func ResultFileForPattern(pattern string) string {
	return fmt.Sprintf("gf-%s-results.txt", pattern)
}

// Options for GF scan
type Options struct {
	Domain    string // Domain name (for directory structure)
	URLsFile  string // Optional: direct path to URLs file (skips fastlook)
	SkipCheck bool   // Skip URL file validation/regeneration
}

// ScanGF runs GF pattern scanning
func ScanGF(domain string) (*Result, error) {
	return ScanGFWithOptions(Options{Domain: domain})
}

// ScanGFWithOptions runs GF pattern scanning with options
func ScanGFWithOptions(opts Options) (*Result, error) {
	if opts.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, utils.SanitizeTargetSegment(opts.Domain))
	var urlsFile string
	var urlsCleanup func()

	if opts.URLsFile != "" {
		// Use provided URLs file directly (e.g., from subdomain workflow)
		urlsFile = opts.URLsFile
		urlsCleanup = func() {} // caller owns this file
		logger.GetLogger().Infof("[INFO] Using provided URLs file: %s", urlsFile)
	} else {
		// Obtain an ephemeral temp file from the URL corpus.
		// WriteTempURLFile falls back to the on-disk all-urls.txt if found.
		var tmpErr error
		urlsFile, urlsCleanup, tmpErr = utils.WriteTempURLFile(opts.Domain)
		if tmpErr != nil {
			// No existing URLs corpus — run fastlook to build one, then retry.
			if !opts.SkipCheck {
				logger.GetLogger().Infof("[INFO] No URLs found for %s, running fastlook first", opts.Domain)
				if _, flErr := fastlook.RunFastlook(opts.Domain, nil); flErr != nil {
					return nil, fmt.Errorf("failed to run fastlook: %w", flErr)
				}
				urlsFile, urlsCleanup, tmpErr = utils.WriteTempURLFile(opts.Domain)
			}
			if tmpErr != nil {
				return nil, fmt.Errorf("URLs not available for %s: %w", opts.Domain, tmpErr)
			}
		}
	}
	defer urlsCleanup()

	baseDir := filepath.Join(domainDir, "vulnerabilities")
	if err := utils.EnsureDir(baseDir); err != nil {
		return nil, fmt.Errorf("failed to create base dir: %w", err)
	}

	patterns := []string{"debug_logic", "idor", "iext", "img-traversal", "iparams", "isubs", "jsvar", "lfi", "rce", "redirect", "sqli", "ssrf", "ssti", "xss"}
	var resultFiles []string
	totalMatches := 0

	logger.GetLogger().Infof("[INFO] Running built-in GF patterns on %s", urlsFile)
	for _, pattern := range patterns {
		outDir := filepath.Join(baseDir, pattern)
		if err := utils.EnsureDir(outDir); err != nil {
			logger.GetLogger().Infof("[WARN] Failed to create dir for pattern %s: %v", pattern, err)
			continue
		}

		outFile := filepath.Join(outDir, ResultFileForPattern(pattern))
		if err := runGFPattern(urlsFile, pattern, outFile); err != nil {
			logger.GetLogger().Infof("[WARN] GF pattern %s failed: %v", pattern, err)
			continue
		}

		if count, _ := countLines(outFile); count > 0 {
			logger.GetLogger().Infof("[OK] GF %s: Found %d matches", pattern, count)
			resultFiles = append(resultFiles, outFile)
			totalMatches += count
		} else {
			logger.GetLogger().Infof("[INFO] GF %s: No matches found", pattern)
		}
	}

	logger.GetLogger().Infof("[OK] GF scan completed: %d total matches across all patterns", totalMatches)

	// Write JSON results to scan directory (local-first)
	// Emit structured per-pattern finding objects so the dashboard can show:
	//   VULN TYPE = pattern name (e.g. gf-sqli, gf-lfi)
	//   TARGET    = the vulnerable URL
	//   SEV       = derived from pattern severity
	if scanID := utils.GetCurrentScanID(); scanID != "" {
		// Map pattern names to rough severity levels
		patternSeverity := map[string]string{
			"sqli":       "high",
			"rce":        "high",
			"lfi":        "high",
			"ssrf":       "high",
			"ssti":       "high",
			"redirect":   "medium",
			"xss":        "medium",
			"idor":       "medium",
			"iparams":    "medium",
			"debug_logic": "medium",
			"iext":       "low",
			"img-traversal": "low",
			"isubs":      "low",
			"jsvar":      "low",
		}
		type gfFinding struct {
			TemplateID string `json:"template-id"` // VULN TYPE column
			MatchedAt  string `json:"matched-at"`  // TARGET column
			Severity   string `json:"severity"`    // SEV column
			Module     string `json:"module"`
			Finding    string `json:"finding"`
			Pattern    string `json:"pattern"`     // raw pattern name
		}
		var findings []gfFinding
		seen := make(map[string]struct{})
		for _, rf := range resultFiles {
			// Extract pattern name from filename: gf-<pattern>-results.txt
			base := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(rf), "-results.txt"), ".txt")
			patternName := strings.TrimPrefix(base, "gf-")
			sev := patternSeverity[patternName]
			if sev == "" {
				sev = "low"
			}
			displayName := "gf-" + patternName
			data, err := os.ReadFile(rf)
			if err != nil {
				continue
			}
			for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				l = strings.TrimSpace(l)
				if l == "" {
					continue
				}
				// Deduplicate by pattern + endpoint + param NAMES (not values).
				// e.g. /search?q=foo and /search?q=bar → same key /search?q=
				key := displayName + "|" + normaliseURL(l)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				findings = append(findings, gfFinding{
					TemplateID: displayName,
					MatchedAt:  l,
					Severity:   sev,
					Module:     "gf-patterns",
					Finding:    "Pattern-matched URL candidate",
					Pattern:    patternName,
				})
			}
		}
		if len(findings) > 0 {
			if err := utils.WriteJSONToScanDir(scanID, "gf-vulnerabilities.json", findings); err != nil {
				logger.GetLogger().Infof("[WARN] Failed to write GF JSON: %v", err)
			}
		} else {
			_ = utils.WriteNoFindingsJSON(scanID, opts.Domain, "gf-patterns", "gf-vulnerabilities.json")
		}
	}

	return &Result{Domain: opts.Domain, TotalMatches: totalMatches, ResultFiles: resultFiles}, nil
}

func validateURLsFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	validCount := 0
	for i, line := range lines {
		if i >= 10 {
			break
		}
		if strings.HasPrefix(strings.TrimSpace(line), "http") {
			validCount++
		}
	}
	if validCount < 5 {
		return fmt.Errorf("too few valid URLs in first 10 lines")
	}
	return nil
}

func runGFPattern(urlsFile, pattern, outFile string) error {
	matches, err := gflib.ScanFile(urlsFile, pattern)
	if err != nil {
		return err
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(outFile), 0o755); err != nil {
		return err
	}

	if len(matches) == 0 {
		return utils.WriteFile(outFile, []byte(""))
	}

	// Deduplicate by endpoint+param-names before writing so dalfox
	// doesn't scan the same endpoint multiple times with different values.
	seen := make(map[string]struct{}, len(matches))
	var deduped []string
	for _, m := range matches {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		k := normaliseURL(m)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		deduped = append(deduped, m)
	}

	data := strings.Join(deduped, "\n") + "\n"
	return utils.WriteFile(outFile, []byte(data))
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

// normaliseURL strips query parameter values, keeping only the base path and
// sorted parameter names. This lets us deduplicate semantically:
//
//	https://example.com/search?q=foo&lang=en  → https://example.com/search?lang=&q=
//	https://example.com/search?q=bar&lang=fr  → https://example.com/search?lang=&q=   (same key)
func normaliseURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery == "" {
		// No parseable query — use scheme+host+path as the key.
		u2, err2 := url.Parse(raw)
		if err2 != nil {
			return raw
		}
		u2.RawQuery = ""
		u2.Fragment = ""
		return u2.String()
	}

	// Collect sorted param names only (drop values).
	q := u.Query()
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)

	normQ := make(url.Values, len(names))
	for _, k := range names {
		normQ[k] = []string{""} // blank value
	}

	u.RawQuery = normQ.Encode()
	u.Fragment = ""
	return u.String()
}
