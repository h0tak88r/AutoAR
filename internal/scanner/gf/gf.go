package gf

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
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
	domainDir := filepath.Join(resultsDir, opts.Domain)
	var urlsFile string
	var urlsCleanup func()

	if opts.URLsFile != "" {
		// Use provided URLs file directly (e.g., from subdomain workflow)
		urlsFile = opts.URLsFile
		urlsCleanup = func() {} // caller owns this file
		log.Printf("[INFO] Using provided URLs file: %s", urlsFile)
	} else {
		// Obtain an ephemeral temp file from the URL corpus.
		// WriteTempURLFile falls back to the on-disk all-urls.txt if found.
		var tmpErr error
		urlsFile, urlsCleanup, tmpErr = utils.WriteTempURLFile(opts.Domain)
		if tmpErr != nil {
			// No existing URLs corpus — run fastlook to build one, then retry.
			if !opts.SkipCheck {
				log.Printf("[INFO] No URLs found for %s, running fastlook first", opts.Domain)
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

	log.Printf("[INFO] Running built-in GF patterns on %s", urlsFile)
	for _, pattern := range patterns {
		outDir := filepath.Join(baseDir, pattern)
		if err := utils.EnsureDir(outDir); err != nil {
			log.Printf("[WARN] Failed to create dir for pattern %s: %v", pattern, err)
			continue
		}

		outFile := filepath.Join(outDir, ResultFileForPattern(pattern))
		if err := runGFPattern(urlsFile, pattern, outFile); err != nil {
			log.Printf("[WARN] GF pattern %s failed: %v", pattern, err)
			continue
		}

		if count, _ := countLines(outFile); count > 0 {
			log.Printf("[OK] GF %s: Found %d matches", pattern, count)
			resultFiles = append(resultFiles, outFile)
			totalMatches += count
		} else {
			log.Printf("[INFO] GF %s: No matches found", pattern)
		}
	}

	log.Printf("[OK] GF scan completed: %d total matches across all patterns", totalMatches)

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
			Pattern    string `json:"pattern"`     // raw pattern name
		}
		var findings []gfFinding
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
				findings = append(findings, gfFinding{
					TemplateID: displayName,
					MatchedAt:  l,
					Severity:   sev,
					Pattern:    patternName,
				})
			}
		}
		if len(findings) > 0 {
			if err := utils.WriteJSONToScanDir(scanID, "gf-vulnerabilities.json", findings); err != nil {
				log.Printf("[WARN] Failed to write GF JSON: %v", err)
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

	data := strings.Join(matches, "\n") + "\n"
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
