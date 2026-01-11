package gf

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	gflib "github.com/h0tak88r/AutoAR/v3/internal/tools/gf"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/fastlook"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/utils"
)

// Result holds GF scan results
type Result struct {
	Domain       string
	TotalMatches int
	ResultFiles  []string
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
	
	if opts.URLsFile != "" {
		// Use provided URLs file directly (e.g., from subdomain workflow)
		urlsFile = opts.URLsFile
		log.Printf("[INFO] Using provided URLs file: %s", urlsFile)
	} else {
		// Use default location
		urlsFile = filepath.Join(domainDir, "urls", "all-urls.txt")
	}
	
	baseDir := filepath.Join(domainDir, "vulnerabilities")

	if err := utils.EnsureDir(baseDir); err != nil {
		return nil, fmt.Errorf("failed to create base dir: %w", err)
	}

	// Only check/regenerate URLs if not skipping check and URLs file not provided
	if !opts.SkipCheck && opts.URLsFile == "" {
		// Check if URLs file exists and is valid
		if info, err := os.Stat(urlsFile); err != nil || info.Size() == 0 {
			log.Printf("[INFO] No URLs found for %s, running fastlook first", opts.Domain)
			if _, err := fastlook.RunFastlook(opts.Domain, nil); err != nil {
				return nil, fmt.Errorf("failed to run fastlook: %w", err)
			}
		}

		// Validate URLs file
		if err := validateURLsFile(urlsFile); err != nil {
			log.Printf("[WARN] URLs file appears corrupted, regenerating: %v", err)
			log.Printf("[INFO] Regenerating URLs for %s via fastlook", opts.Domain)
			if _, err := fastlook.RunFastlook(opts.Domain, nil); err != nil {
				log.Printf("[WARN] Failed to regenerate URLs via fastlook: %v", err)
			}
		}
	}

	if _, err := os.Stat(urlsFile); err != nil {
		return nil, fmt.Errorf("URLs file not found: %s", urlsFile)
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

		outFile := filepath.Join(outDir, "gf-results.txt")
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
		return os.WriteFile(outFile, []byte(""), 0o644)
	}

	data := strings.Join(matches, "\n") + "\n"
	return os.WriteFile(outFile, []byte(data), 0o644)
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
