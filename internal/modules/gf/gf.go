package gf

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/h0tak88r/AutoAR/internal/modules/fastlook"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
)

// Result holds GF scan results
type Result struct {
	Domain       string
	TotalMatches int
	ResultFiles  []string
}

// ScanGF runs GF pattern scanning
func ScanGF(domain string) (*Result, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, domain)
	urlsFile := filepath.Join(domainDir, "urls", "all-urls.txt")
	baseDir := filepath.Join(domainDir, "vulnerabilities")

	if err := utils.EnsureDir(baseDir); err != nil {
		return nil, fmt.Errorf("failed to create base dir: %w", err)
	}

	// Check if URLs file exists and is valid
	if info, err := os.Stat(urlsFile); err != nil || info.Size() == 0 {
		log.Printf("[INFO] No URLs found for %s, running fastlook first", domain)
		if _, err := fastlook.RunFastlook(domain); err != nil {
			return nil, fmt.Errorf("failed to run fastlook: %w", err)
		}
	}

	// Validate URLs file
	if err := validateURLsFile(urlsFile); err != nil {
		log.Printf("[WARN] URLs file appears corrupted, regenerating: %v", err)
		if err := regenerateURLs(domain, urlsFile); err != nil {
			log.Printf("[WARN] Failed to regenerate URLs: %v", err)
		}
	}

	if _, err := os.Stat(urlsFile); err != nil {
		return nil, fmt.Errorf("URLs file not found: %s", urlsFile)
	}

	if _, err := exec.LookPath("gf"); err != nil {
		return nil, fmt.Errorf("gf tool not found in PATH")
	}

	patterns := []string{"debug_logic", "idor", "iext", "img-traversal", "iparams", "isubs", "jsvar", "lfi", "rce", "redirect", "sqli", "ssrf", "ssti", "xss"}
	var resultFiles []string
	totalMatches := 0

	log.Printf("[INFO] Running GF patterns on %s", urlsFile)
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
	return &Result{Domain: domain, TotalMatches: totalMatches, ResultFiles: resultFiles}, nil
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

func regenerateURLs(domain, outFile string) error {
	if _, err := exec.LookPath("urlfinder"); err != nil {
		return fmt.Errorf("urlfinder not found")
	}
	cmd := exec.Command("urlfinder", "-d", domain, "-all", "-silent")
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	return os.WriteFile(outFile, out, 0644)
}

func runGFPattern(urlsFile, pattern, outFile string) error {
	inFile, err := os.Open(urlsFile)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFileHandle, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer outFileHandle.Close()

	cmd := exec.Command("gf", pattern)
	cmd.Stdin = inFile
	cmd.Stdout = outFileHandle
	cmd.Stderr = os.Stderr
	return cmd.Run()
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
