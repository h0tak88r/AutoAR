package reflection

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	kxsstool "github.com/h0tak88r/AutoAR/internal/tools/kxss"
	"github.com/h0tak88r/AutoAR/internal/modules/urls"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
)

// Result holds reflection scan results
type Result struct {
	Domain      string
	Reflections int
	OutputFile  string
}

// ScanReflection runs reflection scanning using kxss
func ScanReflection(domain string) (*Result, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, domain)
	urlsDir := filepath.Join(domainDir, "urls")
	urlsFile := filepath.Join(urlsDir, "all-urls.txt")
	outFile := filepath.Join(domainDir, "vulnerabilities", "kxss-results.txt")

	if err := utils.EnsureDir(filepath.Dir(outFile)); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %w", err)
	}

	// Ensure URLs exist via Go urls module
	if _, err := os.Stat(urlsFile); err != nil {
		log.Printf("[INFO] URLs file missing, collecting URLs for %s", domain)
		_, err := urls.CollectURLs(domain, 100)
		if err != nil {
			log.Printf("[WARN] Failed to collect URLs: %v", err)
			return nil, fmt.Errorf("failed to get URLs for %s: %w", domain, err)
		}
	}

	if _, err := os.Stat(urlsFile); err != nil {
		return nil, fmt.Errorf("URLs file not found: %s", urlsFile)
	}

	// Run embedded kxss engine
	log.Printf("[INFO] Running embedded kxss reflection scan for %s", domain)
	// Read URLs from file
	urlLines, err := readLines(urlsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read URLs file: %w", err)
	}

	kxssResults, err := kxsstool.ScanURLs(urlLines)
	if err != nil {
		log.Printf("[WARN] kxss scan failed: %v", err)
		// Create empty file to keep downstream logic consistent
		if err := os.WriteFile(outFile, []byte(""), 0o644); err != nil {
			return nil, fmt.Errorf("failed to create empty output file: %w", err)
		}
	} else {
		// Write results in the same text format as original kxss
		var lines []string
		for _, r := range kxssResults {
			lines = append(lines, fmt.Sprintf("URL: %s Param: %s Unfiltered: %v ", r.URL, r.Param, r.Chars))
		}
		if err := os.WriteFile(outFile, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
			return nil, fmt.Errorf("failed to write kxss results: %w", err)
		}
		// Filter out empty results as before
		if err := filterEmptyLines(outFile); err != nil {
			log.Printf("[WARN] Failed to filter empty lines: %v", err)
		}
	}

	count, _ := countLines(outFile)
	if count > 0 {
		log.Printf("[OK] Found %d reflection points", count)
	} else {
		log.Printf("[INFO] No reflection points found")
	}

	return &Result{
		Domain:      domain,
		Reflections: count,
		OutputFile:  outFile,
	}, nil
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
