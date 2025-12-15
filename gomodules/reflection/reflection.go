package reflection

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/h0tak88r/AutoAR/gomodules/urls"
	"github.com/h0tak88r/AutoAR/gomodules/utils"
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

	// Run kxss if available
	if _, err := exec.LookPath("kxss"); err == nil {
		log.Printf("[INFO] Running kxss reflection scan for %s", domain)
		inFile, err := os.Open(urlsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to open URLs file: %w", err)
		}
		defer inFile.Close()

		outFileHandle, err := os.Create(outFile)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %w", err)
		}
		defer outFileHandle.Close()

		cmd := exec.Command("kxss")
		cmd.Stdin = inFile
		cmd.Stdout = outFileHandle
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			log.Printf("[WARN] kxss scan failed: %v", err)
		}

		// Filter out empty results
		if err := filterEmptyLines(outFile); err != nil {
			log.Printf("[WARN] Failed to filter empty lines: %v", err)
		}
	} else {
		log.Printf("[WARN] kxss not found, creating empty results file")
		if err := os.WriteFile(outFile, []byte(""), 0644); err != nil {
			return nil, fmt.Errorf("failed to create empty output file: %w", err)
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
