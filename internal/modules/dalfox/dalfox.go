package dalfox

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	dalfoxtool "github.com/h0tak88r/AutoAR/internal/tools/dalfox"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
)

// Result holds dalfox scan results
type Result struct {
	Domain     string
	Findings   int
	OutputFile string
}

// RunDalfox runs dalfox XSS scanner
func RunDalfox(domain string, threads int) (*Result, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if threads == 0 {
		threads = 100
	}

	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, domain)
	inFile := filepath.Join(domainDir, "vulnerabilities", "xss", "gf-results.txt")
	outFile := filepath.Join(domainDir, "dalfox-results.txt")

	if err := utils.EnsureDir(filepath.Dir(outFile)); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %w", err)
	}

	// Ensure GF results exist (run GF scan first if needed)
	if _, err := os.Stat(inFile); err != nil {
		log.Printf("[INFO] No XSS candidates found, GF scan should be run first")
		return nil, fmt.Errorf("GF results file not found: %s (run GF scan first)", inFile)
	}

	if info, err := os.Stat(inFile); err != nil || info.Size() == 0 {
		log.Printf("[WARN] No XSS candidate file at %s", inFile)
		return &Result{Domain: domain, Findings: 0, OutputFile: outFile}, nil
	}

	log.Printf("[INFO] Running dalfox (library mode) with %d threads", threads)
	results, err := dalfoxtool.ScanFile(inFile, dalfoxtool.Options{Threads: threads})
	if err != nil {
		return nil, fmt.Errorf("dalfox scan failed: %w", err)
	}

	// Persist results as JSONL for compatibility with file-based workflows.
	f, err := os.Create(outFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	for _, r := range results {
		if len(r.Raw) == 0 {
			continue
		}
		if _, err := f.Write(r.Raw); err != nil {
			log.Printf("[WARN] Failed to write dalfox result for %s: %v", r.Target, err)
			continue
		}
		if _, err := f.WriteString("\n"); err != nil {
			log.Printf("[WARN] Failed to write newline for %s: %v", r.Target, err)
		}
	}

	count := len(results)
	log.Printf("[OK] Dalfox scan completed, processed %d targets", count)

	return &Result{
		Domain:     domain,
		Findings:   count,
		OutputFile: outFile,
	}, nil
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
