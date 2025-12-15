package dalfox

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/h0tak88r/AutoAR/gomodules/utils"
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

	if _, err := exec.LookPath("dalfox"); err != nil {
		return nil, fmt.Errorf("dalfox not found in PATH")
	}

	log.Printf("[INFO] Running dalfox with %d threads", threads)
	cmd := exec.Command("dalfox", "file", inFile, "--no-spinner", "--only-poc", "r", "--ignore-return", "302,404,403", "--skip-bav", "-b", "0x88.xss.cl", "-w", fmt.Sprintf("%d", threads), "-o", outFile)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("[WARN] dalfox scan failed: %v", err)
	}

	count, _ := countLines(outFile)
	log.Printf("[OK] Dalfox scan completed, found %d findings", count)

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
