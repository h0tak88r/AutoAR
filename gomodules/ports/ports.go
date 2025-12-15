package ports

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/h0tak88r/AutoAR/gomodules/livehosts"
	"github.com/h0tak88r/AutoAR/gomodules/utils"
)

// Result holds port scan results
type Result struct {
	Domain     string
	Ports      int
	OutputFile string
}

// ScanPorts runs port scanning using naabu
func ScanPorts(domain string, threads int) (*Result, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if threads == 0 {
		threads = 100
	}

	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, domain)
	subsDir := filepath.Join(domainDir, "subs")
	subsFile := filepath.Join(subsDir, "live-subs.txt")
	outFile := filepath.Join(domainDir, "ports", "ports.txt")

	if err := utils.EnsureDir(filepath.Dir(outFile)); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %w", err)
	}

	// Ensure live hosts exist via Go livehosts module
	if _, err := os.Stat(subsFile); err != nil {
		log.Printf("[INFO] Live hosts file missing, filtering live hosts for %s", domain)
		_, err := livehosts.FilterLiveHosts(domain, threads, false)
		if err != nil {
			return nil, fmt.Errorf("failed to get live hosts for %s: %w", domain, err)
		}
	}

	if _, err := os.Stat(subsFile); err != nil {
		return nil, fmt.Errorf("live hosts file not found: %s", subsFile)
	}

	if _, err := exec.LookPath("naabu"); err != nil {
		return nil, fmt.Errorf("naabu not found in PATH")
	}

	log.Printf("[INFO] Running naabu port scan with %d threads", threads)
	cmd := exec.Command("naabu", "-l", subsFile, "-tp", fmt.Sprintf("%d", threads), "-ec", "-c", "500", "-Pn", "--silent", "-rate", fmt.Sprintf("%d", threads), "-o", outFile)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("[WARN] Naabu scan failed: %v", err)
	}

	count, _ := countLines(outFile)
	log.Printf("[OK] Port scan completed, found %d open ports", count)

	return &Result{
		Domain:     domain,
		Ports:      count,
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
