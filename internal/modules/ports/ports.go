package ports

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	naabutool "github.com/h0tak88r/AutoAR/v3/internal/tools/naabu"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/livehosts"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/utils"
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

	// Get live hosts file (checks file first, then database)
	liveHostsFile, err := livehosts.GetLiveHostsFile(domain)
	if err != nil {
		log.Printf("[WARN] Failed to get live hosts file for %s: %v, attempting to create it", domain, err)
		// Fallback: try to create it by running livehosts
		_, err2 := livehosts.FilterLiveHosts(domain, threads, false)
		if err2 != nil {
			return nil, fmt.Errorf("failed to get live hosts for %s: %w", domain, err2)
		}
		liveHostsFile = subsFile
	}

	if liveHostsFile != subsFile {
		// File was created from database, update subsFile path
		subsFile = liveHostsFile
	}

	if _, err := os.Stat(subsFile); err != nil {
		return nil, fmt.Errorf("live hosts file not found: %s", subsFile)
	}

	log.Printf("[INFO] Running naabu port scan with %d threads (library mode)", threads)
	count, err := naabutool.ScanFromFile(subsFile, threads, outFile)
	if err != nil {
		log.Printf("[WARN] Naabu scan failed: %v", err)
		// Create empty file with "no results" message
		if f, err := os.Create(outFile); err == nil {
			f.WriteString("No open ports found (scan failed or no ports discovered).\n")
			f.Close()
		}
		count = 0
	} else {
		// Check if file is empty and write "no results" message if so
		if info, err := os.Stat(outFile); err == nil && info.Size() == 0 {
			if f, err := os.OpenFile(outFile, os.O_WRONLY|os.O_APPEND, 0644); err == nil {
				f.WriteString("No open ports found (excluding ports 80 and 443).\n")
				f.Close()
			}
		}
	}
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
