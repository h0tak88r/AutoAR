package cnames

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/h0tak88r/AutoAR/gomodules/subdomains"
	"github.com/h0tak88r/AutoAR/gomodules/utils"
)

// Result holds summary information for a cnames run
type Result struct {
	Domain     string
	Records    int
	OutputFile string
}

// CollectCNAMEs mirrors the behaviour of modules/cnames.sh using Go.
// It ensures subdomains, then uses dnsx (if available) to resolve CNAME records.
func CollectCNAMEs(domain string) (*Result, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, domain)
	subsDir := filepath.Join(domainDir, "subs")
	if err := utils.EnsureDir(subsDir); err != nil {
		return nil, fmt.Errorf("failed to create subs dir: %w", err)
	}

	allSubs := filepath.Join(subsDir, "all-subs.txt")

	// Ensure we have subdomains – reuse Go subdomains module
	if _, err := os.Stat(allSubs); err != nil {
		log.Printf("[INFO] all-subs.txt missing, enumerating subdomains for %s", domain)
		subs, err := subdomains.EnumerateSubdomains(domain, 100)
		if err != nil {
			return nil, fmt.Errorf("failed to enumerate subdomains: %w", err)
		}
		if err := writeLines(allSubs, subs); err != nil {
			return nil, fmt.Errorf("failed to write %s: %w", allSubs, err)
		}
	}

	out := filepath.Join(subsDir, "cname-records.txt")

	// If dnsx is present, run it; otherwise create empty file
	if _, err := exec.LookPath("dnsx"); err == nil {
		log.Printf("[INFO] Collecting CNAME records for %s via dnsx", domain)
		inFile, err := os.Open(allSubs)
		if err != nil {
			return nil, fmt.Errorf("failed to open %s: %w", allSubs, err)
		}
		defer inFile.Close()

		if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
			return nil, fmt.Errorf("failed to create output dir: %w", err)
		}
		outFile, err := os.Create(out)
		if err != nil {
			return nil, fmt.Errorf("failed to create %s: %w", out)
		}
		defer outFile.Close()

		cmd := exec.Command("dnsx", "-cname", "-silent", "-resp", "-nc")
		cmd.Stdin = inFile
		cmd.Stdout = outFile
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			log.Printf("[WARN] dnsx CNAME collection failed: %v", err)
		}
	} else {
		log.Printf("[WARN] dnsx not found in PATH; creating empty CNAME file for %s", domain)
		if err := writeLines(out, nil); err != nil {
			return nil, fmt.Errorf("failed to initialise %s: %w", out, err)
		}
	}

	count, _ := countLines(out)
	log.Printf("[OK] Found %d CNAME records for %s", count, domain)

	return &Result{
		Domain:     domain,
		Records:    count,
		OutputFile: out,
	}, nil
}

func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if len(lines) == 0 {
		return nil
	}
	w := bufio.NewWriter(f)
	for _, l := range lines {
		if _, err := w.WriteString(l + "\n"); err != nil {
			return err
		}
	}
	return w.Flush()
}

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	n := 0
	for s.Scan() {
		n++
	}
	return n, s.Err()
}
