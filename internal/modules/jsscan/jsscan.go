package jsscan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/h0tak88r/AutoAR/internal/modules/urls"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
)

// Options controls JS scan behaviour.
type Options struct {
	Domain    string
	Subdomain string
	Threads   int
}

// Result summarizes JS scan output.
type Result struct {
	Domain     string
	Subdomain  string
	URLsFile   string
	VulnJSFile string
	TotalJS    int
}

// Run performs a JS-focused scan by leveraging the Go urls module.
// It ensures URLs and JS URLs are collected, then copies the JS list
// into the standard vulnerabilities/js directory for Discord/file output.
func Run(opts Options) (*Result, error) {
	if opts.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if opts.Threads <= 0 {
		opts.Threads = 100
	}

	// Collect URLs and JS URLs (writes new-results/<domain>/urls/*)
	urlRes, err := urls.CollectURLs(opts.Domain, opts.Threads, false)
	if err != nil {
		return nil, fmt.Errorf("failed to collect URLs: %w", err)
	}

	domainDir, err := utils.DomainDirInit(opts.Domain)
	if err != nil {
		return nil, fmt.Errorf("failed to init domain directory: %w", err)
	}

	jsVulnDir := filepath.Join(domainDir, "vulnerabilities", "js")
	if err := utils.EnsureDir(jsVulnDir); err != nil {
		return nil, fmt.Errorf("failed to create js vulnerabilities dir: %w", err)
	}

	sourceJS := urlRes.JSFile
	targetJS := filepath.Join(jsVulnDir, "js-urls.txt")

	// Optionally filter by subdomain
	if opts.Subdomain != "" {
		filtered, err := filterJSBySubdomain(urlRes.JSFile, opts.Subdomain, targetJS)
		if err != nil {
			return nil, err
		}
		targetJS = filtered
	} else {
		// Simple copy
		if err := copyFile(sourceJS, targetJS); err != nil {
			return nil, fmt.Errorf("failed to copy JS URLs to vulnerabilities dir: %w", err)
		}
	}

	totalJS := urlRes.JSURLs
	if opts.Subdomain != "" {
		// Recount for filtered file
		if n, err := countLines(targetJS); err == nil {
			totalJS = n
		}
	}

	return &Result{
		Domain:     opts.Domain,
		Subdomain:  opts.Subdomain,
		URLsFile:   urlRes.AllFile,
		VulnJSFile: targetJS,
		TotalJS:    totalJS,
	}, nil
}

func filterJSBySubdomain(src, subdomain, dst string) (string, error) {
	data, err := os.ReadFile(src)
	if err != nil {
		return "", fmt.Errorf("failed to read JS URLs file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	var outLines []string
	hostFragment := subdomain
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, hostFragment) {
			outLines = append(outLines, line)
		}
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", fmt.Errorf("failed to create js output dir: %w", err)
	}
	if err := os.WriteFile(dst, []byte(strings.Join(outLines, "\n")+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("failed to write filtered JS URLs: %w", err)
	}
	return dst, nil
}

func copyFile(src, dst string) error {
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, in, 0o644)
}

func countLines(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, nil
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n, nil
}
