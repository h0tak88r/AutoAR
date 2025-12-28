package jsscan

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/h0tak88r/AutoAR/v3/internal/modules/urls"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/utils"
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

	// Determine which target to use and whether to skip subdomain enumeration
	var target string
	skipSubdomainEnum := false
	
	if opts.Subdomain != "" {
		// Use subdomain mode: work with the specific subdomain
		target = strings.TrimPrefix(strings.TrimPrefix(opts.Subdomain, "http://"), "https://")
		skipSubdomainEnum = true
	} else {
		// Use domain mode: full enumeration
		target = opts.Domain
		skipSubdomainEnum = false
	}

	// Determine which domain to use for directory structure
	// If Subdomain is provided and matches Domain, use it directly (subdomain mode)
	// Otherwise, extract root domain for consistency
	dirDomain := opts.Domain
	if opts.Subdomain != "" && opts.Subdomain == opts.Domain {
		// Subdomain mode: use the subdomain itself for directory structure
		dirDomain = opts.Subdomain
	} else if opts.Subdomain != "" {
		// Extract root domain from subdomain (legacy behavior for domain mode)
		dirDomain = extractRootDomain(opts.Subdomain)
	}
	
	// Check if URL files already exist before running collection
	log.Printf("[INFO] JS scan: Initializing domain directory for: %s", dirDomain)
	domainDir, err := utils.DomainDirInit(dirDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to init domain directory: %w", err)
	}
	log.Printf("[INFO] JS scan: Domain directory: %s", domainDir)
	
	urlsDir := filepath.Join(domainDir, "urls")
	allFile := filepath.Join(urlsDir, "all-urls.txt")
	jsFile := filepath.Join(urlsDir, "js-urls.txt")
	
	log.Printf("[INFO] JS scan: Checking for existing URL files...")
	log.Printf("[INFO] JS scan: All URLs file: %s", allFile)
	log.Printf("[INFO] JS scan: JS URLs file: %s", jsFile)
	
	var urlRes *urls.Result
	
	// Check if both files exist and have content
	allFileExists := false
	jsFileExists := false
	if info, err := os.Stat(allFile); err == nil && info.Size() > 0 {
		allFileExists = true
		log.Printf("[INFO] JS scan: Found existing all-urls.txt (size: %d bytes)", info.Size())
	} else {
		log.Printf("[INFO] JS scan: all-urls.txt not found or empty: %v", err)
	}
	if info, err := os.Stat(jsFile); err == nil && info.Size() > 0 {
		jsFileExists = true
		log.Printf("[INFO] JS scan: Found existing js-urls.txt (size: %d bytes)", info.Size())
	} else {
		log.Printf("[INFO] JS scan: js-urls.txt not found or empty: %v", err)
	}
	
	if allFileExists && jsFileExists {
		// Files already exist, read them instead of re-collecting
		log.Printf("[INFO] JS scan: Using existing URL files (skipping collection)")
		allURLs, _ := readLines(allFile)
		jsURLs, _ := readLines(jsFile)
		log.Printf("[INFO] JS scan: Read %d total URLs, %d JS URLs from existing files", len(allURLs), len(jsURLs))
		urlRes = &urls.Result{
			Domain:    dirDomain,
			Threads:   opts.Threads,
			TotalURLs: len(allURLs),
			JSURLs:    len(jsURLs),
			AllFile:   allFile,
			JSFile:    jsFile,
		}
	} else {
		// Collect URLs and JS URLs (writes new-results/<domain>/urls/*)
		log.Printf("[INFO] JS scan: URL files not found or incomplete, collecting URLs...")
		log.Printf("[INFO] JS scan: Target: %s, Skip subdomain enum: %v, Threads: %d", target, skipSubdomainEnum, opts.Threads)
		// Note: urls.CollectURLs will also check for existing URLs internally
		urlRes, err = urls.CollectURLs(target, opts.Threads, skipSubdomainEnum)
		if err != nil {
			return nil, fmt.Errorf("failed to collect URLs: %w", err)
		}
		log.Printf("[INFO] JS scan: URL collection completed: %d total URLs, %d JS URLs", urlRes.TotalURLs, urlRes.JSURLs)
	}

	jsVulnDir := filepath.Join(domainDir, "vulnerabilities", "js")
	log.Printf("[INFO] JS scan: Creating vulnerabilities/js directory: %s", jsVulnDir)
	if err := utils.EnsureDir(jsVulnDir); err != nil {
		return nil, fmt.Errorf("failed to create js vulnerabilities dir: %w", err)
	}

	sourceJS := urlRes.JSFile
	targetJS := filepath.Join(jsVulnDir, "js-urls.txt")
	log.Printf("[INFO] JS scan: Source JS file: %s", sourceJS)
	log.Printf("[INFO] JS scan: Target JS file: %s", targetJS)

	// Optionally filter by subdomain
	if opts.Subdomain != "" {
		log.Printf("[INFO] JS scan: Filtering JS URLs by subdomain: %s", opts.Subdomain)
		filtered, err := filterJSBySubdomain(urlRes.JSFile, opts.Subdomain, targetJS)
		if err != nil {
			return nil, err
		}
		targetJS = filtered
		log.Printf("[INFO] JS scan: Filtered JS file saved to: %s", targetJS)
	} else {
		// Simple copy
		log.Printf("[INFO] JS scan: Copying JS URLs to vulnerabilities directory...")
		if err := copyFile(sourceJS, targetJS); err != nil {
			return nil, fmt.Errorf("failed to copy JS URLs to vulnerabilities dir: %w", err)
		}
		log.Printf("[INFO] JS scan: JS URLs copied successfully")
	}

	totalJS := urlRes.JSURLs
	if opts.Subdomain != "" {
		// Recount for filtered file
		log.Printf("[INFO] JS scan: Recounting JS URLs in filtered file...")
		if n, err := countLines(targetJS); err == nil {
			totalJS = n
			log.Printf("[INFO] JS scan: Filtered file contains %d JS URLs", totalJS)
		} else {
			log.Printf("[WARN] JS scan: Failed to count lines in filtered file: %v", err)
		}
	}
	
	log.Printf("[INFO] JS scan: Final result - %d JS URLs processed", totalJS)

	return &Result{
		Domain:     dirDomain,
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

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// extractRootDomain extracts the root domain from a subdomain
// e.g., "www.example.com" -> "example.com", "sub.sub.example.com" -> "example.com"
func extractRootDomain(host string) string {
	// Remove protocol if present
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	
	// Remove port if present
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	
	// Remove path if present
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		// Return last two parts (e.g., example.com)
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}
