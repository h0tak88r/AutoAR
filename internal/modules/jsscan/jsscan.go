package jsscan

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

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
	
	// Perform actual secret scanning on JS files
	log.Printf("[INFO] JS scan: Starting secret scanning on %d JS URLs...", totalJS)
	secretsFile := filepath.Join(jsVulnDir, "js-secrets.txt")
	if err := scanJSForSecrets(targetJS, secretsFile, opts.Threads); err != nil {
		log.Printf("[WARN] JS scan: Secret scanning failed: %v", err)
	} else {
		if info, err := os.Stat(secretsFile); err == nil && info.Size() > 0 {
			log.Printf("[OK] JS scan: Found secrets in JS files, saved to: %s", secretsFile)
		} else {
			log.Printf("[INFO] JS scan: No secrets found in JS files")
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

// SecretPattern represents a regex pattern for secret detection
type SecretPattern struct {
	Name       string   `yaml:"name"`
	Regex      string   `yaml:"regex"`
	Regexes    []string `yaml:"regexes"`
	Confidence string   `yaml:"confidence"`
}

// PatternConfig represents the YAML structure of regex pattern files
type PatternConfig struct {
	Patterns []struct {
		Pattern SecretPattern `yaml:"pattern"`
	} `yaml:"patterns"`
}

// scanJSForSecrets downloads JS files and scans them for secrets using regex patterns
func scanJSForSecrets(jsURLsFile, outputFile string, threads int) error {
	if threads <= 0 {
		threads = 50
	}

	// Load regex patterns
	patterns, err := loadSecretPatterns()
	if err != nil {
		return fmt.Errorf("failed to load secret patterns: %w", err)
	}
	log.Printf("[INFO] JS scan: Loaded %d secret patterns", len(patterns))

	// Read JS URLs
	jsURLs, err := readLines(jsURLsFile)
	if err != nil {
		return fmt.Errorf("failed to read JS URLs file: %w", err)
	}
	if len(jsURLs) == 0 {
		return nil
	}

	// Create output file
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	writer := bufio.NewWriter(outFile)
	defer writer.Flush()

	// Worker pool for downloading and scanning
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup
	var mu sync.Mutex
	findingsCount := 0

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 15 * time.Second,
	}

	for _, jsURL := range jsURLs {
		jsURL = strings.TrimSpace(jsURL)
		if jsURL == "" {
			continue
		}

		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Download JS file
			content, err := downloadJSFile(client, url)
			if err != nil {
				return // Silently skip failed downloads
			}

			// Scan for secrets
			findings := scanContentForSecrets(content, url, patterns)
			if len(findings) > 0 {
				mu.Lock()
				for _, finding := range findings {
					writer.WriteString(finding + "\n")
					findingsCount++
				}
				writer.Flush()
				mu.Unlock()
			}
		}(jsURL)
	}

	wg.Wait()
	log.Printf("[INFO] JS scan: Secret scanning completed, found %d secrets", findingsCount)
	return nil
}

// loadSecretPatterns loads regex patterns from the regexes directory
func loadSecretPatterns() (map[string][]*regexp.Regexp, error) {
	patterns := make(map[string][]*regexp.Regexp)

	// Try to load from confident-regexes.yaml first (high confidence patterns)
	regexesDir := "regexes"
	confidentFile := filepath.Join(regexesDir, "confident-regexes.yaml")
	if data, err := os.ReadFile(confidentFile); err == nil {
		var config PatternConfig
		if err := yaml.Unmarshal(data, &config); err == nil {
			for _, p := range config.Patterns {
				pattern := p.Pattern
				var regexes []string
				if pattern.Regex != "" {
					regexes = []string{pattern.Regex}
				} else {
					regexes = pattern.Regexes
				}
				for _, regexStr := range regexes {
					if re, err := regexp.Compile(regexStr); err == nil {
						patterns[pattern.Name] = append(patterns[pattern.Name], re)
					}
				}
			}
		}
	}

	// Also load from risky-regexes.yaml (more patterns)
	riskyFile := filepath.Join(regexesDir, "risky-regexes.yaml")
	if data, err := os.ReadFile(riskyFile); err == nil {
		var config PatternConfig
		if err := yaml.Unmarshal(data, &config); err == nil {
			for _, p := range config.Patterns {
				pattern := p.Pattern
				var regexes []string
				if pattern.Regex != "" {
					regexes = []string{pattern.Regex}
				} else {
					regexes = pattern.Regexes
				}
				for _, regexStr := range regexes {
					if re, err := regexp.Compile(regexStr); err == nil {
						patterns[pattern.Name] = append(patterns[pattern.Name], re)
					}
				}
			}
		}
	}

	return patterns, nil
}

// downloadJSFile downloads a JS file from a URL
func downloadJSFile(client *http.Client, url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("non-200 status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// scanContentForSecrets scans JS content for secrets using loaded patterns
func scanContentForSecrets(content, url string, patterns map[string][]*regexp.Regexp) []string {
	var findings []string
	seen := make(map[string]bool)

	for patternName, regexes := range patterns {
		for _, re := range regexes {
			matches := re.FindAllString(content, -1)
			for _, match := range matches {
				// Truncate long matches
				if len(match) > 200 {
					match = match[:200] + "..."
				}
				key := fmt.Sprintf("%s:%s", patternName, match)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, fmt.Sprintf("[%s] %s -> %s", patternName, url, match))
				}
			}
		}
	}

	return findings
}
