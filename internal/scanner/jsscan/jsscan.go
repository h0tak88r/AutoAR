package jsscan

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/scanner/urls"
	"github.com/h0tak88r/AutoAR/internal/utils"
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
// into the standard vulnerabilities/js directory for webhook/file output.
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
	logger.GetLogger().Infof("[INFO] JS scan: Initializing domain directory for: %s", dirDomain)
	domainDir, err := utils.DomainDirInit(dirDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to init domain directory: %w", err)
	}
	logger.GetLogger().Infof("[INFO] JS scan: Domain directory: %s", domainDir)

	urlsDir := filepath.Join(domainDir, "urls")
	allFile := filepath.Join(urlsDir, "all-urls.txt")
	jsFile := filepath.Join(urlsDir, "js-urls.txt")

	logger.GetLogger().Infof("[INFO] JS scan: Checking for existing URL files...")
	logger.GetLogger().Infof("[INFO] JS scan: All URLs file: %s", allFile)
	logger.GetLogger().Infof("[INFO] JS scan: JS URLs file: %s", jsFile)

	var urlRes *urls.Result

	// Check if both files exist and have content
	allFileExists := false
	jsFileExists := false
	if info, err := os.Stat(allFile); err == nil && info.Size() > 0 {
		allFileExists = true
		logger.GetLogger().Infof("[INFO] JS scan: Found existing all-urls.txt (size: %d bytes)", info.Size())
	} else {
		logger.GetLogger().Infof("[INFO] JS scan: all-urls.txt not found or empty: %v", err)
	}
	if info, err := os.Stat(jsFile); err == nil && info.Size() > 0 {
		jsFileExists = true
		logger.GetLogger().Infof("[INFO] JS scan: Found existing js-urls.txt (size: %d bytes)", info.Size())
	} else {
		logger.GetLogger().Infof("[INFO] JS scan: js-urls.txt not found or empty: %v", err)
	}

	if allFileExists && jsFileExists {
		// Files already exist, read them instead of re-collecting
		logger.GetLogger().Infof("[INFO] JS scan: Using existing URL files (skipping collection)")
		allURLs, _ := readLines(allFile)
		jsURLs, _ := readLines(jsFile)
		logger.GetLogger().Infof("[INFO] JS scan: Read %d total URLs, %d JS URLs from existing files", len(allURLs), len(jsURLs))
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
		logger.GetLogger().Infof("[INFO] JS scan: URL files not found or incomplete, collecting URLs...")
		logger.GetLogger().Infof("[INFO] JS scan: Target: %s, Skip subdomain enum: %v, Threads: %d", target, skipSubdomainEnum, opts.Threads)
		// Note: urls.CollectURLs will also check for existing URLs internally
		urlRes, err = urls.CollectURLs(target, opts.Threads, skipSubdomainEnum)
		if err != nil {
			logger.GetLogger().Infof("[WARN] JS scan: Failed to collect URLs: %v. Continuing with potentially empty list.", err)
			// Ensure we have a valid urlRes even on error to prevent nil pointer
			if urlRes == nil {
				urlRes = &urls.Result{
					Domain:  dirDomain,
					AllFile: allFile,
					JSFile:  jsFile,
				}
			}
		}
		logger.GetLogger().Infof("[INFO] JS scan: URL collection completed: %d total URLs, %d JS URLs", urlRes.TotalURLs, urlRes.JSURLs)
	}

	jsVulnDir := filepath.Join(domainDir, "vulnerabilities", "js")
	logger.GetLogger().Infof("[INFO] JS scan: Creating vulnerabilities/js directory: %s", jsVulnDir)
	if err := utils.EnsureDir(jsVulnDir); err != nil {
		return nil, fmt.Errorf("failed to create js vulnerabilities dir: %w", err)
	}

	sourceJS := urlRes.JSFile
	targetJS := filepath.Join(jsVulnDir, "js-urls.txt")
	logger.GetLogger().Infof("[INFO] JS scan: Source JS file: %s", sourceJS)
	logger.GetLogger().Infof("[INFO] JS scan: Target JS file: %s", targetJS)

	// Optionally filter by subdomain
	if opts.Subdomain != "" {
		logger.GetLogger().Infof("[INFO] JS scan: Filtering JS URLs by subdomain: %s", opts.Subdomain)
		filtered, err := filterJSBySubdomain(urlRes.JSFile, opts.Subdomain, targetJS)
		if err != nil {
			return nil, err
		}
		targetJS = filtered
		logger.GetLogger().Infof("[INFO] JS scan: Filtered JS file saved to: %s", targetJS)
	} else {
		// Simple copy
		logger.GetLogger().Infof("[INFO] JS scan: Copying JS URLs to vulnerabilities directory...")
		if err := copyFile(sourceJS, targetJS); err != nil {
			return nil, fmt.Errorf("failed to copy JS URLs to vulnerabilities dir: %w", err)
		}
		logger.GetLogger().Infof("[INFO] JS scan: JS URLs copied successfully")
	}

	totalJS := urlRes.JSURLs
	if opts.Subdomain != "" {
		// Recount for filtered file
		logger.GetLogger().Infof("[INFO] JS scan: Recounting JS URLs in filtered file...")
		if n, err := countLines(targetJS); err == nil {
			totalJS = n
			logger.GetLogger().Infof("[INFO] JS scan: Filtered file contains %d JS URLs", totalJS)
		} else {
			logger.GetLogger().Infof("[WARN] JS scan: Failed to count lines in filtered file: %v", err)
		}
	}

	// Perform pattern scanning on JS files: secrets + client-side bug candidates.
	// Both pattern sets run in a single download pass over the JS files.
	logger.GetLogger().Infof("[INFO] JS scan: Starting pattern scanning on %d JS URLs...", totalJS)
	secretPatterns, err := utils.LoadSecretPatterns("regexes")
	if err != nil {
		logger.GetLogger().Infof("[WARN] JS scan: Failed to load secret patterns: %v", err)
	}
	clientSidePatterns, err := utils.LoadPatternFile("regexes", "client-side-patterns.yaml")
	if err != nil {
		logger.GetLogger().Infof("[WARN] JS scan: Failed to load client-side patterns: %v", err)
	}

	secretsFile := filepath.Join(jsVulnDir, "js-secrets.txt")
	clientSideFile := filepath.Join(jsVulnDir, "js-clientside.txt")
	scanErr := scanJSFiles(targetJS, []jsScanTarget{
		{name: "secrets", patterns: secretPatterns, outputFile: secretsFile},
		{name: "client-side", patterns: clientSidePatterns, outputFile: clientSideFile},
	}, opts.Threads)
	if scanErr != nil {
		logger.GetLogger().Infof("[WARN] JS scan: Pattern scanning failed: %v", scanErr)
	} else {
		scanID := utils.GetCurrentScanID()
		emitSecretFindings(scanID, opts.Domain, secretsFile)
		emitClientSideFindings(scanID, opts.Domain, clientSideFile)
	}

	logger.GetLogger().Infof("[INFO] JS scan: Final result - %d JS URLs processed", totalJS)

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
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
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

func parseSecretLine(line string) (target string, secretType string, secretValue string) {
	// Expected format from scanner:
	//   [PatternName] URL -> Secret
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", ""
	}
	if strings.HasPrefix(line, "[") {
		if closeIdx := strings.Index(line, "]"); closeIdx > 1 {
			secretType = strings.TrimSpace(line[1:closeIdx])
			line = strings.TrimSpace(line[closeIdx+1:])
		}
	}
	parts := strings.SplitN(line, "->", 2)
	target = strings.TrimSpace(parts[0])
	if len(parts) == 2 {
		secretValue = strings.TrimSpace(parts[1])
	}
	return target, secretType, secretValue
}

func ternary(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}

// jsScanTarget describes one pattern set to apply to every downloaded JS file.
type jsScanTarget struct {
	name       string
	patterns   map[string][]*regexp.Regexp
	outputFile string
	count      int
}

// scanJSFiles downloads each JS file once and scans it with every target's
// pattern set, writing findings (one "[Pattern] URL -> match" line each) to
// the target's output file. Output files are always created, even when empty.
func scanJSFiles(jsURLsFile string, targets []jsScanTarget, threads int) error {
	if threads <= 0 {
		threads = 50
	}

	// Read JS URLs
	jsURLs, err := readLines(jsURLsFile)
	if err != nil {
		return fmt.Errorf("failed to read JS URLs file: %w", err)
	}

	// Create output files and writers (always created even if empty)
	writers := make([]*bufio.Writer, len(targets))
	files := make([]*os.File, len(targets))
	for i := range targets {
		f, err := os.Create(targets[i].outputFile)
		if err != nil {
			for _, opened := range files[:i] {
				opened.Close()
			}
			return fmt.Errorf("failed to create output file %s: %w", targets[i].outputFile, err)
		}
		files[i] = f
		writers[i] = bufio.NewWriter(f)
	}
	defer func() {
		for i := range files {
			writers[i].Flush()
			files[i].Close()
		}
	}()

	if len(jsURLs) == 0 {
		return nil
	}

	// Worker pool for downloading and scanning
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup
	var mu sync.Mutex

	// If every pattern set failed to load there is nothing to scan for — don't
	// download thousands of JS files just to discard them.
	anyPatterns := false
	for i := range targets {
		if len(targets[i].patterns) > 0 {
			anyPatterns = true
			break
		}
	}
	if !anyPatterns {
		logger.GetLogger().Infof("[WARN] JS scan: no patterns loaded — skipping downloads")
		return nil
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 15 * time.Second,
		// A target-controlled JS URL can 302 to a different host (e.g. cloud
		// metadata endpoints) whose body would then be secret-scanned and shipped
		// to artifacts/webhooks — refuse to follow redirects off the original host.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 && !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
				return fmt.Errorf("refusing cross-host redirect to %s", req.URL.Hostname())
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
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

			// Scan with every pattern set
			for i := range targets {
				if len(targets[i].patterns) == 0 {
					continue
				}
				findings := utils.ScanContentForSecrets(content, url, targets[i].patterns)
				if len(findings) > 0 {
					mu.Lock()
					for _, finding := range findings {
						writers[i].WriteString(finding + "\n")
						targets[i].count++
					}
					writers[i].Flush()
					mu.Unlock()
				}
			}
		}(jsURL)
	}

	wg.Wait()
	for i := range targets {
		logger.GetLogger().Infof("[INFO] JS scan: %s scanning completed, found %d matches", targets[i].name, targets[i].count)
	}
	return nil
}

// emitSecretFindings converts js-secrets.txt lines into the structured
// js-secrets-vulnerabilities.json artifact for the current scan.
func emitSecretFindings(scanID, domain, secretsFile string) {
	if info, err := os.Stat(secretsFile); err == nil && info.Size() > 0 {
		logger.GetLogger().Infof("[OK] JS scan: Found secrets in JS files, saved to: %s", secretsFile)

		if scanID != "" {
			data, readErr := os.ReadFile(secretsFile)
			if readErr == nil {
				type secretFinding struct {
					TemplateID string `json:"template-id"`
					MatchedAt  string `json:"matched-at"`
					Severity   string `json:"severity"`
					Finding    string `json:"finding"`
					Module     string `json:"module"`
					SecretType string `json:"secret_type,omitempty"`
					Secret     string `json:"secret,omitempty"`
				}
				var findings []secretFinding
				seen := make(map[string]struct{})
				for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
					if strings.TrimSpace(line) == "" {
						continue
					}
					target, secretType, secretValue := parseSecretLine(line)
					if target == "" {
						continue
					}
					key := target + "|" + secretType + "|" + secretValue
					if _, ok := seen[key]; ok {
						continue
					}
					seen[key] = struct{}{}
					findings = append(findings, secretFinding{
						TemplateID: "JS Secret Exposure" + ternary(secretType != "", " ("+secretType+")", ""),
						MatchedAt:  target,
						Severity:   "high",
						Finding:    line,
						Module:     "js-secrets",
						SecretType: secretType,
						Secret:     secretValue,
					})
				}
				if len(findings) > 0 {
					_ = utils.WriteJSONToScanDir(scanID, "js-secrets-vulnerabilities.json", findings)
				}
			}
		}
	} else {
		logger.GetLogger().Infof("[INFO] JS scan: No secrets found in JS files")
		if scanID != "" {
			_ = utils.WriteNoFindingsJSON(scanID, domain, "js-scan", "js-secrets-vulnerabilities.json")
		}
	}
}

// emitClientSideFindings converts js-clientside.txt lines into the structured
// js-clientside-vulnerabilities.json artifact. These are *candidates* — they
// flag dangerous sources/sinks/idioms that still need manual verification —
// so severities stay below the hard "high" used for exposed secrets.
func emitClientSideFindings(scanID, domain, clientSideFile string) {
	if info, err := os.Stat(clientSideFile); err == nil && info.Size() > 0 {
		logger.GetLogger().Infof("[OK] JS scan: Found client-side bug candidates, saved to: %s", clientSideFile)

		if scanID != "" {
			data, readErr := os.ReadFile(clientSideFile)
			if readErr == nil {
				type clientSideFinding struct {
					TemplateID  string `json:"template-id"`
					MatchedAt   string `json:"matched-at"`
					Severity    string `json:"severity"`
					Finding     string `json:"finding"`
					Module      string `json:"module"`
					PatternType string `json:"pattern_type,omitempty"`
					Match       string `json:"match,omitempty"`
				}
				var findings []clientSideFinding
				seen := make(map[string]struct{})
				for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
					if strings.TrimSpace(line) == "" {
						continue
					}
					target, patternType, match := parseSecretLine(line)
					if target == "" {
						continue
					}
					key := target + "|" + patternType + "|" + match
					if _, ok := seen[key]; ok {
						continue
					}
					seen[key] = struct{}{}
					findings = append(findings, clientSideFinding{
						TemplateID:  "JS Client-Side Candidate" + ternary(patternType != "", " ("+patternType+")", ""),
						MatchedAt:   target,
						Severity:    clientSideSeverity(patternType),
						Finding:     line,
						Module:      "js-clientside",
						PatternType: patternType,
						Match:       match,
					})
				}
				if len(findings) > 0 {
					_ = utils.WriteJSONToScanDir(scanID, "js-clientside-vulnerabilities.json", findings)
				}
			}
		}
	} else {
		logger.GetLogger().Infof("[INFO] JS scan: No client-side bug candidates found")
		if scanID != "" {
			_ = utils.WriteNoFindingsJSON(scanID, domain, "js-scan", "js-clientside-vulnerabilities.json")
		}
	}
}

// clientSideSeverity maps a client-side pattern class (the name prefix from
// regexes/client-side-patterns.yaml) to a severity. Sources alone are "info";
// exploitable sinks and dangerous idioms are "medium"; the rest are "low".
func clientSideSeverity(patternType string) string {
	switch {
	case strings.HasPrefix(patternType, "DOM XSS Source"):
		return "info"
	case strings.HasPrefix(patternType, "DOM XSS Sink"),
		strings.HasPrefix(patternType, "Dynamic Code Execution"),
		strings.HasPrefix(patternType, "postMessage"),
		strings.HasPrefix(patternType, "Prototype Pollution"):
		return "medium"
	default:
		return "low"
	}
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

	// Cap the body read so a malicious/huge JS response can't exhaust memory
	// (this runs across many concurrent workers). 10 MB is ample for real bundles.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return "", err
	}

	return string(body), nil
}
