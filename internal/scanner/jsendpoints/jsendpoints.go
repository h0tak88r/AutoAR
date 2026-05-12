package jsendpoints

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// Options controls JS endpoint extraction behaviour.
type Options struct {
	Domain    string
	JSFile    string // path to js-urls.txt; if empty, derived from Domain
	Threads   int
}

// Result summarises the extraction.
type Result struct {
	Domain        string
	EndpointsFile string
	Total         int
}

// endpoint extraction regexes — ordered by priority
var endpointRegexes = []*regexp.Regexp{
	// REST API paths: /api/v1/users, /v2/auth/token, etc.
	regexp.MustCompile(`["'\x60](/(?:api|v\d+|rest|rpc|graphql|gql|admin|auth|oauth|user|account|data|internal|service|app|mobile|web|backend|public|private|endpoint)[^\s"'\x60?#]{0,200})`),
	// Relative paths that look like endpoints /path/sub or /path/sub/id
	regexp.MustCompile(`["'\x60](/[a-zA-Z0-9_-]{2,40}/[a-zA-Z0-9_/-]{2,120})[?#"'\x60\s]`),
	// fetch/axios/XMLHttpRequest calls
	regexp.MustCompile(`(?:fetch|axios\.(?:get|post|put|patch|delete|request)|XMLHttpRequest|\.open)\s*\(\s*["'\x60]([^"'\x60\s]{4,200})`),
	// URL/href assignments
	regexp.MustCompile(`(?:url|href|endpoint|baseURL|apiUrl|apiBase|API_URL|BASE_URL)\s*[:=]\s*["'\x60]([^"'\x60\s]{4,200})`),
	// route definitions: router.get('/path'), app.post('/path')
	regexp.MustCompile(`(?:router|app|express|server)\s*\.\s*(?:get|post|put|patch|delete|all|use)\s*\(\s*["'\x60](/[^"'\x60\s]{1,200})`),
}

// Run extracts API endpoints from JS files for the given domain.
func Run(opts Options) (*Result, error) {
	if opts.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if opts.Threads <= 0 {
		opts.Threads = 30
	}

	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, opts.Domain)
	jsVulnDir := filepath.Join(domainDir, "vulnerabilities", "js")
	if err := utils.EnsureDir(jsVulnDir); err != nil {
		return nil, fmt.Errorf("failed to create js dir: %w", err)
	}

	// Resolve input JS URLs file
	jsFile := opts.JSFile
	if jsFile == "" {
		jsFile = filepath.Join(domainDir, "urls", "js-urls.txt")
	}
	if _, err := os.Stat(jsFile); os.IsNotExist(err) {
		logger.GetLogger().Infof("[WARN] jsendpoints: JS URLs file not found: %s", jsFile)
		return &Result{Domain: opts.Domain}, nil
	}

	jsURLs, err := readLines(jsFile)
	if err != nil || len(jsURLs) == 0 {
		logger.GetLogger().Infof("[INFO] jsendpoints: No JS URLs to process for %s", opts.Domain)
		return &Result{Domain: opts.Domain}, nil
	}

	logger.GetLogger().Infof("[INFO] jsendpoints: Extracting endpoints from %d JS files for %s", len(jsURLs), opts.Domain)

	outFile := filepath.Join(jsVulnDir, "js-endpoints.txt")
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   15 * time.Second,
	}

	sem := make(chan struct{}, opts.Threads)
	var wg sync.WaitGroup
	var mu sync.Mutex
	endpointSet := make(map[string]struct{})

	for _, jsURL := range jsURLs {
		jsURL = strings.TrimSpace(jsURL)
		if jsURL == "" {
			continue
		}
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			content, err := downloadFile(client, u)
			if err != nil {
				return
			}
			eps := extractEndpoints(content, u)
			if len(eps) == 0 {
				return
			}
			mu.Lock()
			for _, ep := range eps {
				endpointSet[ep] = struct{}{}
			}
			mu.Unlock()
		}(jsURL)
	}
	wg.Wait()

	if len(endpointSet) == 0 {
		logger.GetLogger().Infof("[INFO] jsendpoints: No endpoints found for %s", opts.Domain)
		if scanID := utils.GetCurrentScanID(); scanID != "" {
			_ = utils.WriteNoFindingsJSON(scanID, opts.Domain, "js-endpoints", "js-endpoints.json")
		}
		return &Result{Domain: opts.Domain, EndpointsFile: outFile, Total: 0}, nil
	}

	// Write plain text output
	endpoints := make([]string, 0, len(endpointSet))
	for ep := range endpointSet {
		endpoints = append(endpoints, ep)
	}
	_ = utils.WriteLines(outFile, endpoints)
	logger.GetLogger().Infof("[OK] jsendpoints: Found %d unique endpoints for %s → %s", len(endpoints), opts.Domain, outFile)

	// Write structured JSON for the dashboard
	if scanID := utils.GetCurrentScanID(); scanID != "" {
		type epFinding struct {
			TemplateID string `json:"template-id"`
			MatchedAt  string `json:"matched-at"`
			Severity   string `json:"severity"`
			Finding    string `json:"finding"`
			Module     string `json:"module"`
			Endpoint   string `json:"endpoint"`
		}
		findings := make([]epFinding, 0, len(endpoints))
		for _, ep := range endpoints {
			findings = append(findings, epFinding{
				TemplateID: "js-endpoint",
				MatchedAt:  ep,
				Severity:   "info",
				Finding:    ep,
				Module:     "js-endpoints",
				Endpoint:   ep,
			})
		}
		if err := utils.WriteJSONToScanDir(scanID, "js-endpoints.json", findings); err != nil {
			logger.GetLogger().Infof("[WARN] jsendpoints: Failed to write JSON: %v", err)
		}
	}

	return &Result{Domain: opts.Domain, EndpointsFile: outFile, Total: len(endpoints)}, nil
}

// extractEndpoints runs all regexes against JS content and returns unique paths.
func extractEndpoints(content, sourceURL string) []string {
	seen := make(map[string]struct{})
	var out []string

	for _, re := range endpointRegexes {
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			ep := strings.TrimSpace(m[1])
			ep = strings.Trim(ep, `"'` + "`")
			if ep == "" || len(ep) < 3 || len(ep) > 300 {
				continue
			}
			// Skip common noise
			if isNoise(ep) {
				continue
			}
			if _, ok := seen[ep]; !ok {
				seen[ep] = struct{}{}
				out = append(out, ep)
			}
		}
	}
	return out
}

// isNoise filters out common false positives.
func isNoise(ep string) bool {
	noisePatterns := []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff",
		".woff2", ".ttf", ".eot", ".map", ".min.", "//", "localhost", "127.0.0.1",
		"example.com", "schema.org", "w3.org", "mozilla.org", "jquery",
	}
	lower := strings.ToLower(ep)
	for _, p := range noisePatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	// Skip template strings like ${variable}
	if strings.Contains(ep, "${") {
		return true
	}
	return false
}

func downloadFile(client *http.Client, url string) (string, error) {
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024)) // 5 MB cap per file
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, sc.Err()
}
