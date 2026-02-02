package ffuf

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	ffufpkg "github.com/ffuf/ffuf/v2/pkg/ffuf"
	"github.com/ffuf/ffuf/v2/pkg/filter"
	"github.com/ffuf/ffuf/v2/pkg/input"
	"github.com/ffuf/ffuf/v2/pkg/output"
	"github.com/ffuf/ffuf/v2/pkg/runner"
	"github.com/h0tak88r/AutoAR/internal/modules/livehosts"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
)

// Options holds ffuf scan options
type Options struct {
	Target          string
	Domain          string // Domain mode: fuzz all live hosts for this domain
	Wordlist        string
	Threads         int
	Concurrency     int // Concurrency for domain mode (number of hosts to fuzz concurrently)
	Recursion       bool
	RecursionDepth  int
	Bypass403       bool
	Extensions      []string
	CustomHeaders   map[string]string
	OutputFile      string
	FollowRedirects bool
}

// Result holds ffuf scan results
type Result struct {
	Target      string
	TotalFound  int
	OutputFile  string
	UniqueSizes map[int64]bool
	HostsScanned int // For domain mode: number of hosts scanned
}

// RunFFuf executes ffuf fuzzing with custom filtering
// If Domain is set, it runs in domain mode (fuzz all live hosts for the domain)
// Otherwise, it runs in single target mode
func RunFFuf(opts Options) (*Result, error) {
	// Setup log filter to silence noisy library logs
	setupLogFilter()

	// Domain mode: fuzz all live hosts for the domain
	if opts.Domain != "" {
		return RunFFufDomainMode(opts)
	}

	// Single target mode
	if opts.Target == "" {
		return nil, fmt.Errorf("target is required (use -u for URL or -d for domain mode)")
	}

	if opts.Threads <= 0 {
		opts.Threads = 40
	}

	// Default wordlist
	if opts.Wordlist == "" {
		wordlistPath := filepath.Join(utils.GetRootDir(), "Wordlists", "quick_fuzz.txt")
		if _, err := os.Stat(wordlistPath); err == nil {
			opts.Wordlist = wordlistPath
		} else {
			return nil, fmt.Errorf("wordlist not found: %s", wordlistPath)
		}
	}
	
	// Convert wordlist to absolute path and validate it exists
	wordlistPath := opts.Wordlist
	if !filepath.IsAbs(wordlistPath) {
		// Try relative to root dir first
		absPath := filepath.Join(utils.GetRootDir(), wordlistPath)
		if _, err := os.Stat(absPath); err == nil {
			wordlistPath = absPath
		} else {
			// Try relative to current working directory
			if cwd, err := os.Getwd(); err == nil {
				absPath = filepath.Join(cwd, wordlistPath)
				if _, err := os.Stat(absPath); err == nil {
					wordlistPath = absPath
				}
			}
		}
	}
	
	// Validate wordlist file exists and is readable
	info, err := os.Stat(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("wordlist file not found or not accessible: %s (error: %w)", wordlistPath, err)
	}
	if info.Size() == 0 {
		return nil, fmt.Errorf("wordlist file is empty: %s", wordlistPath)
	}
	
	opts.Wordlist = wordlistPath
	wordlistSize := info.Size()
	
	// Count lines in wordlist for better logging
	wordlistLines := 0
	if file, err := os.Open(wordlistPath); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				wordlistLines++
			}
		}
		file.Close()
	}
	
	log.Printf("[INFO] Wordlist: %s", wordlistPath)
	log.Printf("[INFO] Wordlist size: %d bytes, %d lines", wordlistSize, wordlistLines)

	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Validate URL contains FUZZ keyword
	if !strings.Contains(opts.Target, "FUZZ") {
		return nil, fmt.Errorf("URL must contain FUZZ keyword: %s", opts.Target)
	}

	// Create ffuf config
	conf := ffufpkg.NewConfig(ctx, cancel)
	conf.Url = opts.Target
	conf.Threads = opts.Threads
	// Use absolute path for wordlist
	absWordlist, err := filepath.Abs(opts.Wordlist)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for wordlist: %w", err)
	}
	// IMPORTANT: We need to create InputProviders, not just set Wordlists
	// The InputProviders are what actually load the wordlist file
	// InputMode defaults to "clusterbomb" which works fine for single wordlist
	// Don't override it - let it use the default "clusterbomb"
	conf.InputProviders = []ffufpkg.InputProviderConfig{
		{
			Name:    "wordlist",
			Value:   absWordlist,
			Keyword: "FUZZ",
		},
	}
	// Also set Wordlists for compatibility
	conf.Wordlists = []string{absWordlist}
	log.Printf("[DEBUG] FFuf config: URL=%s, Wordlist=%s, Threads=%d", conf.Url, absWordlist, conf.Threads)
	// Config is logged above with wordlist info
	conf.Recursion = opts.Recursion
	if opts.RecursionDepth > 0 {
		conf.RecursionDepth = opts.RecursionDepth
	} else if opts.Recursion {
		conf.RecursionDepth = 3
	}
	conf.FollowRedirects = opts.FollowRedirects
	conf.Verbose = false  // Keep verbose off to reduce noise
	conf.Quiet = true     // Keep quiet, but we'll handle errors explicitly
	conf.Json = false

	// Validate config before creating input provider
	if len(conf.Wordlists) == 0 {
		return nil, fmt.Errorf("no wordlists configured")
	}
	for _, wl := range conf.Wordlists {
		if wl == "" {
			return nil, fmt.Errorf("empty wordlist path in config")
		}
		// Extract file path (remove ":keyword" suffix if present)
		filePath := wl
		if idx := strings.LastIndex(wl, ":"); idx > 0 {
			filePath = wl[:idx]
		}
		if _, err := os.Stat(filePath); err != nil {
			return nil, fmt.Errorf("wordlist file does not exist: %s (error: %w)", filePath, err)
		}
	}

	// Match only 200 status codes
	conf.MatcherManager = filter.NewMatcherManager()
	if err := conf.MatcherManager.AddMatcher("status", "200"); err != nil {
		return nil, fmt.Errorf("failed to add status matcher: %w", err)
	}

	// Filter by size (real-time deduplication)
	uniqueSizes := make(map[int64]bool)
	var sizeMutex sync.Mutex
	lastSize := int64(-1)

	// Setup output directory
	resultsDir := utils.GetResultsDir()
	outputDir := filepath.Join(resultsDir, extractDomain(opts.Target), "ffuf")
	if err := utils.EnsureDir(outputDir); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	if opts.OutputFile == "" {
		opts.OutputFile = filepath.Join(outputDir, "ffuf-results.txt")
	}

	// Create output file
	outFile, err := os.Create(opts.OutputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Custom output handler to filter duplicates in real-time
	var resultCount int
	var resultMutex sync.Mutex

	// Create job
	job := ffufpkg.NewJob(&conf)

	// Setup input provider
	inputProvider, inputErr := input.NewInputProvider(&conf)
	if err := inputErr.ErrorOrNil(); err != nil {
		return nil, fmt.Errorf("failed to create input provider: %w", err)
	}
	job.Input = inputProvider
	
	// Validate wordlist was loaded
	if inputProvider == nil {
		return nil, fmt.Errorf("input provider is nil - wordlist may not be loaded")
	}
	
	// Try to validate input provider has words by checking if we can get position/total
	// This is a best-effort check - if the provider doesn't support these methods, we continue
	var inputProviderTotal int
	if posProvider, ok := inputProvider.(interface{ Position() int }); ok {
		if totalProvider, ok := inputProvider.(interface{ Total() int }); ok {
			inputProviderTotal = totalProvider.Total()
			pos := posProvider.Position()
			log.Printf("[INFO] Input provider initialized: position=%d, total=%d", pos, inputProviderTotal)
			if inputProviderTotal == 0 {
				return nil, fmt.Errorf("input provider has 0 total words - wordlist may not be loaded correctly")
			}
			// Warn if input provider total doesn't match wordlist line count
			if wordlistLines > 0 && inputProviderTotal != wordlistLines {
				log.Printf("[WARN] Input provider total (%d) doesn't match wordlist line count (%d) - this may be normal if wordlist has comments or empty lines", inputProviderTotal, wordlistLines)
			}
		}
	} else {
		log.Printf("[INFO] Input provider initialized (cannot determine total count)")
	}

	// Setup runner
	job.Runner = runner.NewSimpleRunner(&conf, false)

	// Setup custom output that filters duplicates
	outputProvider := output.NewOutputProviderByName("json", &conf)
	if outputProvider == nil {
		return nil, fmt.Errorf("failed to create output provider")
	}

	// Override output to filter duplicates
	var resultsMutex sync.Mutex
	var bypassMutex sync.Mutex
	var webhookMutex sync.Mutex
	
	// Create HTTP client for 403 bypass attempts
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	
	// Create webhook messages file for batch sending
	webhookMessagesFile := filepath.Join(outputDir, "ffuf-webhook-messages.txt")
	webhookFile, webhookErr := os.Create(webhookMessagesFile)
	if webhookErr != nil {
		log.Printf("[WARN] Failed to create webhook messages file: %v", webhookErr)
		webhookFile = nil
	}
	
	job.Output = &customOutputProvider{
		base:         outputProvider,
		outFile:      outFile,
		uniqueSizes:  uniqueSizes,
		sizeMutex:    &sizeMutex,
		lastSize:     &lastSize,
		resultCount:  &resultCount,
		resultMutex:  &resultMutex,
		bypass403:    opts.Bypass403,
		target:       opts.Target,
		conf:         &conf,
		results:      make([]ffufpkg.Result, 0),
		resultsMutex: &resultsMutex,
		bypassTried:  make(map[string]bool),
		bypassMutex:  &bypassMutex,
		httpClient:   httpClient,
		webhookFile:  webhookFile,
		webhookMutex: &webhookMutex,
	}

	// Add custom headers if provided
	if len(opts.CustomHeaders) > 0 {
		if conf.Headers == nil {
			conf.Headers = make(map[string]string)
		}
		for k, v := range opts.CustomHeaders {
			conf.Headers[k] = v
		}
	}

	// Add extensions if provided
	if len(opts.Extensions) > 0 {
		conf.Extensions = opts.Extensions
	}

	log.Printf("[INFO] Starting fuzzing: %s", opts.Target)
	log.Printf("[INFO] Configuration: %d threads, wordlist: %d lines", opts.Threads, wordlistLines)
	if inputProviderTotal > 0 {
		log.Printf("[INFO] Will test %d payloads", inputProviderTotal)
	}

	// Validate job is properly configured before starting
	if job.Input == nil {
		return nil, fmt.Errorf("job input is nil - cannot start fuzzing")
	}
	if job.Runner == nil {
		return nil, fmt.Errorf("job runner is nil - cannot start fuzzing")
	}

	// Start the job (this runs synchronously)
	// Note: job.Start() blocks until completion
	startTime := time.Now()
	job.Start()
	duration := time.Since(startTime)

	resultMutex.Lock()
	found := resultCount
	resultMutex.Unlock()

	// Calculate statistics
	var requestsPerSec float64
	if duration.Seconds() > 0 && inputProviderTotal > 0 {
		requestsPerSec = float64(inputProviderTotal) / duration.Seconds()
	}
	
	log.Printf("[INFO] Fuzzing completed in %v", duration)
	if inputProviderTotal > 0 {
		log.Printf("[INFO] Tested %d/%d payloads (%.1f req/sec)", inputProviderTotal, inputProviderTotal, requestsPerSec)
	}
	log.Printf("[INFO] Found %d unique results", found)
	
	// Warn if job completed suspiciously fast (less than 1 second for large wordlist)
	if duration < time.Second && wordlistSize > 100000 {
		log.Printf("[WARN] Job completed very quickly (%v) for large wordlist (%d bytes, %d lines) - this may indicate an issue", duration, wordlistSize, wordlistLines)
	}

	log.Printf("[OK] FFuf fuzzing completed. Found %d unique results", found)
	log.Printf("[INFO] Results saved to: %s", opts.OutputFile)

	// Webhook file sending removed - files are now sent via utils.SendPhaseFiles from phase functions
	// Close webhook file if it was created
	webhookFilePath := filepath.Join(filepath.Dir(opts.OutputFile), "ffuf-webhook-messages.txt")
	if job.Output != nil {
		if customOutput, ok := job.Output.(*customOutputProvider); ok && customOutput.webhookFile != nil {
			customOutput.webhookMutex.Lock()
			customOutput.webhookFile.Close()
			customOutput.webhookMutex.Unlock()
			// Clean up webhook file
			os.Remove(webhookFilePath)
		}
	}

	return &Result{
		Target:      opts.Target,
		TotalFound:  found,
		OutputFile:  opts.OutputFile,
		UniqueSizes: uniqueSizes,
	}, nil
}

// customOutputProvider filters results in real-time
type customOutputProvider struct {
	base         ffufpkg.OutputProvider
	outFile      *os.File
	uniqueSizes  map[int64]bool
	sizeMutex    *sync.Mutex
	lastSize     *int64
	resultCount  *int
	resultMutex  *sync.Mutex
	bypass403    bool
	target       string
	conf         *ffufpkg.Config
	results      []ffufpkg.Result
	resultsMutex *sync.Mutex
	bypassTried  map[string]bool // Track URLs we've already tried bypass for
	bypassMutex  *sync.Mutex
	httpClient   *http.Client
	webhookFile  *os.File // File to store webhook messages for batch sending
	webhookMutex *sync.Mutex
}

func (c *customOutputProvider) Banner() {
	// Silence banner
	// c.base.Banner()
}

func (c *customOutputProvider) Finalize() error {
	// Silence finalize
	// return c.base.Finalize()
	return nil
}

func (c *customOutputProvider) Error(errstr string) {
	// Silence errors (network errors, etc.) to prevent log noise
	// c.base.Error(errstr)
}

func (c *customOutputProvider) Warning(warnstr string) {
	// Silence warning
	// c.base.Warning(warnstr)
}

func (c *customOutputProvider) Info(infostr string) {
	// Silence info
	// c.base.Info(infostr)
}

func (c *customOutputProvider) Raw(output string) {
	// Silence raw
	// c.base.Raw(output)
}

func (c *customOutputProvider) Result(resp ffufpkg.Response) {
	// Convert Response to Result for processing
	result := ffufpkg.Result{
		StatusCode:    resp.StatusCode,
		ContentLength: resp.ContentLength,
		ContentWords:  resp.ContentWords,
		ContentLines:  resp.ContentLines,
		ContentType:   resp.ContentType,
		Url:           resp.Request.Url,
		Duration:      resp.Time,
	}
	
	// Only process 200 status codes
	if resp.StatusCode != 200 {
		// If 403 bypass is enabled, try bypass techniques only for 403 responses
		if c.bypass403 && resp.StatusCode == 403 {
			// Check if we've already tried bypass for this URL to avoid duplicates
			c.bypassMutex.Lock()
			alreadyTried := c.bypassTried[result.Url]
			if !alreadyTried {
				c.bypassTried[result.Url] = true
				c.bypassMutex.Unlock()
				// Try bypass techniques asynchronously to avoid blocking
				go c.try403Bypass(resp)
			} else {
				c.bypassMutex.Unlock()
			}
		}
		c.base.Result(resp)
		return
	}

	// Real-time size filtering - skip if same size as previous
	c.sizeMutex.Lock()
	currentSize := resp.ContentLength
	if *c.lastSize == currentSize && *c.lastSize != -1 {
		c.sizeMutex.Unlock()
		c.base.Result(resp)
		return // Skip duplicate size
	}

	// Check if we've seen this size before
	if c.uniqueSizes[currentSize] {
		c.sizeMutex.Unlock()
		c.base.Result(resp)
		return // Skip duplicate size
	}

	// Mark this size as seen
	c.uniqueSizes[currentSize] = true
	*c.lastSize = currentSize
	c.sizeMutex.Unlock()

	// Write to file
	line := fmt.Sprintf("[%d] %s (Size: %d, Lines: %d, Words: %d)\n",
		resp.StatusCode, result.Url, resp.ContentLength, resp.ContentLines, resp.ContentWords)
	
	if _, err := c.outFile.WriteString(line); err != nil {
		log.Printf("[WARN] Failed to write result: %v", err)
	}

	// Store result
	c.resultsMutex.Lock()
	c.results = append(c.results, result)
	c.resultsMutex.Unlock()

	// Save webhook message to file for batch sending (instead of sending immediately)
	// Format: One-liner with all info: FFuf: {url} | Status: {status} | Size: {size} bytes | Lines: {lines} | Words: {words}
	webhookMessage := fmt.Sprintf("FFuf: `%s` | Status: %d | Size: %d bytes",
		result.Url, resp.StatusCode, resp.ContentLength)
	if resp.ContentLines > 0 {
		webhookMessage += fmt.Sprintf(" | Lines: %d", resp.ContentLines)
	}
	if resp.ContentWords > 0 {
		webhookMessage += fmt.Sprintf(" | Words: %d", resp.ContentWords)
	}
	
	// Write to webhook messages file instead of sending immediately
	if c.webhookFile != nil {
		c.webhookMutex.Lock()
		c.webhookFile.WriteString(webhookMessage + "\n")
		c.webhookMutex.Unlock()
	}

	// Also write to base output
	// Silence base result output (stops printing results to stdout)
	// c.base.Result(resp)

	// Increment counter
	c.resultMutex.Lock()
	*c.resultCount++
	c.resultMutex.Unlock()
}

func (c *customOutputProvider) PrintResult(res ffufpkg.Result) {
	c.base.PrintResult(res)
}

func (c *customOutputProvider) Progress(status ffufpkg.Progress) {
	c.base.Progress(status)
}

func (c *customOutputProvider) Cycle() {
	c.base.Cycle()
}

func (c *customOutputProvider) GetCurrentResults() []ffufpkg.Result {
	c.resultsMutex.Lock()
	defer c.resultsMutex.Unlock()
	return c.results
}

func (c *customOutputProvider) SetCurrentResults(results []ffufpkg.Result) {
	c.resultsMutex.Lock()
	c.results = results
	c.resultsMutex.Unlock()
	c.base.SetCurrentResults(results)
}

func (c *customOutputProvider) Reset() {
	c.resultsMutex.Lock()
	c.results = make([]ffufpkg.Result, 0)
	c.resultsMutex.Unlock()
	c.base.Reset()
}

func (c *customOutputProvider) SaveFile(filename, format string) error {
	return c.base.SaveFile(filename, format)
}

// try403Bypass attempts various 403 bypass techniques and processes successful bypasses
func (c *customOutputProvider) try403Bypass(originalResp ffufpkg.Response) {
	// Extract URL from request
	originalURL := originalResp.Request.Url
	if originalURL == "" {
		return
	}

	bypassTechniques := []struct {
		name   string
		header map[string]string
		path   string
	}{
		{"X-Forwarded-For", map[string]string{"X-Forwarded-For": "127.0.0.1"}, ""},
		{"X-Real-IP", map[string]string{"X-Real-IP": "127.0.0.1"}, ""},
		{"X-Originating-IP", map[string]string{"X-Originating-IP": "127.0.0.1"}, ""},
		{"X-Remote-IP", map[string]string{"X-Remote-IP": "127.0.0.1"}, ""},
		{"X-Remote-Addr", map[string]string{"X-Remote-Addr": "127.0.0.1"}, ""},
		{"X-Forwarded-Host", map[string]string{"X-Forwarded-Host": "localhost"}, ""},
		{"Referer", map[string]string{"Referer": originalURL}, ""},
		{"Path with ..;/", map[string]string{}, "..;/"},
		{"Path with %2e%2e%2f", map[string]string{}, "%2e%2e%2f"},
		{"Path with %2e%2e/", map[string]string{}, "%2e%2e/"},
		{"Path with ..%2f", map[string]string{}, "..%2f"},
		{"Path with ..%252f", map[string]string{}, "..%252f"},
		{"Path with %252e%252e%252f", map[string]string{}, "%252e%252e%252f"},
	}

	// Extract path from URL
	basePath := extractPath(originalURL)
	baseURL := strings.Split(originalURL, "?")[0] // Remove query string for path manipulation

	for _, technique := range bypassTechniques {
		var testURL string
		var headers map[string]string

		// Build test URL and headers
		if len(technique.header) > 0 {
			// Header-based bypass
			testURL = originalURL
			headers = technique.header
		} else if technique.path != "" {
			// Path-based bypass
			// Insert bypass path before the last path segment
			if strings.HasSuffix(basePath, "/") {
				testURL = baseURL + basePath[:len(basePath)-1] + technique.path + "/"
			} else {
				lastSlash := strings.LastIndex(basePath, "/")
				if lastSlash >= 0 {
					testURL = baseURL + basePath[:lastSlash+1] + technique.path + basePath[lastSlash+1:]
				} else {
					testURL = baseURL + "/" + technique.path + basePath
				}
			}
			headers = make(map[string]string)
		} else {
			continue
		}

		// Make HTTP request with bypass technique
		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}

		// Set headers
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		// Make request
		resp, err := c.httpClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Only process if bypass was successful (status 200)
		if resp.StatusCode == 200 {
			// Read response body to get content metrics
			bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // Limit to 1MB
			if err != nil {
				continue
			}

			// Calculate content metrics
			bodyStr := string(bodyBytes)
			contentLines := strings.Count(bodyStr, "\n") + 1
			contentWords := len(strings.Fields(bodyStr))
			contentLength := int64(len(bodyBytes))

			// Check if this size was already seen to avoid duplicates
			c.sizeMutex.Lock()
			if c.uniqueSizes[contentLength] {
				c.sizeMutex.Unlock()
				continue // Skip duplicate size
			}
			c.uniqueSizes[contentLength] = true
			c.sizeMutex.Unlock()

			// Create result for successful bypass
			bypassResult := ffufpkg.Result{
				StatusCode:    200,
				ContentLength: contentLength,
				ContentWords:  int64(contentWords),
				ContentLines:  int64(contentLines),
				ContentType:   resp.Header.Get("Content-Type"),
				Url:           testURL,
				Duration:      time.Since(time.Now()),
			}

			// Write to file
			line := fmt.Sprintf("[200] %s (Size: %d, Lines: %d, Words: %d) [403-Bypass: %s]\n",
				testURL, contentLength, contentLines, contentWords, technique.name)
			if _, err := c.outFile.WriteString(line); err != nil {
				log.Printf("[WARN] Failed to write bypass result: %v", err)
			}

			// Store result
			c.resultsMutex.Lock()
			c.results = append(c.results, bypassResult)
			c.resultsMutex.Unlock()

			// Save webhook message to file for batch sending
			webhookMessage := fmt.Sprintf("FFuf: `%s` | Status: 200 | Size: %d bytes", testURL, contentLength)
			if contentLines > 0 {
				webhookMessage += fmt.Sprintf(" | Lines: %d", contentLines)
			}
			if contentWords > 0 {
				webhookMessage += fmt.Sprintf(" | Words: %d", contentWords)
			}
			webhookMessage += fmt.Sprintf(" | [403-Bypass: %s]", technique.name)
			
			// Write to webhook messages file instead of sending immediately
			if c.webhookFile != nil {
				c.webhookMutex.Lock()
				c.webhookFile.WriteString(webhookMessage + "\n")
				c.webhookMutex.Unlock()
			}

			// Increment counter
			c.resultMutex.Lock()
			*c.resultCount++
			c.resultMutex.Unlock()

			// Log successful bypass
			log.Printf("[INFO] 403 bypass successful: %s -> %s (technique: %s)", originalURL, testURL, technique.name)
			
			// Stop after first successful bypass to avoid duplicates
			return
		}
	}
}

// extractDomain extracts domain from URL
func extractDomain(url string) string {
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	if idx := strings.Index(url, "?"); idx != -1 {
		url = url[:idx]
	}
	return url
}

// extractPath extracts path from URL
func extractPath(url string) string {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return url
	}
	if idx := strings.Index(url, "://"); idx != -1 {
		url = url[idx+3:]
	}
	if idx := strings.Index(url, "/"); idx != -1 {
		return url[idx:]
	}
	return "/"
}

// RunFFufDomainMode runs ffuf in domain mode:
// 1. Searches for live-subs.txt for the domain
// 2. If not found, checks database
// 3. If not in database, calls livehosts module to collect live hosts
// 4. Tests each host per line against the quick fuzz wordlist with concurrency
func RunFFufDomainMode(opts Options) (*Result, error) {
	if opts.Domain == "" {
		return nil, fmt.Errorf("domain is required for domain mode")
	}

	// Set default concurrency if not specified
	if opts.Concurrency <= 0 {
		opts.Concurrency = 5 // Default: 5 hosts concurrently
	}

	// Default wordlist
	if opts.Wordlist == "" {
		wordlistPath := filepath.Join(utils.GetRootDir(), "Wordlists", "quick_fuzz.txt")
		if _, err := os.Stat(wordlistPath); err == nil {
			opts.Wordlist = wordlistPath
		} else {
			return nil, fmt.Errorf("wordlist not found: %s", wordlistPath)
		}
	}
	
	// Convert wordlist to absolute path and validate it exists
	wordlistPath := opts.Wordlist
	if !filepath.IsAbs(wordlistPath) {
		// Try relative to root dir first
		absPath := filepath.Join(utils.GetRootDir(), wordlistPath)
		if _, err := os.Stat(absPath); err == nil {
			wordlistPath = absPath
		} else {
			// Try relative to current working directory
			if cwd, err := os.Getwd(); err == nil {
				absPath = filepath.Join(cwd, wordlistPath)
				if _, err := os.Stat(absPath); err == nil {
					wordlistPath = absPath
				}
			}
		}
	}
	
	// Validate wordlist file exists and is readable
	info, err := os.Stat(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("wordlist file not found or not accessible: %s (error: %w)", wordlistPath, err)
	}
	if info.Size() == 0 {
		return nil, fmt.Errorf("wordlist file is empty: %s", wordlistPath)
	}
	
	opts.Wordlist = wordlistPath
	log.Printf("[DEBUG] Using wordlist: %s (size: %d bytes)", wordlistPath, info.Size())

	log.Printf("[INFO] Starting ffuf domain mode for %s", opts.Domain)
	log.Printf("[INFO] Concurrency: %d hosts", opts.Concurrency)
	log.Printf("[INFO] Wordlist: %s", opts.Wordlist)

	// Step 1: Get live hosts file (checks file, then database, then collects)
	liveHostsFile, err := livehosts.GetLiveHostsFile(opts.Domain)
	if err != nil {
		// File not found in results dir or database, run livehosts module
		log.Printf("[INFO] Live hosts file not found for %s, running livehosts module...", opts.Domain)
		liveHostsResult, err2 := livehosts.FilterLiveHosts(opts.Domain, opts.Threads, false)
		if err2 != nil {
			return nil, fmt.Errorf("failed to get live hosts: %w", err2)
		}
		liveHostsFile = liveHostsResult.LiveSubsFile
		if liveHostsFile == "" {
			return nil, fmt.Errorf("live hosts file path is empty")
		}
	} else {
		log.Printf("[INFO] Using existing live hosts file: %s", liveHostsFile)
	}

	// Read hosts from file
	file, err := os.Open(liveHostsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open live hosts file: %w", err)
	}
	defer file.Close()

	var hosts []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		
		// Normalize URL: remove any existing protocol (handle multiple prefixes)
		// This handles cases where file has "https://" already or just domain
		normalized := line
		// Remove all protocol prefixes (in case of double prefixes like "https://https://")
		for strings.HasPrefix(normalized, "http://") || strings.HasPrefix(normalized, "https://") {
			if strings.HasPrefix(normalized, "https://") {
				normalized = strings.TrimPrefix(normalized, "https://")
			} else if strings.HasPrefix(normalized, "http://") {
				normalized = strings.TrimPrefix(normalized, "http://")
			} else {
				break
			}
		}
		
		// Remove trailing slash for consistency
		normalized = strings.TrimSuffix(normalized, "/")
		
		// Add https:// prefix
		normalized = "https://" + normalized
		
		hosts = append(hosts, normalized)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read live hosts file: %w", err)
	}

	if len(hosts) == 0 {
		log.Printf("[WARN] No live hosts found for %s", opts.Domain)
		return &Result{
			Target:       opts.Domain,
			TotalFound:   0,
			OutputFile:   "",
			UniqueSizes:  make(map[int64]bool),
			HostsScanned: 0,
		}, nil
	}

	log.Printf("[INFO] Found %d live hosts to fuzz", len(hosts))

	// Setup output directory
	resultsDir := utils.GetResultsDir()
	outputDir := filepath.Join(resultsDir, opts.Domain, "ffuf")
	if err := utils.EnsureDir(outputDir); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	// Create combined output file
	combinedOutputFile := filepath.Join(outputDir, "ffuf-results.txt")
	combinedOutFile, err := os.Create(combinedOutputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create combined output file: %w", err)
	}
	defer combinedOutFile.Close()

	// Track total results across all hosts
	var totalFound int
	var totalMutex sync.Mutex
	var hostsScanned int
	var hostsMutex sync.Mutex

	// Create a semaphore to limit concurrency
	semaphore := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	// Fuzz each host concurrently
	for _, host := range hosts {
		wg.Add(1)
		semaphore <- struct{}{} // Acquire semaphore

		go func(targetHost string) {
			defer wg.Done()
			defer func() { <-semaphore }() // Release semaphore

			// Ensure URL has FUZZ placeholder
			targetURL := targetHost
			if !strings.Contains(targetURL, "FUZZ") {
				if !strings.HasSuffix(targetURL, "/") {
					targetURL += "/"
				}
				targetURL += "FUZZ"
			}

			// Create per-host options
			hostOpts := opts
			hostOpts.Target = targetURL
			hostOpts.Domain = "" // Clear domain to avoid recursion
			hostOpts.OutputFile = "" // Use default per-host output

			// Run ffuf for this host
			result, err := runFFufSingleTarget(hostOpts)
			if err != nil {
				log.Printf("[WARN] FFuf fuzzing failed for %s: %v", targetHost, err)
				// Still count as scanned even if failed
				hostsMutex.Lock()
				hostsScanned++
				log.Printf("[INFO] Completed %d/%d hosts: %s (failed: %v)", hostsScanned, len(hosts), targetHost, err)
				hostsMutex.Unlock()
				return
			}

			// Read results from per-host file and append to combined file
			if result.OutputFile != "" {
				hostFile, err := os.Open(result.OutputFile)
				if err == nil {
					defer hostFile.Close()
					scanner := bufio.NewScanner(hostFile)
					for scanner.Scan() {
						line := scanner.Text()
						if line != "" {
							// Write to combined file with host prefix
							combinedLine := fmt.Sprintf("[%s] %s\n", targetHost, line)
							combinedOutFile.WriteString(combinedLine)
						}
					}
				}
			}

			// Update totals
			totalMutex.Lock()
			totalFound += result.TotalFound
			totalMutex.Unlock()

			hostsMutex.Lock()
			hostsScanned++
			log.Printf("[INFO] Completed %d/%d hosts: %s (found %d results)", hostsScanned, len(hosts), targetHost, result.TotalFound)
			hostsMutex.Unlock()
		}(host)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	log.Printf("[OK] FFuf domain mode completed for %s", opts.Domain)
	log.Printf("[INFO] Scanned %d hosts, found %d total unique results", hostsScanned, totalFound)
	log.Printf("[INFO] Combined results saved to: %s", combinedOutputFile)

	return &Result{
		Target:       opts.Domain,
		TotalFound:   totalFound,
		OutputFile:   combinedOutputFile,
		UniqueSizes:  make(map[int64]bool),
		HostsScanned: hostsScanned,
	}, nil
}

// runFFufSingleTarget runs ffuf for a single target (used internally)
func runFFufSingleTarget(opts Options) (*Result, error) {
	if opts.Target == "" {
		return nil, fmt.Errorf("target is required")
	}

	if opts.Threads <= 0 {
		opts.Threads = 40
	}

	// Default wordlist
	if opts.Wordlist == "" {
		wordlistPath := filepath.Join(utils.GetRootDir(), "Wordlists", "quick_fuzz.txt")
		if _, err := os.Stat(wordlistPath); err == nil {
			opts.Wordlist = wordlistPath
		} else {
			return nil, fmt.Errorf("wordlist not found: %s", wordlistPath)
		}
	}
	
	// Convert wordlist to absolute path and validate it exists
	wordlistPath := opts.Wordlist
	if !filepath.IsAbs(wordlistPath) {
		// Try relative to root dir first
		absPath := filepath.Join(utils.GetRootDir(), wordlistPath)
		if _, err := os.Stat(absPath); err == nil {
			wordlistPath = absPath
		} else {
			// Try relative to current working directory
			if cwd, err := os.Getwd(); err == nil {
				absPath = filepath.Join(cwd, wordlistPath)
				if _, err := os.Stat(absPath); err == nil {
					wordlistPath = absPath
				}
			}
		}
	}
	
	// Validate wordlist file exists and is readable
	info, err := os.Stat(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("wordlist file not found or not accessible: %s (error: %w)", wordlistPath, err)
	}
	if info.Size() == 0 {
		return nil, fmt.Errorf("wordlist file is empty: %s", wordlistPath)
	}
	
	opts.Wordlist = wordlistPath
	wordlistSize := info.Size()
	
	// Count lines in wordlist for better logging
	wordlistLines := 0
	if file, err := os.Open(wordlistPath); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				wordlistLines++
			}
		}
		file.Close()
	}
	
	log.Printf("[INFO] Wordlist: %s", wordlistPath)
	log.Printf("[INFO] Wordlist size: %d bytes, %d lines", wordlistSize, wordlistLines)

	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Validate URL contains FUZZ keyword
	if !strings.Contains(opts.Target, "FUZZ") {
		return nil, fmt.Errorf("URL must contain FUZZ keyword: %s", opts.Target)
	}

	// Create ffuf config
	conf := ffufpkg.NewConfig(ctx, cancel)
	conf.Url = opts.Target
	conf.Threads = opts.Threads
	conf.Quiet = true
	conf.Noninteractive = true
	// Use absolute path for wordlist
	absWordlist, err := filepath.Abs(opts.Wordlist)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for wordlist: %w", err)
	}
	// IMPORTANT: We need to create InputProviders, not just set Wordlists
	// The InputProviders are what actually load the wordlist file
	// InputMode defaults to "clusterbomb" which works fine for single wordlist
	// Don't override it - let it use the default "clusterbomb"
	conf.InputProviders = []ffufpkg.InputProviderConfig{
		{
			Name:    "wordlist",
			Value:   absWordlist,
			Keyword: "FUZZ",
		},
	}
	// Also set Wordlists for compatibility
	conf.Wordlists = []string{absWordlist}
	log.Printf("[DEBUG] FFuf config: URL=%s, Wordlist=%s, Threads=%d", conf.Url, absWordlist, conf.Threads)
	// Config is logged above with wordlist info
	conf.Recursion = opts.Recursion
	if opts.RecursionDepth > 0 {
		conf.RecursionDepth = opts.RecursionDepth
	} else if opts.Recursion {
		conf.RecursionDepth = 3
	}
	conf.FollowRedirects = opts.FollowRedirects
	conf.Verbose = false  // Keep verbose off to reduce noise
	conf.Quiet = true     // Keep quiet, but we'll handle errors explicitly
	conf.Json = false

	// Validate config before creating input provider
	if len(conf.Wordlists) == 0 {
		return nil, fmt.Errorf("no wordlists configured")
	}
	for _, wl := range conf.Wordlists {
		if wl == "" {
			return nil, fmt.Errorf("empty wordlist path in config")
		}
		// Extract file path (remove ":keyword" suffix if present)
		filePath := wl
		if idx := strings.LastIndex(wl, ":"); idx > 0 {
			filePath = wl[:idx]
		}
		if _, err := os.Stat(filePath); err != nil {
			return nil, fmt.Errorf("wordlist file does not exist: %s (error: %w)", filePath, err)
		}
	}

	// Match only 200 status codes
	conf.MatcherManager = filter.NewMatcherManager()
	if err := conf.MatcherManager.AddMatcher("status", "200"); err != nil {
		return nil, fmt.Errorf("failed to add status matcher: %w", err)
	}

	// Filter by size (real-time deduplication)
	uniqueSizes := make(map[int64]bool)
	var sizeMutex sync.Mutex
	lastSize := int64(-1)

	// Setup output directory
	resultsDir := utils.GetResultsDir()
	outputDir := filepath.Join(resultsDir, extractDomain(opts.Target), "ffuf")
	if err := utils.EnsureDir(outputDir); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	if opts.OutputFile == "" {
		// Create per-host output file
		hostName := extractDomain(opts.Target)
		opts.OutputFile = filepath.Join(outputDir, fmt.Sprintf("%s-ffuf-results.txt", hostName))
	}

	// Create output file
	outFile, err := os.Create(opts.OutputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Custom output handler to filter duplicates in real-time
	var resultCount int
	var resultMutex sync.Mutex

	// Create job
	job := ffufpkg.NewJob(&conf)

	// Setup input provider
	inputProvider, inputErr := input.NewInputProvider(&conf)
	if err := inputErr.ErrorOrNil(); err != nil {
		return nil, fmt.Errorf("failed to create input provider: %w", err)
	}
	job.Input = inputProvider
	
	// Validate wordlist was loaded
	if inputProvider == nil {
		return nil, fmt.Errorf("input provider is nil - wordlist may not be loaded")
	}
	
	// Try to validate input provider has words by checking if we can get position/total
	// This is a best-effort check - if the provider doesn't support these methods, we continue
	var inputProviderTotal int
	if posProvider, ok := inputProvider.(interface{ Position() int }); ok {
		if totalProvider, ok := inputProvider.(interface{ Total() int }); ok {
			inputProviderTotal = totalProvider.Total()
			pos := posProvider.Position()
			log.Printf("[INFO] Input provider initialized: position=%d, total=%d", pos, inputProviderTotal)
			if inputProviderTotal == 0 {
				return nil, fmt.Errorf("input provider has 0 total words - wordlist may not be loaded correctly")
			}
			// Warn if input provider total doesn't match wordlist line count
			if wordlistLines > 0 && inputProviderTotal != wordlistLines {
				log.Printf("[WARN] Input provider total (%d) doesn't match wordlist line count (%d) - this may be normal if wordlist has comments or empty lines", inputProviderTotal, wordlistLines)
			}
		}
	} else {
		log.Printf("[INFO] Input provider initialized (cannot determine total count)")
	}

	// Setup runner
	job.Runner = runner.NewSimpleRunner(&conf, false)

	// Setup custom output that filters duplicates
	outputProvider := output.NewOutputProviderByName("json", &conf)
	if outputProvider == nil {
		return nil, fmt.Errorf("failed to create output provider")
	}

	// Override output to filter duplicates
	var resultsMutex sync.Mutex
	var bypassMutex sync.Mutex
	var webhookMutex sync.Mutex
	
	// Create HTTP client for 403 bypass attempts
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	
	// Create webhook messages file for batch sending
	webhookMessagesFile := filepath.Join(outputDir, "ffuf-webhook-messages.txt")
	webhookFile, webhookErr := os.Create(webhookMessagesFile)
	if webhookErr != nil {
		log.Printf("[WARN] Failed to create webhook messages file: %v", webhookErr)
		webhookFile = nil
	}
	
	job.Output = &customOutputProvider{
		base:         outputProvider,
		outFile:      outFile,
		uniqueSizes:  uniqueSizes,
		sizeMutex:    &sizeMutex,
		lastSize:     &lastSize,
		resultCount:  &resultCount,
		resultMutex:  &resultMutex,
		bypass403:    opts.Bypass403,
		target:       opts.Target,
		conf:         &conf,
		results:      make([]ffufpkg.Result, 0),
		resultsMutex: &resultsMutex,
		bypassTried:  make(map[string]bool),
		bypassMutex:  &bypassMutex,
		httpClient:   httpClient,
		webhookFile:  webhookFile,
		webhookMutex: &webhookMutex,
	}

	// Add custom headers if provided
	if len(opts.CustomHeaders) > 0 {
		if conf.Headers == nil {
			conf.Headers = make(map[string]string)
		}
		for k, v := range opts.CustomHeaders {
			conf.Headers[k] = v
		}
	}

	// Add extensions if provided
	if len(opts.Extensions) > 0 {
		conf.Extensions = opts.Extensions
	}

	log.Printf("[INFO] Starting fuzzing: %s", opts.Target)
	log.Printf("[INFO] Configuration: %d threads, wordlist: %d lines", opts.Threads, wordlistLines)
	if inputProviderTotal > 0 {
		log.Printf("[INFO] Will test %d payloads", inputProviderTotal)
	}
	
	// Validate job is properly configured before starting
	if job.Input == nil {
		return nil, fmt.Errorf("job input is nil - cannot start fuzzing")
	}
	if job.Runner == nil {
		return nil, fmt.Errorf("job runner is nil - cannot start fuzzing")
	}

	// Start the job (this runs synchronously)
	// Note: job.Start() blocks until completion
	startTime := time.Now()
	job.Start()
	duration := time.Since(startTime)
	
	resultMutex.Lock()
	found := resultCount
	resultMutex.Unlock()

	// Calculate statistics
	var requestsPerSec float64
	if duration.Seconds() > 0 && inputProviderTotal > 0 {
		requestsPerSec = float64(inputProviderTotal) / duration.Seconds()
	}
	
	log.Printf("[INFO] Fuzzing completed in %v", duration)
	if inputProviderTotal > 0 {
		log.Printf("[INFO] Tested %d/%d payloads (%.1f req/sec)", inputProviderTotal, inputProviderTotal, requestsPerSec)
	}
	log.Printf("[INFO] Found %d unique results", found)
	
	// Warn if job completed suspiciously fast (less than 1 second for large wordlist)
	if duration < time.Second && wordlistSize > 100000 {
		log.Printf("[WARN] Job completed very quickly (%v) for large wordlist (%d bytes, %d lines) - this may indicate an issue", duration, wordlistSize, wordlistLines)
	}

	// Webhook file sending removed - files are now sent via utils.SendPhaseFiles from phase functions
	// Close webhook file if it was created
	webhookFilePath := filepath.Join(outputDir, "ffuf-webhook-messages.txt")
	if job.Output != nil {
		if customOutput, ok := job.Output.(*customOutputProvider); ok && customOutput.webhookFile != nil {
			customOutput.webhookMutex.Lock()
			customOutput.webhookFile.Close()
			customOutput.webhookMutex.Unlock()
			// Clean up webhook file
			os.Remove(webhookFilePath)
		}
	}

	return &Result{
		Target:      opts.Target,
		TotalFound:  found,
		OutputFile:  opts.OutputFile,
		UniqueSizes: uniqueSizes,
	}, nil
}

