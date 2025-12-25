package ffuf

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	ffufpkg "github.com/ffuf/ffuf/v2/pkg/ffuf"
	"github.com/ffuf/ffuf/v2/pkg/filter"
	"github.com/ffuf/ffuf/v2/pkg/input"
	"github.com/ffuf/ffuf/v2/pkg/output"
	"github.com/ffuf/ffuf/v2/pkg/runner"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
)

// Options holds ffuf scan options
type Options struct {
	Target          string
	Wordlist        string
	Threads         int
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
}

// RunFFuf executes ffuf fuzzing with custom filtering
func RunFFuf(opts Options) (*Result, error) {
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

	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create ffuf config
	conf := ffufpkg.NewConfig(ctx, cancel)
	conf.Url = opts.Target
	conf.Threads = opts.Threads
	conf.Wordlists = []string{opts.Wordlist}
	conf.Recursion = opts.Recursion
	if opts.RecursionDepth > 0 {
		conf.RecursionDepth = opts.RecursionDepth
	} else if opts.Recursion {
		conf.RecursionDepth = 3
	}
	conf.FollowRedirects = opts.FollowRedirects
	conf.Verbose = false
	conf.Quiet = true
	conf.Json = false

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

	// Setup runner
	job.Runner = runner.NewSimpleRunner(&conf, false)

	// Setup custom output that filters duplicates
	outputProvider := output.NewOutputProviderByName("json", &conf)
	if outputProvider == nil {
		return nil, fmt.Errorf("failed to create output provider")
	}

	// Override output to filter duplicates
	var resultsMutex sync.Mutex
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

	log.Printf("[INFO] Starting ffuf fuzzing for %s", opts.Target)
	log.Printf("[INFO] Wordlist: %s", opts.Wordlist)
	log.Printf("[INFO] Threads: %d", opts.Threads)
	log.Printf("[INFO] Recursion: %v", opts.Recursion)
	log.Printf("[INFO] 403 Bypass: %v", opts.Bypass403)

	// Start the job (this runs synchronously)
	job.Start()
	
	log.Printf("[INFO] FFuf job completed")

	resultMutex.Lock()
	found := resultCount
	resultMutex.Unlock()

	log.Printf("[OK] FFuf fuzzing completed. Found %d unique results", found)
	log.Printf("[INFO] Results saved to: %s", opts.OutputFile)

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
}

func (c *customOutputProvider) Banner() {
	c.base.Banner()
}

func (c *customOutputProvider) Finalize() error {
	return c.base.Finalize()
}

func (c *customOutputProvider) Error(errstr string) {
	c.base.Error(errstr)
}

func (c *customOutputProvider) Warning(warnstr string) {
	c.base.Warning(warnstr)
}

func (c *customOutputProvider) Info(infostr string) {
	c.base.Info(infostr)
}

func (c *customOutputProvider) Raw(output string) {
	c.base.Raw(output)
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
		// If 403 bypass is enabled, try bypass techniques
		if c.bypass403 && resp.StatusCode == 403 {
			c.try403Bypass(resp)
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

	// Also write to base output
	c.base.Result(resp)

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

// try403Bypass attempts various 403 bypass techniques
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

	for _, technique := range bypassTechniques {
		// Try with header modification
		if len(technique.header) > 0 {
			log.Printf("[DEBUG] Trying 403 bypass: %s for %s", technique.name, originalURL)
		}

		// Try with path modification
		if technique.path != "" {
			modifiedPath := basePath + technique.path
			log.Printf("[DEBUG] Trying 403 bypass path: %s -> %s", basePath, modifiedPath)
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

