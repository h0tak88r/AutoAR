package fuzzuli

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Default configuration values adapted from the original fuzzuli CLI.
const (
	defaultMinContentLength = 100
	defaultStatusCode       = 200
	defaultWorkers          = 16
	defaultTimeoutSeconds   = 10
)

var defaultExtensions = []string{
	".rar", ".zip", ".tar.gz", ".tar", ".gz", ".jar", ".7z", ".bz2", ".sql", ".backup", ".war", ".bak", ".dll",
}

var defaultMimeTypes = []string{
	"application/octet-stream",
	"application/x-bzip",
	"application/x-bzip2",
	"application/gzip",
	"application/java-archive",
	"application/vnd.rar",
	"application/x-sh",
	"application/x-tar",
	"application/zip",
	"application/x-7z-compressed",
	"application/x-msdownload",
	"application/x-msdos-program",
}

// Options controls how the embedded fuzzuli engine runs.
type Options struct {
	Workers          int
	MinContentLength int
	StatusCode       int
	Extensions       []string
	Paths            []string
	Timeout          time.Duration
	UserAgent        string
}

// DefaultOptions returns sane defaults similar to the upstream fuzzuli CLI.
func DefaultOptions() Options {
	return Options{
		Workers:          defaultWorkers,
		MinContentLength: defaultMinContentLength,
		StatusCode:       defaultStatusCode,
		Extensions:       append([]string{}, defaultExtensions...),
		Paths:            []string{"/"},
		Timeout:          time.Second * defaultTimeoutSeconds,
		UserAgent:        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0",
	}
}

// ScanDomain runs a fuzzuli-style backup scan for a single domain
// (e.g. example.com) and returns a slice of discovered backup URLs.
func ScanDomain(domain string, opts Options) ([]string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, fmt.Errorf("domain is required for fuzzuli scan")
	}
	base := normalizeBase(domain)
	return scanBases([]string{base}, opts)
}

// ScanFromFile runs a fuzzuli-style backup scan for all hosts contained in
// the given file (one host per line) and returns a slice of discovered URLs.
func ScanFromFile(path string, opts Options) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("live hosts file is required for fuzzuli scan")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("live hosts file not found: %s", path)
	}
	defer f.Close()

	var bases []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		bases = append(bases, normalizeBase(line))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(bases) == 0 {
		return nil, fmt.Errorf("no valid hosts found in %s", path)
	}
	return scanBases(bases, opts)
}

// scanBases performs the actual scanning logic across all base URLs.
func scanBases(bases []string, opts Options) ([]string, error) {
	if opts.Workers <= 0 {
		opts.Workers = defaultWorkers
	}
	if opts.MinContentLength <= 0 {
		opts.MinContentLength = defaultMinContentLength
	}
	if opts.StatusCode == 0 {
		opts.StatusCode = defaultStatusCode
	}
	if len(opts.Extensions) == 0 {
		opts.Extensions = append([]string{}, defaultExtensions...)
	}
	if len(opts.Paths) == 0 {
		opts.Paths = []string{"/"}
	}
	if opts.Timeout <= 0 {
		opts.Timeout = time.Second * defaultTimeoutSeconds
	}
	if opts.UserAgent == "" {
		opts.UserAgent = DefaultOptions().UserAgent
	}

	type task struct {
		Base string
		Word string
	}

	tasks := make(chan task, 1024)
	var wg sync.WaitGroup

	var resultsMu sync.Mutex
	var results []string

	client := newHTTPClient(opts.Timeout)

	worker := func() {
		defer wg.Done()
		for t := range tasks {
			for _, p := range opts.Paths {
				for _, ext := range opts.Extensions {
					u := buildURL(t.Base, p, t.Word, ext)
					if u == "" {
						continue
					}
					ok, err := checkURL(client, u, opts)
					if err != nil {
						continue
					}
					if ok {
						resultsMu.Lock()
						results = append(results, u)
						resultsMu.Unlock()
					}
				}
			}
		}
	}

	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go worker()
	}

	for _, base := range bases {
		words := generateWordlist(base)
		for _, w := range words {
			tasks <- task{Base: base, Word: w}
		}
	}
	close(tasks)
	wg.Wait()

	return unique(results), nil
}

// normalizeBase ensures we have a scheme and no trailing slash.
func normalizeBase(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "http://" + host
	}
	return strings.TrimRight(host, "/")
}

// buildURL constructs the full candidate URL from base, path, word, and extension.
func buildURL(base, path, word, ext string) string {
	if base == "" || word == "" || ext == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path + word + ext
}

// newHTTPClient returns an HTTP client similar to the one used by fuzzuli.
func newHTTPClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		MaxIdleConns:        100,
		MaxConnsPerHost:     100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     5 * time.Second,
		DisableKeepAlives:   false,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // fuzzuli runs with insecure by default
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		}).DialContext,
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
}

// checkURL performs a HEAD request and applies fuzzuli-like heuristics.
func checkURL(client *http.Client, target string, opts Options) (bool, error) {
	req, err := http.NewRequest("HEAD", target, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", opts.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != opts.StatusCode {
		return false, nil
	}

	clHeader := resp.Header.Get("Content-Length")
	if clHeader == "" {
		return false, nil
	}
	cl, err := strconv.Atoi(clHeader)
	if err != nil || cl <= opts.MinContentLength {
		return false, nil
	}

	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		return false, nil
	}

	// Some servers include charset, so just match prefix.
	matched := false
	for _, mt := range defaultMimeTypes {
		if strings.HasPrefix(strings.ToLower(ct), strings.ToLower(mt)) {
			matched = true
			break
		}
	}
	if !matched {
		return false, nil
	}

	return true, nil
}

// generateWordlist builds candidate words from the domain similar to fuzzuli.
func generateWordlist(domain string) []string {
	var words []string

	// Regular domain (without scheme)
	justDomain := strings.Split(domain, "://")[1]
	generatePossibilities(justDomain, &words)

	// Without dots
	withoutDot := strings.ReplaceAll(justDomain, ".", "")
	generatePossibilities(withoutDot, &words)

	// Without vowels
	clearVowel := strings.NewReplacer("a", "", "e", "", "i", "", "u", "", "o", "")
	withoutVowel := clearVowel.Replace(justDomain)
	generatePossibilities(withoutVowel, &words)

	// Reverse domain
	split := strings.Split(justDomain, ".")
	reversed := reverseSlice(split)
	reverseDomain := strings.Join(reversed, ".")
	generatePossibilities(reverseDomain, &words)
	generatePossibilities(strings.ReplaceAll(reverseDomain, ".", ""), &words)
	generatePossibilities(clearVowel.Replace(reverseDomain), &words)

	return unique(words)
}

func generatePossibilities(domain string, possibilities *[]string) {
	justDomain := domain
	for first := range justDomain {
		for last := range justDomain[first:] {
			p := justDomain[first : first+last+1]
			if !contains(*possibilities, p) {
				*possibilities = append(*possibilities, p)
			}
		}
	}
}

func reverseSlice(slice []string) []string {
	for i, j := 0, len(slice)-1; i < j; i, j = i+1, j-1 {
		slice[i], slice[j] = slice[j], slice[i]
	}
	return slice
}

func contains(slice []string, element string) bool {
	for _, s := range slice {
		if s == element {
			return true
		}
	}
	return false
}

func unique(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
