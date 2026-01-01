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

	"github.com/hashicorp/go-retryablehttp"
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

// Method defines the wordlist generation method
type Method string

const (
	MethodRegular      Method = "regular"
	MethodWithoutDots  Method = "withoutdots"
	MethodWithoutVowels Method = "withoutvowels"
	MethodReverse      Method = "reverse"
	MethodMixed        Method = "mixed"
	MethodWithoutDV    Method = "withoutdv"
	MethodShuffle      Method = "shuffle"
	MethodAll          Method = "all"
)

// Options controls how the embedded fuzzuli engine runs.
type Options struct {
	Workers          int
	MinContentLength int
	StatusCode       int
	Extensions       []string
	Paths            []string
	Timeout          time.Duration
	UserAgent        string
	Method           Method // Wordlist generation method
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
		Method:           MethodRegular, // Default to regular method
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

	retryClient := newRetryableHTTPClient(opts.Timeout)
	client := retryClient.StandardClient()

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
						// Silently continue on errors (network issues, etc.)
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
		words := generateWordlist(base, opts.Method)
		// Debug: Check if we're generating words
		if len(words) == 0 {
			// This shouldn't happen, but log it if it does
			continue
		}
		for _, w := range words {
			tasks <- task{Base: base, Word: w}
		}
	}
	close(tasks)
	wg.Wait()

	return unique(results), nil
}

// normalizeBase ensures we have a scheme and no trailing slash.
// Matches fuzzuli behavior: uses http:// by default (as per original fuzzuli code)
func normalizeBase(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	// Preserve existing protocol if present
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "http://" + host // Use http:// by default (matches original fuzzuli)
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

// newRetryableHTTPClient returns a retryablehttp client (matching real fuzzuli).
func newRetryableHTTPClient(timeout time.Duration) *retryablehttp.Client {
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

	// Use retryablehttp like the real fuzzuli
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3
	retryClient.RetryWaitMax = 3 * time.Second
	retryClient.RetryWaitMin = 100 * time.Millisecond
	retryClient.Logger = nil // Disable logging
	retryClient.HTTPClient.Transport = tr
	retryClient.HTTPClient.Timeout = timeout

	return retryClient
}

// checkURL performs a HEAD request and applies fuzzuli-like heuristics.
// Uses retryablehttp client which handles retries automatically (matching real fuzzuli).
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
func generateWordlist(domain string, method Method) []string {
	var words []string
	// Extract domain part (remove protocol if present)
	justDomain := domain
	if strings.Contains(domain, "://") {
		justDomain = strings.Split(domain, "://")[1]
	}

	// Determine which methods to use
	methods := []Method{}
	if method == MethodAll {
		methods = []Method{MethodRegular, MethodWithoutDots, MethodWithoutVowels, MethodReverse, MethodMixed, MethodWithoutDV, MethodShuffle}
	} else {
		methods = []Method{method}
	}

	for _, m := range methods {
		switch m {
		case MethodRegular:
			regularDomain(justDomain, &words)
		case MethodWithoutDots:
			withoutDots(justDomain, &words)
		case MethodWithoutVowels:
			withoutVowels(justDomain, &words)
		case MethodReverse:
			reverseDomain(justDomain, &words)
		case MethodMixed:
			mixedSubdomain(domain, &words)
		case MethodWithoutDV:
			withoutVowelsAndDots(justDomain, &words)
		case MethodShuffle:
			shuffle(domain, &words)
		default:
			regularDomain(justDomain, &words)
		}
	}

	return unique(words)
}

func regularDomain(domain string, wordlist *[]string) {
	generatePossibilities(domain, wordlist)
}

func withoutDots(domain string, wordlist *[]string) {
	withoutDot := strings.ReplaceAll(domain, ".", "")
	generatePossibilities(withoutDot, wordlist)
}

func withoutVowels(domain string, wordlist *[]string) {
	clearVowel := strings.NewReplacer("a", "", "e", "", "i", "", "u", "", "o", "")
	withoutVowel := clearVowel.Replace(domain)
	generatePossibilities(withoutVowel, wordlist)
}

func withoutVowelsAndDots(domain string, wordlist *[]string) {
	clearVowel := strings.NewReplacer("a", "", "e", "", "i", "", "u", "", "o", "", ".", "")
	withoutVowelDot := clearVowel.Replace(domain)
	generatePossibilities(withoutVowelDot, wordlist)
}

func reverseDomain(domain string, wordlist *[]string) {
	// Extract domain part (remove protocol if present)
	clearDomain := domain
	if strings.Contains(domain, "://") {
		clearDomain = strings.Split(domain, "://")[1]
	}
	split := strings.Split(clearDomain, ".")
	reversed := reverseSlice(split)
	reverseDomain := strings.Join(reversed, ".")
	generatePossibilities(reverseDomain, wordlist)
	withoutDots(reverseDomain, wordlist)
	withoutVowels(reverseDomain, wordlist)
	withoutVowelsAndDots(reverseDomain, wordlist)
}

func mixedSubdomain(domain string, wordlist *[]string) {
	// Extract domain part (remove protocol if present)
	clearDomain := domain
	if strings.Contains(domain, "://") {
		parts := strings.Split(domain, "://")
		if len(parts) > 1 {
			clearDomain = parts[1]
		}
	}
	split := strings.Split(clearDomain, ".")
	for sindex := range split {
		for eindex := range split {
			generatePossibilities(split[sindex]+"."+split[eindex], wordlist)
		}
	}
}

func shuffle(domain string, wordlist *[]string) {
	// Extract domain part (remove protocol if present)
	clearDomain := domain
	if strings.Contains(domain, "://") {
		clearDomain = strings.Split(domain, "://")[1]
	}
	split := strings.Split(clearDomain, ".")
	splitReverse := reverseSlice(split)
	reverseDomain := strings.Join(splitReverse, ".")
	shuffleSubdomain(clearDomain, wordlist)
	shuffleSubdomain(reverseDomain, wordlist)
}

func shuffleSubdomain(domain string, wordlist *[]string) {
	split := strings.Split(domain, ".")
	for id1 := range split {
		for id2 := range split[id1:] {
			p := strings.Join(split[id1:id1+id2+1], ".")
			addShuffleSubdomain(p, wordlist)
			if id2 >= 2 {
				p = split[id1] + "." + split[id1+id2]
				addShuffleSubdomain(p, wordlist)
			}
		}
	}
}

func addShuffleSubdomain(domain string, wordlist *[]string) {
	if !contains(*wordlist, domain) {
		*wordlist = append(*wordlist, domain)
	}

	clearVowel := strings.NewReplacer("a", "", "e", "", "i", "", "u", "", "o", "")
	domainWithoutVowel := clearVowel.Replace(domain)
	if !contains(*wordlist, domainWithoutVowel) {
		*wordlist = append(*wordlist, domainWithoutVowel)
	}

	withoutDot := strings.ReplaceAll(domain, ".", "")
	if !contains(*wordlist, withoutDot) {
		*wordlist = append(*wordlist, withoutDot)
	}

	clearVowelDot := strings.NewReplacer("a", "", "e", "", "i", "", "u", "", "o", "", ".", "")
	withoutVowelDot := clearVowelDot.Replace(domain)
	if !contains(*wordlist, withoutVowelDot) {
		*wordlist = append(*wordlist, withoutVowelDot)
	}
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
