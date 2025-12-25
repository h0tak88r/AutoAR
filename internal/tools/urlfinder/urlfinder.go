package urlfinder

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Options controls how the embedded URL discovery engine runs.
// For now this is a lightweight, passive-only implementation inspired by
// urlfinder but implemented natively inside AutoAR (no external binary).
type Options struct {
	AllSources         bool
	SkipSubdomainEnum  bool
}

// FindURLsForDomain passively discovers URLs for a given domain using a small
// set of HTTP-based sources (currently Wayback Machine). It returns a
// de-duplicated slice of URLs.
func FindURLsForDomain(domain string, opts Options) ([]string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	var out []string
	seen := make(map[string]struct{})

	// Wayback Machine CDX API
	waybackURLs, err := fetchWayback(domain, opts.SkipSubdomainEnum)
	if err != nil {
		// Don't fail the whole scan on a single source error
	} else {
		for _, u := range waybackURLs {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			if _, ok := seen[u]; ok {
				continue
			}
			seen[u] = struct{}{}
			out = append(out, u)
		}
	}

	return out, nil
}

// FindURLsToFile runs URL discovery for a domain and writes deduplicated
// URLs to the given output file, returning the number of URLs written.
func FindURLsToFile(domain, outFile string, opts Options) (int, error) {
	urls, err := FindURLsForDomain(domain, opts)
	if err != nil {
		return 0, err
	}
	if len(urls) == 0 {
		return 0, nil
	}

	if err := os.MkdirAll(filepath.Dir(outFile), 0o755); err != nil {
		return 0, fmt.Errorf("failed to create output dir: %w", err)
	}

	f, err := os.Create(outFile)
	if err != nil {
		return 0, fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	defer w.Flush()

	count := 0
	seen := make(map[string]struct{}, len(urls))
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		if _, err := w.WriteString(u + "\n"); err != nil {
			return count, err
		}
		count++
	}

	return count, nil
}

// fetchWayback queries the Wayback Machine CDX API for archived URLs.
func fetchWayback(domain string, skipSubdomainEnum bool) ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	var q string
	if skipSubdomainEnum {
		// For subdomain mode, query the specific subdomain directly
		q = fmt.Sprintf("%s/*", domain)
	} else {
		// For domain mode, use wildcard pattern
		q = fmt.Sprintf("*.%s/*", domain)
	}
	apiURL := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s&output=text&fl=original&collapse=urlkey",
		url.QueryEscape(q))

	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("wayback returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var urls []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return urls, nil
}
