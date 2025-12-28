package urls

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	jsfindertool "github.com/h0tak88r/AutoAR/v3/internal/tools/jsfinder"
	urlfindertool "github.com/h0tak88r/AutoAR/v3/internal/tools/urlfinder"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/livehosts"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/utils"
)

// Result summarizes URL collection for a domain.
type Result struct {
	Domain    string
	Threads   int
	TotalURLs int
	JSURLs    int
	AllFile   string
	JSFile    string
}

// CollectURLs ensures live hosts exist for a domain and then collects URLs and JS URLs
// using external tools (urlfinder and jsfinder), mirroring modules/urls.sh behaviour.
// If skipSubdomainEnum is true, it treats the input as a single subdomain and skips
// subdomain enumeration (no livehosts filtering, no wildcard API queries).
func CollectURLs(domain string, threads int, skipSubdomainEnum bool) (*Result, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if threads <= 0 {
		threads = 100
	}

	// Determine which domain to use for directory structure
	// In subdomain mode, use the actual subdomain; otherwise use root domain
	var dirDomain string
	if skipSubdomainEnum {
		// Use the subdomain itself for directory structure
		dirDomain = domain
	} else {
		// Extract root domain for directory structure
		dirDomain = extractRootDomain(domain)
	}
	
	// Initialize directory structure
	domainDir, err := utils.DomainDirInit(dirDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to init domain dir: %v", err)
	}

	subsDir := filepath.Join(domainDir, "subs")
	urlsDir := filepath.Join(domainDir, "urls")
	if err := utils.EnsureDir(urlsDir); err != nil {
		return nil, fmt.Errorf("failed to ensure urls dir: %v", err)
	}

	var liveFile string
	if skipSubdomainEnum {
		// For subdomain mode, use the existing live-subs.txt file if it exists
		// Otherwise create it with the subdomain
		liveFile = filepath.Join(subsDir, "live-subs.txt")
		if _, err := os.Stat(liveFile); os.IsNotExist(err) {
			// If file doesn't exist, create it with the subdomain
			// Ensure it has protocol for consistency
			subdomainURL := domain
			if !strings.HasPrefix(subdomainURL, "http://") && !strings.HasPrefix(subdomainURL, "https://") {
				subdomainURL = "https://" + subdomainURL
			}
			_ = writeLines(liveFile, []string{subdomainURL})
		}
		log.Printf("[INFO] Subdomain mode: scanning %s directly (no subdomain enumeration)", domain)
	} else {
		// Get live hosts file (checks file first, then database)
		liveFile, err = livehosts.GetLiveHostsFile(domain)
		if err != nil {
			log.Printf("[WARN] Failed to get live hosts file for %s: %v, attempting to create it", domain, err)
			// Fallback: try to create it by running livehosts
			liveRes, err2 := livehosts.FilterLiveHosts(domain, threads, true)
			if err2 != nil {
				log.Printf("[WARN] livehosts filtering failed for %s: %v", domain, err2)
			} else if liveRes != nil && liveRes.LiveSubsFile != "" {
				liveFile = liveRes.LiveSubsFile
			}
		}
	}

	// Prepare output files
	allFile := filepath.Join(urlsDir, "all-urls.txt")
	jsFile := filepath.Join(urlsDir, "js-urls.txt")
	
	// Check if URLs already exist and have content - if so, skip collection
	if info, err := os.Stat(allFile); err == nil && info.Size() > 0 {
		if jsInfo, err := os.Stat(jsFile); err == nil && jsInfo.Size() >= 0 {
			// URLs already collected, read and return them
			allURLs, _ := readLines(allFile)
			jsURLs, _ := readLines(jsFile)
			log.Printf("[INFO] Using existing URLs for %s (%d total URLs, %d JS URLs)", dirDomain, len(allURLs), len(jsURLs))
			return &Result{
				Domain:    dirDomain,
				Threads:   threads,
				TotalURLs: len(allURLs),
				JSURLs:    len(jsURLs),
				AllFile:   allFile,
				JSFile:    jsFile,
			}, nil
		}
	}
	
	_ = writeLines(allFile, nil)
	_ = writeLines(jsFile, nil)

	// 1) Collect URLs with embedded urlfinder library
	log.Printf("[INFO] Collecting URLs with embedded urlfinder for %s", domain)
	if _, err := urlfindertool.FindURLsToFile(domain, allFile, urlfindertool.Options{
		AllSources:      true,
		SkipSubdomainEnum: skipSubdomainEnum,
	}); err != nil {
		log.Printf("[WARN] urlfinder library failed for %s: %v", domain, err)
	}

	// 2) Collect URLs from external APIs (VirusTotal, Wayback, URLScan, OTX, Common Crawl)
	log.Printf("[INFO] Collecting URLs from external APIs for %s", domain)
	externalURLs := collectExternalURLs(domain, skipSubdomainEnum)
	if len(externalURLs) > 0 {
		log.Printf("[OK] Found %d URLs from external APIs", len(externalURLs))
		// Merge external URLs with existing URLs
		existingURLs, _ := readLines(allFile)
		allURLs := uniqueStrings(append(existingURLs, externalURLs...))
		_ = writeLines(allFile, allURLs)
	}

	// 3) Collect JS URLs with embedded jsfinder over live hosts
	if fi, err := os.Stat(liveFile); err == nil && fi.Size() > 0 {
		log.Printf("[INFO] Running embedded jsfinder on live hosts for %s", domain)
		liveURLs, err := readLines(liveFile)
		if err != nil {
			log.Printf("[WARN] Failed to read live hosts file for jsfinder: %v", err)
		} else {
			jsMatches, err := jsfindertool.Extract(liveURLs, jsfindertool.ExtractOptions{
				Concurrency: threads,
				Silent:      true,
			})
			if err != nil {
				log.Printf("[WARN] jsfinder library failed for %s: %v", domain, err)
			} else if len(jsMatches) > 0 {
				if err := writeLines(jsFile, jsMatches); err != nil {
					log.Printf("[WARN] Failed to write jsfinder results: %v", err)
				}
			}
		}
	}

	// 4) Merge JS URLs from all-urls.txt into js-urls.txt and deduplicate
	allURLs, _ := readLines(allFile)
	jsURLs, _ := readLines(jsFile)
	for _, u := range allURLs {
		if strings.Contains(strings.ToLower(u), ".js") {
			jsURLs = append(jsURLs, u)
		}
	}

	jsURLs = uniqueStrings(jsURLs)
	_ = writeLines(jsFile, jsURLs)

	// 5) Merge js-urls.txt back into all-urls.txt and deduplicate
	allURLs = uniqueStrings(append(allURLs, jsURLs...))
	_ = writeLines(allFile, allURLs)

	total := len(allURLs)
	jsCount := len(jsURLs)
	log.Printf("[OK] Found %d total URLs; %d JavaScript URLs for %s", total, jsCount, domain)

	return &Result{
		Domain:    dirDomain, // Return domain used for directory structure
		Threads:   threads,
		TotalURLs: total,
		JSURLs:    jsCount,
		AllFile:   allFile,
		JSFile:    jsFile,
	}, nil
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

// helpers

// readLines reads non-empty lines from a file.
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

// writeLines writes lines to a file (one per line). If lines is nil, creates/empties the file.
func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	if len(lines) == 0 {
		return nil
	}

	w := bufio.NewWriter(file)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, err := w.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return w.Flush()
}

// uniqueStrings returns a deduplicated slice preserving order.
func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// collectExternalURLs collects URLs from external APIs (VirusTotal, Wayback, URLScan, OTX, Common Crawl)
// If skipSubdomainEnum is true, queries are made for the specific subdomain instead of *.domain patterns
func collectExternalURLs(domain string, skipSubdomainEnum bool) []string {
	var allURLs []string
	client := &http.Client{Timeout: 30 * time.Second}

	// VirusTotal
	if urls := collectVirusTotalURLs(client, domain, skipSubdomainEnum); len(urls) > 0 {
		allURLs = append(allURLs, urls...)
	}

	// Wayback Machine
	if urls := collectWaybackURLs(client, domain, skipSubdomainEnum); len(urls) > 0 {
		allURLs = append(allURLs, urls...)
	}

	// URLScan.io
	if urls := collectURLScanURLs(client, domain, skipSubdomainEnum); len(urls) > 0 {
		allURLs = append(allURLs, urls...)
	}

	// AlienVault OTX
	if urls := collectOTXURLs(client, domain, skipSubdomainEnum); len(urls) > 0 {
		allURLs = append(allURLs, urls...)
	}

	// Common Crawl
	if urls := collectCommonCrawlURLs(client, domain, skipSubdomainEnum); len(urls) > 0 {
		allURLs = append(allURLs, urls...)
	}

	return uniqueStrings(allURLs)
}

// collectVirusTotalURLs fetches URLs from VirusTotal API
func collectVirusTotalURLs(client *http.Client, domain string, skipSubdomainEnum bool) []string {
	apiKey := os.Getenv("VIRUSTOTAL_API_KEY")
	if apiKey == "" {
		log.Printf("[INFO] VIRUSTOTAL_API_KEY not set, skipping VirusTotal")
		return nil
	}

	url := fmt.Sprintf("https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s", apiKey, domain)
	log.Printf("[INFO] Fetching URLs from VirusTotal for %s", domain)

	resp, err := client.Get(url)
	if err != nil {
		log.Printf("[WARN] VirusTotal API request failed: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[WARN] VirusTotal API returned status %d", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[WARN] Failed to read VirusTotal response: %v", err)
		return nil
	}

	var result struct {
		DetectedURLs    [][]interface{} `json:"detected_urls"`
		UndetectedURLs [][]interface{} `json:"undetected_urls"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("[WARN] Failed to parse VirusTotal JSON: %v", err)
		return nil
	}

	var urls []string
	// detected_urls format: [url, scan_id, scan_date, positives, total, permalink]
	for _, entry := range result.DetectedURLs {
		if len(entry) > 0 {
			if urlStr, ok := entry[0].(string); ok {
				urls = append(urls, urlStr)
			}
		}
	}
	// undetected_urls format: [url, scan_id, scan_date, positives, total, permalink]
	for _, entry := range result.UndetectedURLs {
		if len(entry) > 0 {
			if urlStr, ok := entry[0].(string); ok {
				urls = append(urls, urlStr)
			}
		}
	}

	log.Printf("[OK] VirusTotal: Found %d URLs", len(urls))
	return urls
}

// collectWaybackURLs fetches URLs from Wayback Machine CDX API
func collectWaybackURLs(client *http.Client, domain string, skipSubdomainEnum bool) []string {
	var url string
	if skipSubdomainEnum {
		// For subdomain mode, query the specific subdomain directly
		url = fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s/*&output=text&fl=original&collapse=urlkey", domain)
	} else {
		// For domain mode, use wildcard pattern
		url = fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey", domain)
	}
	log.Printf("[INFO] Fetching URLs from Wayback Machine for %s", domain)

	resp, err := client.Get(url)
	if err != nil {
		log.Printf("[WARN] Wayback Machine API request failed: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[WARN] Wayback Machine API returned status %d", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[WARN] Failed to read Wayback Machine response: %v", err)
		return nil
	}

	lines := strings.Split(string(body), "\n")
	var urls []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			urls = append(urls, line)
		}
	}

	log.Printf("[OK] Wayback Machine: Found %d URLs", len(urls))
	return urls
}

// collectURLScanURLs fetches URLs from URLScan.io API
func collectURLScanURLs(client *http.Client, domain string, skipSubdomainEnum bool) []string {
	apiKey := os.Getenv("URLSCAN_API_KEY")
	var url string
	if skipSubdomainEnum {
		// For subdomain mode, query the specific subdomain
		url = fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=10000", domain)
	} else {
		// For domain mode, use domain pattern
		url = fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=10000", domain)
	}
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("[WARN] Failed to create URLScan request: %v", err)
		return nil
	}

	if apiKey != "" {
		req.Header.Set("API-Key", apiKey)
	}

	log.Printf("[INFO] Fetching URLs from URLScan.io for %s", domain)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[WARN] URLScan.io API request failed: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[WARN] URLScan.io API returned status %d", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[WARN] Failed to read URLScan.io response: %v", err)
		return nil
	}

	var result struct {
		Results []struct {
			Page struct {
				URL string `json:"url"`
			} `json:"page"`
		} `json:"results"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("[WARN] Failed to parse URLScan.io JSON: %v", err)
		return nil
	}

	var urls []string
	for _, item := range result.Results {
		if item.Page.URL != "" {
			urls = append(urls, item.Page.URL)
		}
	}

	log.Printf("[OK] URLScan.io: Found %d URLs", len(urls))
	return urls
}

// collectOTXURLs fetches URLs from AlienVault OTX API
func collectOTXURLs(client *http.Client, domain string, skipSubdomainEnum bool) []string {
	// OTX API works with both domains and subdomains
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=500", domain)
	log.Printf("[INFO] Fetching URLs from AlienVault OTX for %s", domain)

	resp, err := client.Get(url)
	if err != nil {
		log.Printf("[WARN] OTX API request failed: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[WARN] OTX API returned status %d", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[WARN] Failed to read OTX response: %v", err)
		return nil
	}

	var result struct {
		URLList []struct {
			URL string `json:"url"`
		} `json:"url_list"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("[WARN] Failed to parse OTX JSON: %v", err)
		return nil
	}

	var urls []string
	for _, item := range result.URLList {
		if item.URL != "" {
			urls = append(urls, item.URL)
		}
	}

	log.Printf("[OK] OTX: Found %d URLs", len(urls))
	return urls
}

// collectCommonCrawlURLs fetches URLs from Common Crawl API
func collectCommonCrawlURLs(client *http.Client, domain string, skipSubdomainEnum bool) []string {
	// Use a recent Common Crawl index (update this periodically)
	var url string
	if skipSubdomainEnum {
		// For subdomain mode, query the specific subdomain directly
		url = fmt.Sprintf("https://index.commoncrawl.org/CC-MAIN-2023-06-index?url=%s/*&output=json&fl=timestamp,url,mime,status,digest", domain)
	} else {
		// For domain mode, use wildcard pattern
		url = fmt.Sprintf("https://index.commoncrawl.org/CC-MAIN-2023-06-index?url=*.%s/*&output=json&fl=timestamp,url,mime,status,digest", domain)
	}
	log.Printf("[INFO] Fetching URLs from Common Crawl for %s", domain)

	resp, err := client.Get(url)
	if err != nil {
		log.Printf("[WARN] Common Crawl API request failed: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[WARN] Common Crawl API returned status %d", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[WARN] Failed to read Common Crawl response: %v", err)
		return nil
	}

	lines := strings.Split(string(body), "\n")
	var urls []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var entry struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err == nil {
			if entry.URL != "" {
				urls = append(urls, entry.URL)
			}
		}
	}

	log.Printf("[OK] Common Crawl: Found %d URLs", len(urls))
	return urls
}
