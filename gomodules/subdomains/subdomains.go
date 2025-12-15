package subdomains

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// EnumerateSubdomains enumerates subdomains for a given domain using subfinder and API sources
func EnumerateSubdomains(domain string, threads int) ([]string, error) {
	var results []string
	var mu sync.Mutex
	unique := make(map[string]bool)
	
	// Helper to add unique subdomain
	addSubdomain := func(subdomain string) {
		subdomain = strings.TrimSpace(subdomain)
		if subdomain != "" && !strings.Contains(subdomain, "*") {
			mu.Lock()
			if !unique[subdomain] {
				unique[subdomain] = true
				results = append(results, subdomain)
			}
			mu.Unlock()
		}
	}
	
	// 1. Get subdomains from API sources (lightweight, fast)
	log.Printf("[INFO] Collecting subdomains from API sources for %s", domain)
	apiResults := getSubdomainsFromAPIs(domain)
	for _, subdomain := range apiResults {
		addSubdomain(subdomain)
	}
	log.Printf("[INFO] Found %d subdomains from API sources", len(apiResults))
	
	// 2. Get subdomains from subfinder library
	log.Printf("[INFO] Collecting subdomains using subfinder library for %s", domain)
	subfinderResults, err := getSubdomainsFromSubfinder(domain, threads)
	if err != nil {
		log.Printf("[WARN] Subfinder enumeration failed: %v", err)
	} else {
		for _, subdomain := range subfinderResults {
			addSubdomain(subdomain)
		}
		log.Printf("[INFO] Found %d additional subdomains from subfinder", len(subfinderResults))
	}

	log.Printf("[OK] Found %d unique subdomains for %s", len(results), domain)
	return results, nil
}

// getSubdomainsFromAPIs collects subdomains from hackertarget and crt.sh APIs
func getSubdomainsFromAPIs(domain string) []string {
	var results []string
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	// Hackertarget API
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, err := http.Get(fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain))
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			re := regexp.MustCompile(fmt.Sprintf(`[a-zA-Z0-9._-]+\.%s`, regexp.QuoteMeta(domain)))
			matches := re.FindAllString(string(body), -1)
			mu.Lock()
			results = append(results, matches...)
			mu.Unlock()
		}
	}()
	
	// crt.sh API
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, err := http.Get(fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain))
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			
			// Parse JSON response
			var crtData []map[string]interface{}
			if json.Unmarshal(body, &crtData) == nil {
				re := regexp.MustCompile(fmt.Sprintf(`[a-zA-Z0-9._-]+\.%s`, regexp.QuoteMeta(domain)))
				for _, entry := range crtData {
					if nameValue, ok := entry["name_value"].(string); ok {
						matches := re.FindAllString(nameValue, -1)
						mu.Lock()
						results = append(results, matches...)
						mu.Unlock()
					}
				}
			} else {
				// Fallback to regex if JSON parsing fails
				re := regexp.MustCompile(fmt.Sprintf(`[a-zA-Z0-9._-]+\.%s`, regexp.QuoteMeta(domain)))
				matches := re.FindAllString(string(body), -1)
				mu.Lock()
				results = append(results, matches...)
				mu.Unlock()
			}
		}
	}()
	
	wg.Wait()
	return results
}

// getSubdomainsFromSubfinder collects subdomains using subfinder library
func getSubdomainsFromSubfinder(domain string, threads int) ([]string, error) {
	// Create runner options
	opts := &runner.Options{
		Threads:            threads,
		Timeout:            30,
		MaxEnumerationTime: 10,
		ProviderConfig:     getProviderConfig(),
		Verbose:            false,
		Silent:             true,
		NoColor:            true,
		JSON:               false,
		HostIP:             false,
		RemoveWildcard:     true,
		Domain:             []string{domain},
	}

	// Create runner instance
	subfinderRunner, err := runner.NewRunner(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create subfinder runner: %v", err)
	}

	// Run enumeration and capture output
	var buf bytes.Buffer
	err = subfinderRunner.EnumerateSingleDomain(domain, []io.Writer{&buf})
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate subdomains: %v", err)
	}
	
	// Parse results from buffer
	bufData := buf.String()
	lines := strings.Split(strings.TrimSpace(bufData), "\n")
	
	var results []string
	unique := make(map[string]bool)
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.Contains(line, "*") && !unique[line] {
			unique[line] = true
			results = append(results, line)
		}
	}

	return results, nil
}

// getProviderConfig returns provider configuration from environment variables
func getProviderConfig() string {
	// Check for subfinder config file
	configPath := os.Getenv("SUBFINDER_CONFIG")
	if configPath == "" {
		homeDir, _ := os.UserHomeDir()
		configPath = fmt.Sprintf("%s/.config/subfinder/config.yaml", homeDir)
	}

	if _, err := os.Stat(configPath); err == nil {
		return configPath
	}

	// Return empty string to use default providers
	return ""
}
