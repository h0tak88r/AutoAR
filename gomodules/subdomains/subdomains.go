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
	var allResults []string
	var mu sync.Mutex
	unique := make(map[string]bool)
	
	// Helper to add unique subdomain
	addUnique := func(subdomain string) {
		subdomain = strings.TrimSpace(subdomain)
		if subdomain != "" && !strings.Contains(subdomain, "*") {
			mu.Lock()
			if !unique[subdomain] {
				unique[subdomain] = true
				allResults = append(allResults, subdomain)
			}
			mu.Unlock()
		}
	}
	
	// Collect from API sources first (lightweight, fast)
	var wg sync.WaitGroup
	
	// HackerTarget API
	wg.Add(1)
	go func() {
		defer wg.Done()
		apiResults := getSubdomainsFromHackerTarget(domain)
		for _, subdomain := range apiResults {
			addUnique(subdomain)
		}
	}()
	
	// crt.sh API
	wg.Add(1)
	go func() {
		defer wg.Done()
		apiResults := getSubdomainsFromCrtSh(domain)
		for _, subdomain := range apiResults {
			addUnique(subdomain)
		}
	}()
	
	// Wait for API calls to complete
	wg.Wait()
	
	// Use subfinder library for comprehensive enumeration
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
		log.Printf("[WARN] Failed to create subfinder runner: %v, using API results only", err)
		return allResults, nil
	}

	// Run enumeration and capture output
	var buf bytes.Buffer
	err = subfinderRunner.EnumerateSingleDomain(domain, []io.Writer{&buf})
	if err != nil {
		log.Printf("[WARN] Subfinder enumeration failed: %v, using API results only", err)
		return allResults, nil
	}
	
	// Parse results from buffer
	bufData := buf.String()
	lines := strings.Split(strings.TrimSpace(bufData), "\n")
	
	for _, line := range lines {
		addUnique(line)
	}

	log.Printf("[OK] Found %d unique subdomains for %s", len(allResults), domain)
	return allResults, nil
}

// getSubdomainsFromHackerTarget fetches subdomains from HackerTarget API
func getSubdomainsFromHackerTarget(domain string) []string {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	resp, err := http.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	
	// Extract subdomains using regex
	re := regexp.MustCompile(`[a-zA-Z0-9._-]+\.` + regexp.QuoteMeta(domain))
	matches := re.FindAllString(string(body), -1)
	
	var results []string
	for _, match := range matches {
		results = append(results, strings.TrimSpace(match))
	}
	
	return results
}

// getSubdomainsFromCrtSh fetches subdomains from crt.sh API
func getSubdomainsFromCrtSh(domain string) []string {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	resp, err := http.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	
	var crtEntries []struct {
		NameValue string `json:"name_value"`
	}
	
	if err := json.Unmarshal(body, &crtEntries); err != nil {
		// If JSON parsing fails, try regex extraction
		re := regexp.MustCompile(`[a-zA-Z0-9._-]+\.` + regexp.QuoteMeta(domain))
		matches := re.FindAllString(string(body), -1)
		var results []string
		for _, match := range matches {
			results = append(results, strings.TrimSpace(match))
		}
		return results
	}
	
	var results []string
	unique := make(map[string]bool)
	
	for _, entry := range crtEntries {
		// Entry can contain multiple domains separated by newlines
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name != "" && strings.HasSuffix(name, "."+domain) && !unique[name] {
				unique[name] = true
				results = append(results, name)
			}
		}
	}
	
	return results
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
