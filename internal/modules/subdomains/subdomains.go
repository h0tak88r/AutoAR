package subdomains

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/db"
)

// EnumerateSubdomains enumerates subdomains for a given domain using subfinder and API sources
// First checks the database for existing subdomains before enumerating
func EnumerateSubdomains(domain string, threads int) ([]string, error) {
	// Step 1: Check database first
	if os.Getenv("DB_HOST") != "" || os.Getenv("SAVE_TO_DB") == "true" {
		if err := db.Init(); err == nil {
			_ = db.InitSchema()
			count, err := db.CountSubdomains(domain)
			if err == nil && count > 0 {
				log.Printf("[INFO] Found %d subdomains in database for %s, using them", count, domain)
				// Load subdomains from database
				subs, err := db.ListSubdomains(domain)
				if err == nil && len(subs) > 0 {
					log.Printf("[OK] Using %d subdomains from database for %s", len(subs), domain)
					return subs, nil
				}
			}
		}
	}

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
	
	// 2. Get subdomains from API sources (lightweight, fast)
	log.Printf("[INFO] Collecting subdomains from API sources for %s", domain)
	apiResults := getSubdomainsFromAPIs(domain)
	for _, subdomain := range apiResults {
		addSubdomain(subdomain)
	}
	log.Printf("[INFO] Found %d subdomains from API sources", len(apiResults))
	
	// 3. Get subdomains from subfinder library
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
	
	// Save to database if configured
	if os.Getenv("DB_HOST") != "" || os.Getenv("SAVE_TO_DB") == "true" {
		if err := db.Init(); err == nil {
			_ = db.InitSchema()
			if err := db.BatchInsertSubdomains(domain, results, false); err != nil {
				log.Printf("[WARN] Failed to save subdomains to database: %v", err)
			} else {
				log.Printf("[OK] Saved %d subdomains to database for %s", len(results), domain)
			}
		} else {
			log.Printf("[WARN] Database initialization failed, skipping subdomains save: %v", err)
		}
	}
	
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
// It generates a temporary config file from environment variables if no config file exists
func getProviderConfig() string {
	// First, check if user explicitly provided a config file path
	configPath := os.Getenv("SUBFINDER_CONFIG")
	if configPath != "" {
	if _, err := os.Stat(configPath); err == nil {
		return configPath
	}
	}

	// Check default location
	homeDir, _ := os.UserHomeDir()
	defaultConfigPath := filepath.Join(homeDir, ".config", "subfinder", "config.yaml")
	if _, err := os.Stat(defaultConfigPath); err == nil {
		return defaultConfigPath
	}

	// Generate config from environment variables
	generatedConfigPath, err := generateSubfinderConfigFromEnv()
	if err != nil {
		log.Printf("[WARN] Failed to generate subfinder config from env vars: %v", err)
	return ""
	}

	return generatedConfigPath
}

// generateSubfinderConfigFromEnv generates a subfinder-compatible YAML config file from environment variables
func generateSubfinderConfigFromEnv() (string, error) {
	// Create temp directory for config
	tempDir := os.TempDir()
	configDir := filepath.Join(tempDir, "autoar-subfinder-config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create config directory: %v", err)
	}

	configPath := filepath.Join(configDir, "config.yaml")

	// Map of environment variable names to subfinder provider names
	providerMap := map[string]string{
		"GITHUB_TOKEN":              "github",
		"SECURITYTRAILS_API_KEY":   "securitytrails",
		"SHODAN_API_KEY":           "shodan",
		"VIRUSTOTAL_API_KEY":       "virustotal",
		"WORDPRESS_API_KEY":        "wordpress",
		"BEVIGIL_API_KEY":          "bevigil",
		"BINARYEDGE_API_KEY":       "binaryedge",
		"URLSCAN_API_KEY":           "urlscan",
		"CENSYS_API_ID":            "censys",
		"CENSYS_API_SECRET":         "censys",
		"CERTSPOTTER_API_KEY":      "certspotter",
		"CHAOS_API_KEY":            "chaos",
		"FOFA_EMAIL":               "fofa",
		"FOFA_KEY":                 "fofa",
		"FULLHUNT_API_KEY":         "fullhunt",
		"INTELX_API_KEY":           "intelx",
		"PASSIVETOTAL_USERNAME":     "passivetotal",
		"PASSIVETOTAL_API_KEY":     "passivetotal",
		"QUAKE_USERNAME":           "quake",
		"QUAKE_PASSWORD":           "quake",
		"THREATBOOK_API_KEY":       "threatbook",
		"WHOISXMLAPI_API_KEY":      "whoisxmlapi",
		"ZOOMEYE_USERNAME":         "zoomeye",
		"ZOOMEYE_PASSWORD":         "zoomeye",
		"ZOOMEYEAPI_API_KEY":       "zoomeyeapi",
	}

	var builder strings.Builder
	builder.WriteString("# Subfinder Configuration\n")
	builder.WriteString("# Generated automatically from environment variables\n\n")

	// Track which providers we've written
	writtenProviders := make(map[string]bool)

	// Handle special cases first (multi-value providers)
	// Censys needs both ID and SECRET
	if censysID := os.Getenv("CENSYS_API_ID"); censysID != "" {
		if censysSecret := os.Getenv("CENSYS_API_SECRET"); censysSecret != "" {
			builder.WriteString(fmt.Sprintf("censys: [\"%s\", \"%s\"]\n", censysID, censysSecret))
			writtenProviders["censys"] = true
		}
	}

	// FOFA needs both EMAIL and KEY
	if fofaEmail := os.Getenv("FOFA_EMAIL"); fofaEmail != "" {
		if fofaKey := os.Getenv("FOFA_KEY"); fofaKey != "" {
			builder.WriteString(fmt.Sprintf("fofa: [\"%s\", \"%s\"]\n", fofaEmail, fofaKey))
			writtenProviders["fofa"] = true
		}
	}

	// Passivetotal needs both USERNAME and API_KEY
	if ptUsername := os.Getenv("PASSIVETOTAL_USERNAME"); ptUsername != "" {
		if ptAPIKey := os.Getenv("PASSIVETOTAL_API_KEY"); ptAPIKey != "" {
			builder.WriteString(fmt.Sprintf("passivetotal: [\"%s\", \"%s\"]\n", ptUsername, ptAPIKey))
			writtenProviders["passivetotal"] = true
		}
	}

	// Quake needs both USERNAME and PASSWORD
	if quakeUsername := os.Getenv("QUAKE_USERNAME"); quakeUsername != "" {
		if quakePassword := os.Getenv("QUAKE_PASSWORD"); quakePassword != "" {
			builder.WriteString(fmt.Sprintf("quake: [\"%s\", \"%s\"]\n", quakeUsername, quakePassword))
			writtenProviders["quake"] = true
		}
	}

	// Zoomeye needs both USERNAME and PASSWORD
	if zoomeyeUsername := os.Getenv("ZOOMEYE_USERNAME"); zoomeyeUsername != "" {
		if zoomeyePassword := os.Getenv("ZOOMEYE_PASSWORD"); zoomeyePassword != "" {
			builder.WriteString(fmt.Sprintf("zoomeye: [\"%s\", \"%s\"]\n", zoomeyeUsername, zoomeyePassword))
			writtenProviders["zoomeye"] = true
		}
	}

	// Handle single-value providers
	for envVar, providerName := range providerMap {
		// Skip if already written (multi-value providers)
		if writtenProviders[providerName] {
			continue
		}

		// Skip censys, fofa, passivetotal, quake, zoomeye (already handled)
		if providerName == "censys" || providerName == "fofa" || providerName == "passivetotal" || providerName == "quake" || providerName == "zoomeye" {
			continue
		}

		if value := os.Getenv(envVar); value != "" {
			if !writtenProviders[providerName] {
				builder.WriteString(fmt.Sprintf("%s: [\"%s\"]\n", providerName, value))
				writtenProviders[providerName] = true
			}
		}
	}

	// Check if we have any providers configured
	configContent := builder.String()
	trimmedContent := strings.TrimSpace(configContent)
	
	// If no providers were configured (only header comments), don't create a file
	// Count actual provider entries (lines that contain ": [")
	providerLines := strings.Count(trimmedContent, ": [")
	if providerLines == 0 {
		// No providers configured, return empty string to use default providers
		return "", nil
	}

	// Write config to file only if we have at least one provider
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		return "", fmt.Errorf("failed to write config file: %v", err)
	}

	return configPath, nil
}
