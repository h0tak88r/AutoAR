package subdomains

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// EnumerateSubdomains enumerates subdomains for a given domain using subfinder
func EnumerateSubdomains(domain string, threads int) ([]string, error) {
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

	log.Printf("[OK] Found %d unique subdomains for %s", len(results), domain)
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
