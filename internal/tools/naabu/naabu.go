package naabu

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/goflags"
	naaburesult "github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// ScanFromFile reads hosts from subsFile, runs a naabu scan using the
// official library, writes host:port lines to outFile, and returns the
// number of discovered open ports.
func ScanFromFile(subsFile string, threads int, outFile string) (int, error) {
	if threads <= 0 {
		threads = 100
	}

	hosts, err := readHosts(subsFile)
	if err != nil {
		return 0, err
	}
	if len(hosts) == 0 {
		return 0, fmt.Errorf("no hosts found in %s", subsFile)
	}

	// Prepare output file
	f, err := os.Create(outFile)
	if err != nil {
		return 0, fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	defer writer.Flush()

	count := 0

	onResult := func(hr *naaburesult.HostResult) {
		if hr == nil || len(hr.Ports) == 0 {
			return
		}
		// Extract hostname from URL if needed (remove protocol)
		host := hr.Host
		if strings.HasPrefix(host, "http://") {
			host = strings.TrimPrefix(host, "http://")
		} else if strings.HasPrefix(host, "https://") {
			host = strings.TrimPrefix(host, "https://")
		}
		// Remove path if present
		if idx := strings.Index(host, "/"); idx != -1 {
			host = host[:idx]
		}
		
		for _, p := range hr.Ports {
			if p == nil {
				continue
			}
			// Skip HTTP (80) and HTTPS (443) ports as they're already known from web scanning
			if p.Port == 80 || p.Port == 443 {
				continue
			}
			// Port is a struct, access the Port field (which is an int)
			line := fmt.Sprintf("%s:%d\n", host, p.Port)
			if _, err := writer.WriteString(line); err == nil {
				count++
			}
		}
	}

	options := &runner.Options{
		Host:     goflags.StringSlice(hosts),
		ScanType: "c", // connect scan to avoid raw packet requirements
		Rate:     threads * 100,
		Timeout:  5,
		Retries:  1,
		OnResult: onResult,
	}

	r, err := runner.NewRunner(options)
	if err != nil {
		return 0, fmt.Errorf("failed to create naabu runner: %w", err)
	}
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if err := r.RunEnumeration(ctx); err != nil {
		return count, fmt.Errorf("naabu scan failed: %w", err)
	}

	return count, nil
}

func readHosts(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open hosts file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var hosts []string
	seen := make(map[string]struct{})
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		
		// Clean URL: remove protocol (http://, https://)
		host := strings.TrimPrefix(line, "https://")
		host = strings.TrimPrefix(host, "http://")
		
		// Remove path if present
		if idx := strings.Index(host, "/"); idx != -1 {
			host = host[:idx]
		}
		
		// Remove port if present (keep hostname/IP only)
		if idx := strings.Index(host, ":"); idx != -1 {
			// Check if it's an IPv6 address (contains colons)
			if !strings.Contains(host, "[") {
				host = host[:idx]
			}
		}
		
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return hosts, nil
}
