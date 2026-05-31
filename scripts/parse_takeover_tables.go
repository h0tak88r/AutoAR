package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type SubdomainTakeoverEntry struct {
	Engine       string `json:"engine"`
	Status       string `json:"status"`
	Verified     string `json:"verified"`
	Fingerprint  string `json:"fingerprint"`
	Discussion   string `json:"discussion"`
	Documentation string `json:"documentation"`
}

type DNSTakeoverEntry struct {
	Provider     string `json:"provider"`
	Status       string `json:"status"`
	Fingerprint  string `json:"fingerprint"`
	Instructions string `json:"instructions"`
}

func parseSubdomainTakeover(filename string) ([]SubdomainTakeoverEntry, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []SubdomainTakeoverEntry
	scanner := bufio.NewScanner(file)
	inTable := false
	headerPassed := false

	for scanner.Scan() {
		line := scanner.Text()

		// Start parsing when we hit the table header
		if strings.Contains(line, "| Engine") && strings.Contains(line, "| Status") {
			inTable = true
			continue
		}

		// Skip separator line
		if inTable && !headerPassed && strings.Contains(line, "| ---") {
			headerPassed = true
			continue
		}

		// Parse table rows
		if inTable && headerPassed && strings.HasPrefix(line, "|") {
			// Stop if we hit a section header
			if strings.HasPrefix(line, "## ") {
				break
			}

			parts := strings.Split(line, "|")
			if len(parts) >= 8 {
				engine := cleanCell(parts[1])
				status := cleanCell(parts[2])

				// Only add if engine name is not empty and not a header
				if engine != "" && engine != "Engine" && !strings.Contains(engine, "---") {
					entry := SubdomainTakeoverEntry{
						Engine:        engine,
						Status:        status,
						Verified:      cleanCell(parts[3]),
						Fingerprint:   cleanCell(parts[5]),
						Discussion:    cleanCell(parts[6]),
						Documentation: cleanCell(parts[7]),
					}
					entries = append(entries, entry)
				}
			}
		}
	}

	return entries, scanner.Err()
}

func parseDNSTakeover(filename string) ([]DNSTakeoverEntry, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []DNSTakeoverEntry
	scanner := bufio.NewScanner(file)
	inTable := false
	headerPassed := false

	for scanner.Scan() {
		line := scanner.Text()

		// Start parsing when we hit the DNS Providers table header
		if strings.Contains(line, "Provider") && strings.Contains(line, "Status") && strings.Contains(line, "Fingerprint") {
			inTable = true
			continue
		}

		// Skip separator line
		if inTable && !headerPassed && strings.HasPrefix(line, "---") {
			headerPassed = true
			continue
		}

		// Parse table rows
		if inTable && headerPassed && strings.HasPrefix(line, "[") {
			// Stop if we hit "## Private DNS" section
			if strings.Contains(line, "## Private DNS") {
				break
			}

			parts := strings.Split(line, "|")
			if len(parts) >= 4 {
				entry := DNSTakeoverEntry{
					Provider:     cleanCell(parts[0]),
					Status:       cleanCell(parts[1]),
					Fingerprint:  cleanCell(parts[2]),
					Instructions: cleanCell(parts[3]),
				}

				// Only add if provider name is not empty
				if entry.Provider != "" {
					entries = append(entries, entry)
				}
			}
		}
	}

	return entries, scanner.Err()
}

func cleanCell(cell string) string {
	// Remove markdown formatting
	cell = strings.TrimSpace(cell)
	cell = strings.ReplaceAll(cell, "**", "")
	cell = strings.ReplaceAll(cell, "`", "")

	// Extract link text from markdown links [text](url)
	if strings.Contains(cell, "[") && strings.Contains(cell, "]") {
		start := strings.Index(cell, "[")
		end := strings.Index(cell, "]")
		if start >= 0 && end > start {
			linkText := cell[start+1 : end]
			// Keep the URL if present
			if strings.Contains(cell, "(") && strings.Contains(cell, ")") {
				urlStart := strings.Index(cell, "(")
				urlEnd := strings.Index(cell, ")")
				if urlStart > end && urlEnd > urlStart {
					url := cell[urlStart+1 : urlEnd]
					return linkText + " (" + url + ")"
				}
			}
			return linkText
		}
	}

	// Clean up HTML tags
	cell = strings.ReplaceAll(cell, "<br>", ", ")
	cell = strings.ReplaceAll(cell, "<sub>", "")
	cell = strings.ReplaceAll(cell, "</sub>", "")
	cell = strings.ReplaceAll(cell, "<sup>", "")
	cell = strings.ReplaceAll(cell, "</sup>", "")
	cell = strings.ReplaceAll(cell, "<ins>", "")
	cell = strings.ReplaceAll(cell, "</ins>", "")

	return strings.TrimSpace(cell)
}

func main() {
	// Parse subdomain takeover table
	subdomainEntries, err := parseSubdomainTakeover("/tmp/can-i-take-over-xyz.md")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing subdomain takeover: %v\n", err)
		os.Exit(1)
	}

	// Parse DNS takeover table
	dnsEntries, err := parseDNSTakeover("/tmp/can-i-take-over-dns.md")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing DNS takeover: %v\n", err)
		os.Exit(1)
	}

	// Write subdomain takeover JSON
	subdomainJSON, err := json.MarshalIndent(subdomainEntries, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling subdomain JSON: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile("web/static/data/subdomain-takeover.json", subdomainJSON, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing subdomain JSON: %v\n", err)
		os.Exit(1)
	}

	// Write DNS takeover JSON
	dnsJSON, err := json.MarshalIndent(dnsEntries, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling DNS JSON: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile("web/static/data/dns-takeover.json", dnsJSON, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing DNS JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Parsed %d subdomain takeover entries\n", len(subdomainEntries))
	fmt.Printf("✓ Parsed %d DNS takeover entries\n", len(dnsEntries))
	fmt.Println("✓ JSON files written to web/static/data/")
}
