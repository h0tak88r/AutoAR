package gobot

import (
	"fmt"
	"log"
	"time"
)

// SubdomainResult represents a subdomain result
type SubdomainResult struct {
	Subdomain   string `json:"subdomain"`
	IsLive      bool   `json:"is_live"`
	HTTPStatus  int    `json:"http_status"`
	HTTPSStatus int    `json:"https_status"`
}

// URLResult represents a URL result
type URLResult struct {
	URL       string `json:"url"`
	IsLive    bool   `json:"is_live"`
	StatusCode int   `json:"status_code"`
	Title     string `json:"title,omitempty"`
	Tech      string `json:"tech,omitempty"`
}

// NucleiResult represents a Nuclei finding
type NucleiResult struct {
	TemplateID   string `json:"template_id,omitempty"`
	Severity     string `json:"severity,omitempty"`
	URL          string `json:"url,omitempty"`
	MatchedAt    string `json:"matched_at,omitempty"`
	Description  string `json:"description,omitempty"`
	Info         NucleiInfo `json:"info,omitempty"`
}

type NucleiInfo struct {
	Name      string `json:"name,omitempty"`
	Severity  string `json:"severity,omitempty"`
	SeverityCSS string `json:"severity_css,omitempty"`
	Author    string `json:"author,omitempty"`
	Reference []string `json:"reference,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

// VulnerabilityResult represents a generic vulnerability finding
type VulnerabilityResult struct {
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	URL       string `json:"url,omitempty"`
	Target    string `json:"target,omitempty"`
	Source    string `json:"source,omitempty"`
	File      string `json:"file,omitempty"`
}

// ScanResults represents a collection of results for a scan
type ScanResults struct {
	ScanID     string            `json:"scan_id"`
	Target     string            `json:"target"`
	ScanType   string            `json:"scan_type"`
	Generated  string            `json:"generated"`
	Subdomains []SubdomainResult `json:"subdomains,omitempty"`
	URLs       []URLResult       `json:"urls,omitempty"`
	Vulnerabilities []VulnerabilityResult `json:"vulnerabilities,omitempty"`
	Files      map[string]interface{} `json:"files,omitempty"`
}

// writeJSONResults writes structured JSON results to a file
func writeJSONResults(scanID, fileName string, jsonData interface{}) error {
	if err := writeJSONToFile(scanID, fileName, jsonData); err != nil {
		return fmt.Errorf("failed to write JSON results: %w", err)
	}
	log.Printf("[JSON Output] Wrote %s with %d items", fileName, 0)
	return nil
}

// writeSubdomainResults writes subdomain results as JSON
func writeSubdomainResults(scanID, target string, results []SubdomainResult) error {
	output := ScanResults{
		ScanID:   scanID,
		Target:   target,
		ScanType: "subdomain",
		Generated: time.Now().Format(time.RFC3339),
		Subdomains: results,
	}
	return writeJSONResults(scanID, "subdomains.json", output)
}

// writeURLResults writes URL results as JSON
func writeURLResults(scanID, target string, results []URLResult) error {
	output := ScanResults{
		ScanID:   scanID,
		Target:   target,
		ScanType: "urls",
		Generated: time.Now().Format(time.RFC3339),
		URLs:     results,
	}
	return writeJSONResults(scanID, "urls.json", output)
}

// writeNucleiResults writes Nuclei findings as JSON
func writeNucleiResults(scanID, target string, findings []NucleiResult) error {
	output := ScanResults{
		ScanID:   scanID,
		Target:   target,
		ScanType: "nuclei",
		Generated: time.Now().Format(time.RFC3339),
		Vulnerabilities: []VulnerabilityResult{
			{
				Type:      "nuclei_vulnerability",
				Severity:  "vulnerability",
				Source:    "nuclei",
			},
		},
	}

	// Map to a unified format
	for _, f := range findings {
		output.Vulnerabilities = append(output.Vulnerabilities, VulnerabilityResult{
			Type:    "nuclei_template",
			Severity: f.Severity,
			URL:     f.URL,
			Target:   target,
			Source:  "nuclei",
			File:    fmt.Sprintf("nuclei-%s.json", f.TemplateID),
		})
	}

	return writeJSONResults(scanID, "nuclei-vulnerabilities.json", output)
}

// writeVulnerabilityResults writes generic vulnerability findings as JSON
func writeVulnerabilityResults(scanID, target string, findings []VulnerabilityResult) error {
	output := ScanResults{
		ScanID:   scanID,
		Target:   target,
		ScanType: "vulnerability",
		Generated: time.Now().Format(time.RFC3339),
		Vulnerabilities: findings,
	}
	return writeJSONResults(scanID, "vulnerabilities.json", output)
}

// writePortsResults writes port scan results as JSON
type PortsResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	State    string `json:"state"`
}

func writePortsResults(scanID, target string, ports []PortsResult) error {
	output := ScanResults{
		ScanID:   scanID,
		Target:   target,
		ScanType: "ports",
		Generated: time.Now().Format(time.RFC3339),
	}

	// Map ports to vulnerabilities
	for _, p := range ports {
		output.Vulnerabilities = append(output.Vulnerabilities, VulnerabilityResult{
			Type:    "open_port",
			Severity: "info",
			URL:     "",
			Target:  fmt.Sprintf("port:%d", p.Port),
			Source:  "ports",
			File:    "ports.json",
		})
	}

	return writeJSONResults(scanID, "ports.json", output)
}

// writeGFResults writes GF pattern scan results as JSON
type GFResult struct {
	URL       string `json:"url"`
	Parameter string `json:"parameter"`
	Pattern   string `json:"pattern"`
	Severity  string `json:"severity"`
}

func writeGFResults(scanID, target string, results []GFResult) error {
	output := ScanResults{
		ScanID:   scanID,
		Target:   target,
		ScanType: "gf",
		Generated: time.Now().Format(time.RFC3339),
		Vulnerabilities: []VulnerabilityResult{},
	}

	// Map GF results to vulnerabilities
	for _, r := range results {
		output.Vulnerabilities = append(output.Vulnerabilities, VulnerabilityResult{
			Type:    "gf_pattern",
			Severity: r.Severity,
			URL:     r.URL,
			Target:  target,
			Source:  "gf",
			File:    fmt.Sprintf("gf-%s.json", r.Pattern),
		})
	}

	return writeJSONResults(scanID, "gf-vulnerabilities.json", output)
}

// writeTechResults writes technology detection results as JSON
type TechResult struct {
	URL    string `json:"url"`
	Tech   string `json:"technology"`
	Version string `json:"version,omitempty"`
	Category string `json:"category,omitempty"`
}

func writeTechResults(scanID, target string, results []TechResult) error {
	output := ScanResults{
		ScanID:   scanID,
		Target:   target,
		ScanType: "tech",
		Generated: time.Now().Format(time.RFC3339),
	}

	// Map tech results to recon
	for _, r := range results {
		output.Subdomains = append(output.Subdomains, SubdomainResult{
			Subdomain: r.URL,
			IsLive:    true,
		})
	}

	return writeJSONResults(scanID, "tech-detect.json", output)
}

// writeZerodaysResults writes ZeroDays CVE scan results as JSON
func writeZerodaysResults(scanID, target string, cves []VulnerabilityResult) error {
	output := ScanResults{
		ScanID:   scanID,
		Target:   target,
		ScanType: "zerodays",
		Generated: time.Now().Format(time.RFC3339),
		Vulnerabilities: cves,
	}
	return writeJSONResults(scanID, "zerodays-results.json", output)
}

// writeS3Results writes S3 scan results as JSON
type S3Result struct {
	Bucket   string `json:"bucket"`
	Objects  int    `json:"objects"`
	Public   bool   `json:"public"`
	URL      string `json:"url,omitempty"`
}

func writeS3Results(scanID, target string, results []S3Result) error {
	output := ScanResults{
		ScanID:   scanID,
		Target:   target,
		ScanType: "s3",
		Generated: time.Now().Format(time.RFC3339),
	}

	for _, r := range results {
		if r.Public {
			output.Vulnerabilities = append(output.Vulnerabilities, VulnerabilityResult{
				Type:    "s3_bucket_public",
				Severity: "high",
				URL:     r.URL,
				Target:  r.Bucket,
				Source:  "s3",
				File:    "s3-vulnerabilities.json",
			})
		}
	}

	return writeJSONResults(scanID, "s3-vulnerabilities.json", output)
}

// writeGitHubResults writes GitHub scan results as JSON
type GitHubResult struct {
	Path     string `json:"path"`
	Secret   string `json:"secret"`
	Type     string `json:"type"`
	Found    bool   `json:"found"`
	Location string `json:"location,omitempty"`
}

func writeGitHubResults(scanID, repo string, results []GitHubResult) error {
	output := ScanResults{
		ScanID:   scanID,
		Target:   repo,
		ScanType: "github",
		Generated: time.Now().Format(time.RFC3339),
	}

	// Map GitHub results to vulnerabilities
	for _, r := range results {
		output.Vulnerabilities = append(output.Vulnerabilities, VulnerabilityResult{
			Type:    fmt.Sprintf("github_%s", r.Type),
			Severity: "secrets",
			URL:     r.Path,
			Target:  repo,
			Source:  "github",
			File:    "github-secrets.json",
		})
	}

	return writeJSONResults(scanID, "github-secrets.json", output)
}

// writeDNSResults writes DNS takeover results as JSON
type DNSResult struct {
	Domain     string `json:"domain"`
	CNAME      string `json:"cname,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Vulnerable bool   `json:"vulnerable"`
}

func writeDNSResults(scanID, target string, results []DNSResult) error {
	output := ScanResults{
		ScanID:   scanID,
		Target:   target,
		ScanType: "dns",
		Generated: time.Now().Format(time.RFC3339),
	}

	for _, r := range results {
		if r.Vulnerable {
			output.Vulnerabilities = append(output.Vulnerabilities, VulnerabilityResult{
				Type:    "dns_takeover",
				Severity: "critical",
				URL:     r.Domain,
				Target:  r.Domain,
				Source:  "dns",
				File:    "dns-takeover-vulnerabilities.json",
			})
		}
	}

	return writeJSONResults(scanID, "dns-takeover-vulnerabilities.json", output)
}

// writeReflectionResults writes XSS reflection scan results as JSON
func writeReflectionResults(scanID, target string, findings []VulnerabilityResult) error {
	output := ScanResults{
		ScanID:   scanID,
		Target:   target,
		ScanType: "reflection",
		Generated: time.Now().Format(time.RFC3339),
		Vulnerabilities: findings,
	}
	return writeJSONResults(scanID, "xss-reflection-vulnerabilities.json", output)
}

// writeScanResults creates a comprehensive scan results structure
func writeScanResults(scanID, target, scanType string, data map[string]interface{}) error {
	output := ScanResults{
		ScanID:   scanID,
		Target:   target,
		ScanType: scanType,
		Generated: time.Now().Format(time.RFC3339),
	}

	// Merge all data into files map
	if output.Files == nil {
		output.Files = make(map[string]interface{})
	}
	for k, v := range data {
		output.Files[k] = v
	}

	return writeJSONResults(scanID, fmt.Sprintf("%s-results.json", scanType), output)
}
