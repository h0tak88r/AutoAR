// Package cf1016 detects dangling DNS records that resolve to Cloudflare's
// edge network but return an HTTP error code 1016 (Origin DNS Error).
//
// A Cloudflare 1016 response means:
//  - The DNS record is still alive and routing through Cloudflare's proxy.
//  - The backend origin server has been deleted, deactivated, or misconfigured.
//  - An attacker who can claim the original origin resource could hijack the subdomain.
//
// This is a reportable bug class under "DNS Misconfiguration / Dangling Record".
package cf1016

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// cloudflareCIDRs is the list of Cloudflare's published IPv4 CIDR ranges.
// Source: https://www.cloudflare.com/ips-v4
var cloudflareCIDRs = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

var cfNets []*net.IPNet

func init() {
	for _, cidr := range cloudflareCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			cfNets = append(cfNets, network)
		}
	}
}

// Finding represents a single dangling DNS / CF-1016 result.
type Finding struct {
	Subdomain  string
	IPs        []string
	StatusCode int   // HTTP status code returned
	IsError    bool  // true when the body contains "error code: 1016"
}

// Options controls the scan.
type Options struct {
	// Domain to enumerate subdomains from (reads live-subs.txt).
	// If SubdomainsFile is set it takes priority.
	Domain         string
	SubdomainsFile string // path to a file with one subdomain per line
	Threads        int    // concurrency, default 100
	Timeout        time.Duration
	OutputDir      string // directory to write results; defaults to resultsDir/domain/vulnerabilities/dns-takeover/
}

// Result holds the outcome of the scan.
type Result struct {
	Findings []Finding
	Output   string // path to the output file
}

// Run scans the subdomains for dangling Cloudflare 1016 records.
func Run(opts Options) (*Result, error) {
	if opts.Threads <= 0 {
		opts.Threads = 100
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}

	subdomains, err := loadSubdomains(opts)
	if err != nil {
		return nil, fmt.Errorf("cf1016: failed to load subdomains: %w", err)
	}
	if len(subdomains) == 0 {
		log.Printf("[cf1016] No subdomains to scan")
		return &Result{}, nil
	}

	log.Printf("[cf1016] Scanning %d subdomains for Cloudflare 1016 dangling records (threads=%d)", len(subdomains), opts.Threads)

	findings := scanConcurrent(subdomains, opts.Threads, opts.Timeout)

	// Write output
	outputPath, err := writeOutput(opts, findings)
	if err != nil {
		log.Printf("[cf1016] Warning: could not write output file: %v", err)
	}

	log.Printf("[cf1016] Done. Found %d dangling Cloudflare 1016 records", len(findings))

	return &Result{Findings: findings, Output: outputPath}, nil
}

// ------------------------  helpers  ------------------------

func loadSubdomains(opts Options) ([]string, error) {
	filePath := opts.SubdomainsFile

	if filePath == "" && opts.Domain != "" {
		// Try the live-subs.txt produced by the livehosts phase first, then
		// fall back to all subdomains.
		resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
		if resultsDir == "" {
			resultsDir = "new-results"
		}
		candidates := []string{
			filepath.Join(resultsDir, opts.Domain, "subs", "live-subs.txt"),
			filepath.Join(resultsDir, opts.Domain, "subs", "subdomains.txt"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				filePath = c
				break
			}
		}
	}

	if filePath == "" {
		return nil, fmt.Errorf("no subdomains file found for domain %q; run livehosts phase first", opts.Domain)
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var subs []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			subs = append(subs, line)
		}
	}
	return subs, sc.Err()
}

func scanConcurrent(subdomains []string, threads int, timeout time.Duration) []Finding {
	jobs := make(chan string, threads*2)
	results := make(chan Finding, threads*2)
	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range jobs {
				if f, ok := checkSubdomain(sub, timeout); ok {
					results <- f
				}
			}
		}()
	}

	go func() {
		for _, s := range subdomains {
			jobs <- s
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var findings []Finding
	for f := range results {
		findings = append(findings, f)
	}
	return findings
}

// checkSubdomain resolves the subdomain, checks whether all IPs belong to
// Cloudflare, and if so performs an HTTP probe to detect error code 1016.
func checkSubdomain(subdomain string, timeout time.Duration) (Finding, bool) {
	subdomain = strings.TrimPrefix(subdomain, "http://")
	subdomain = strings.TrimPrefix(subdomain, "https://")
	hostname := strings.Split(subdomain, "/")[0]

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupHost(ctx, hostname)
	if err != nil || len(ips) == 0 {
		return Finding{}, false
	}

	// All IPs must be Cloudflare IPs for this to be a CF-proxied host.
	allCF := true
	for _, rawIP := range ips {
		ip := net.ParseIP(rawIP)
		if ip == nil {
			allCF = false
			break
		}
		inCF := false
		for _, network := range cfNets {
			if network.Contains(ip) {
				inCF = true
				break
			}
		}
		if !inCF {
			allCF = false
			break
		}
	}

	if !allCF {
		return Finding{}, false
	}

	// At least one IP is Cloudflare — probe HTTP for error code 1016.
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	url := "https://" + hostname + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Finding{}, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; AutoAR/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		// Try plain HTTP as backup
		url = "http://" + hostname + "/"
		req2, err2 := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err2 != nil {
			return Finding{}, false
		}
		req2.Header.Set("User-Agent", "Mozilla/5.0 (compatible; AutoAR/1.0)")
		resp, err = client.Do(req2)
		if err != nil {
			return Finding{}, false
		}
	}
	defer resp.Body.Close()

	// Read up to 8 KB of body to look for the 1016 error string.
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	body := string(bodyBytes)

	// Cloudflare embeds "error code: 1016" in the HTML body.
	if !strings.Contains(body, "1016") {
		return Finding{}, false
	}

	log.Printf("[cf1016] FOUND dangling record: %s -> %v (HTTP %d, error code: 1016)", hostname, ips, resp.StatusCode)
	return Finding{
		Subdomain:  hostname,
		IPs:        ips,
		StatusCode: resp.StatusCode,
		IsError:    true,
	}, true
}

func writeOutput(opts Options, findings []Finding) (string, error) {
	outDir := opts.OutputDir
	if outDir == "" {
		resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
		if resultsDir == "" {
			resultsDir = "new-results"
		}
		domain := opts.Domain
		if domain == "" {
			domain = "unknown"
		}
		outDir = filepath.Join(resultsDir, domain, "vulnerabilities", "dns-takeover")
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}

	outputPath := filepath.Join(outDir, "cf1016-dangling.txt")

	f, err := os.Create(outputPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if len(findings) == 0 {
		fmt.Fprintln(f, "# No Cloudflare 1016 dangling records found.")
		return outputPath, nil
	}

	fmt.Fprintf(f, "# Cloudflare 1016 Dangling DNS Records\n")
	fmt.Fprintf(f, "# Vulnerability Type: DNS Misconfiguration / Dangling Record\n")
	fmt.Fprintf(f, "# Found: %d subdomains\n", len(findings))
	fmt.Fprintf(f, "# Generated: %s\n\n", time.Now().UTC().Format(time.RFC3339))

	fmt.Fprintf(f, "%-60s  %-40s  %s\n", "Subdomain", "Cloudflare IPs", "HTTP Status")
	fmt.Fprintf(f, "%s  %s  %s\n", strings.Repeat("-", 60), strings.Repeat("-", 40), strings.Repeat("-", 11))

	for _, finding := range findings {
		fmt.Fprintf(f, "%-60s  %-40s  %d\n",
			finding.Subdomain,
			strings.Join(finding.IPs, ", "),
			finding.StatusCode,
		)
	}

	fmt.Fprintf(f, "\n\n# --- Report Template ---\n")
	for _, finding := range findings {
		fmt.Fprintf(f, `
## Dangling DNS Record / Origin Resolution Error (Cloudflare 1016)
**Subdomain:** %s
**Cloudflare IPs:** %s
**HTTP Status:** %d

**Vulnerability Type:** DNS Misconfiguration / Dangling Record

**Summary:**
The subdomain %s is currently resolving to Cloudflare's edge network, but HTTP
requests return Cloudflare Error 1016 (Origin DNS Error). The DNS record still
actively routes traffic through Cloudflare, but the underlying backend origin
has been deleted, deactivated, or misconfigured.

**Steps To Reproduce:**
1. dig %s      (resolves to Cloudflare IPs: %s)
2. curl https://%s/  (observe error code: 1016)

**Impact:**
If an attacker can claim the abandoned origin resource, they could hijack this
subdomain via Cloudflare's proxy — enabling phishing, cookie theft, or session
hijacking against users of the target organization.

**Recommended Mitigation:**
Remove the A/CNAME records for %s from your DNS zone to clean up the dangling record.
`,
			finding.Subdomain,
			strings.Join(finding.IPs, ", "),
			finding.StatusCode,
			finding.Subdomain,
			finding.Subdomain,
			strings.Join(finding.IPs, ", "),
			finding.Subdomain,
			finding.Subdomain,
		)
	}

	log.Printf("[cf1016] Wrote %d findings to %s", len(findings), outputPath)
	return outputPath, nil
}
