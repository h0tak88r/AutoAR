package utils

import (
	"fmt"
	"path/filepath"
	"strings"
)

// SendPhaseFiles is a no-op stub — Discord bot has been removed.
// Phase results are served through the dashboard API instead.
func SendPhaseFiles(phaseName, domain string, filePaths []string) error {
	return nil
}

// GetPhaseFiles returns the expected result file paths for a scan phase.
func GetPhaseFiles(phaseName, domain string) []string {
	resultsDir := GetResultsDir()
	var files []string

	switch phaseName {
	case "subdomains":
		files = []string{
			filepath.Join(resultsDir, domain, "subs", "all-subs.txt"),
		}
	case "livehosts":
		files = []string{
			filepath.Join(resultsDir, domain, "subs", "all-subs.txt"),
			filepath.Join(resultsDir, domain, "subs", "live-subs.txt"),
		}
	case "reflection":
		files = []string{
			filepath.Join(resultsDir, domain, "vulnerabilities", "kxss-results.txt"),
		}
	case "js", "jsscan", "js-analysis":
		jsDir := filepath.Join(resultsDir, domain, "vulnerabilities", "js")
		if matches, err := filepath.Glob(filepath.Join(jsDir, "*.txt")); err == nil {
			for _, m := range matches {
				if !strings.HasSuffix(m, "js-urls.txt") {
					files = append(files, m)
				}
			}
		}
	case "js-endpoints":
		jsDir := filepath.Join(resultsDir, domain, "vulnerabilities", "js")
		files = []string{
			filepath.Join(jsDir, "js-urls.txt"),
			filepath.Join(resultsDir, domain, "vulnerabilities", "js-endpoints-results.txt"),
		}
	case "katana":
		urlsDir := filepath.Join(resultsDir, domain, "urls")
		files = []string{
			filepath.Join(urlsDir, "katana-urls.json"),
			filepath.Join(urlsDir, "all-urls.txt"),
		}
	case "xss-detection":
		files = []string{
			filepath.Join(resultsDir, domain, "vulnerabilities", "kxss-results.txt"),
			filepath.Join(resultsDir, domain, "vulnerabilities", "dalfox-results.txt"),
		}
	case "cnames":
		rootDomain := domain
		parts := strings.Split(domain, ".")
		if len(parts) > 2 {
			rootDomain = strings.Join(parts[len(parts)-2:], ".")
		}
		files = []string{
			filepath.Join(resultsDir, rootDomain, "subs", "cname-records.txt"),
		}
	case "tech":
		files = []string{
			filepath.Join(resultsDir, domain, "subs", "tech-detect.txt"),
		}
	case "urls":
		files = []string{
			filepath.Join(resultsDir, domain, "urls", "all-urls.txt"),
			filepath.Join(resultsDir, domain, "urls", "js-urls.txt"),
			filepath.Join(resultsDir, domain, "urls", "interesting-urls.txt"),
		}
	case "ports":
		files = []string{
			filepath.Join(resultsDir, domain, "ports", "ports.txt"),
		}
	case "backup":
		files = []string{
			filepath.Join(resultsDir, domain, "backup", "fuzzuli-results.txt"),
		}
	case "dns":
		rootDomain := domain
		parts := strings.Split(domain, ".")
		if len(parts) > 2 {
			rootDomain = strings.Join(parts[len(parts)-2:], ".")
		}
		dnsDir := filepath.Join(resultsDir, domain, "vulnerabilities", "dns-takeover")
		if matches, err := filepath.Glob(filepath.Join(dnsDir, "*.txt")); err == nil && len(matches) > 0 {
			files = append(files, matches...)
		}
		if domain != rootDomain {
			dnsRootDir := filepath.Join(resultsDir, rootDomain, "vulnerabilities", "dns-takeover")
			if matches, err := filepath.Glob(filepath.Join(dnsRootDir, "*.txt")); err == nil && len(matches) > 0 {
				files = append(files, matches...)
			}
		}
	case "cf1016":
		dnsDir := filepath.Join(resultsDir, domain, "vulnerabilities", "dns-takeover")
		files = []string{filepath.Join(dnsDir, "cf1016-dangling.txt")}
	case "exposure":
		files = []string{
			filepath.Join(resultsDir, domain, "vulnerabilities", "exposure", "exposure-findings.txt"),
		}
	case "misconfig":
		files = []string{
			filepath.Join(resultsDir, domain, "misconfig", "misconfig-scan-results.txt"),
			filepath.Join(resultsDir, domain, "misconfig", "scan-results.txt"),
			filepath.Join(resultsDir, "misconfig", domain, "scan-results.txt"),
		}
	case "nuclei":
		vulnDir := filepath.Join(resultsDir, domain, "vulnerabilities")
		if matches, err := filepath.Glob(filepath.Join(vulnDir, "nuclei-*.txt")); err == nil {
			for _, m := range matches {
				if !strings.HasSuffix(m, "nuclei-summary.txt") {
					files = append(files, m)
				}
			}
		}
	case "gf":
		vulnDir := filepath.Join(resultsDir, domain, "vulnerabilities")
		patterns := []string{"debug_logic", "idor", "iext", "img-traversal", "iparams", "isubs", "jsvar", "lfi", "rce", "redirect", "sqli", "ssrf", "ssti", "xss"}
		for _, pattern := range patterns {
			newPath := filepath.Join(vulnDir, pattern, fmt.Sprintf("gf-%s-results.txt", pattern))
			oldPath := filepath.Join(vulnDir, pattern, "gf-results.txt")
			if !IsFileEmpty(newPath) {
				files = append(files, newPath)
			} else if !IsFileEmpty(oldPath) {
				files = append(files, oldPath)
			} else {
				files = append(files, newPath)
			}
		}
	case "ffuf":
		files = []string{
			filepath.Join(resultsDir, domain, "ffuf", "ffuf-results.txt"),
		}
	case "wp_confusion":
		files = []string{
			filepath.Join(resultsDir, domain, "wp-confusion", "wp-confusion-results.txt"),
		}
	case "depconfusion":
		depDir := filepath.Join(resultsDir, domain, "depconfusion", "web-file")
		files = []string{
			filepath.Join(depDir, "depconfusion-results.txt"),
			filepath.Join(depDir, "confused2-web-results.json"),
		}
	case "s3":
		rootDomain := domain
		parts := strings.Split(domain, ".")
		if len(parts) > 2 {
			rootDomain = strings.Join(parts[len(parts)-2:], ".")
		}
		files = []string{
			filepath.Join(resultsDir, domain, "s3", "buckets.txt"),
			filepath.Join(resultsDir, "s3", rootDomain, "buckets.txt"),
		}
		s3Dir := filepath.Join(resultsDir, domain, "s3")
		if matches, err := filepath.Glob(filepath.Join(s3Dir, "*", "scan-results.txt")); err == nil {
			files = append(files, matches...)
		}
	case "githubscan", "github-scan":
		files = []string{
			filepath.Join(resultsDir, "github", "orgs", domain, "secrets.json"),
			filepath.Join(resultsDir, "github", "orgs", domain, "secrets_table.txt"),
			filepath.Join(resultsDir, "github", "repos", domain, "secrets.json"),
			filepath.Join(resultsDir, "github", "repos", domain, "secrets_table.txt"),
		}
	case "aem", "aem_scan":
		files = []string{
			filepath.Join(resultsDir, domain, "aem", "aem-scan.txt"),
		}
	case "zerodays", "0days":
		zerodaysDir := filepath.Join(resultsDir, domain, "zerodays")
		files = []string{
			filepath.Join(zerodaysDir, "react2shell-cve-2025-55182.txt"),
			filepath.Join(zerodaysDir, "mongodb-cve-2025-14847.txt"),
			filepath.Join(zerodaysDir, "zerodays-results.json"),
		}
		if matches, err := filepath.Glob(filepath.Join(zerodaysDir, "mongodb-leaked-*.bin")); err == nil {
			files = append(files, matches...)
		}
	}
	return files
}
