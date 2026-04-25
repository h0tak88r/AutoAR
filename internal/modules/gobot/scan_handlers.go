package gobot

// scan_handlers.go — HTTP handlers for every scan type.
//
// All handlers call their module's Go API directly via runScanInProcess
// instead of spawning a child "autoar ..." subprocess. This eliminates the
// double-memory fork that was causing Docker OOM container restarts.

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"

	"github.com/gin-gonic/gin"
	backupmod "github.com/h0tak88r/AutoAR/internal/modules/backup"
	cnamesmod "github.com/h0tak88r/AutoAR/internal/modules/cnames"
	dnsmod "github.com/h0tak88r/AutoAR/internal/modules/dns"
	domainmod "github.com/h0tak88r/AutoAR/internal/modules/domain"
	ffufmod "github.com/h0tak88r/AutoAR/internal/modules/ffuf"
	gfmod "github.com/h0tak88r/AutoAR/internal/modules/gf"
	githubmod "github.com/h0tak88r/AutoAR/internal/modules/githubscan"
	jsscanmod "github.com/h0tak88r/AutoAR/internal/modules/jsscan"
	litemod "github.com/h0tak88r/AutoAR/internal/modules/lite"
	livehostsmod "github.com/h0tak88r/AutoAR/internal/modules/livehosts"
	misconfigmod "github.com/h0tak88r/AutoAR/internal/modules/misconfig"
	nucleimod "github.com/h0tak88r/AutoAR/internal/modules/nuclei"
	portsmod "github.com/h0tak88r/AutoAR/internal/modules/ports"
	reconmod "github.com/h0tak88r/AutoAR/internal/modules/recon"
	reflectionmod "github.com/h0tak88r/AutoAR/internal/modules/reflection"
	s3mod "github.com/h0tak88r/AutoAR/internal/modules/s3"
	subdomainsmod "github.com/h0tak88r/AutoAR/internal/modules/subdomains"
	subdomainmod "github.com/h0tak88r/AutoAR/internal/modules/subdomain"
	techmod "github.com/h0tak88r/AutoAR/internal/modules/tech"
	urlsmod "github.com/h0tak88r/AutoAR/internal/modules/urls"
	zerodaysmod "github.com/h0tak88r/AutoAR/internal/modules/zerodays"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func bindOrBad(c *gin.Context, req interface{}) bool {
	if err := c.ShouldBindJSON(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return false
	}
	return true
}

func requireField(c *gin.Context, v *string, name string) bool {
	if v == nil || *v == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": name + " is required"})
		return false
	}
	return true
}

func okStarted(c *gin.Context, scanID, msg string) {
	c.JSON(http.StatusOK, ScanResponse{ScanID: scanID, Status: "started", Message: msg})
}

// extractRootDomain strips subdomains to return the root domain.
// Returns empty string if the input is itself a root domain.
func extractRootDomain(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(strings.TrimPrefix(host, "http://"), "https://")
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return ""
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// ── Subdomains ────────────────────────────────────────────────────────────────

func scanSubdomains(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Domain, "Domain") { return }
	domain := *req.Domain
	scanID := generateScanID()
	go runScanInProcess(scanID, "subdomains", domain, func() error {
		_, err := subdomainsmod.EnumerateSubdomains(domain, 0)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Subdomain enumeration started for %s", domain))
}

// ── Domain workflow ───────────────────────────────────────────────────────────

func scanDomainRun(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Domain, "Domain") { return }
	domain := *req.Domain
	skipFFuf := req.SkipFFuf != nil && *req.SkipFFuf
	scanID := generateScanID()
	go runScanInProcess(scanID, "domain_run", domain, func() error {
		_, err := domainmod.RunDomain(domainmod.ScanOptions{Domain: domain, SkipFFuf: skipFFuf})
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Domain workflow scan started for %s", domain))
}

// ── Subdomain workflow ────────────────────────────────────────────────────────

func scanSubdomainRun(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Subdomain, "Subdomain") { return }
	sub := *req.Subdomain
	skipFFuf := req.SkipFFuf != nil && *req.SkipFFuf
	scanID := generateScanID()
	go runScanInProcess(scanID, "subdomain_run", sub, func() error {
		_, err := subdomainmod.RunSubdomainWithOptions(sub, subdomainmod.RunOptions{SkipFFuf: skipFFuf})
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Subdomain workflow scan started for %s", sub))
}

// ── Live hosts ────────────────────────────────────────────────────────────────

func scanLivehosts(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Domain, "Domain") { return }
	domain := *req.Domain
	scanID := generateScanID()
	go runScanInProcess(scanID, "livehosts", domain, func() error {
		_, err := livehostsmod.FilterLiveHosts(domain, 0, false)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Live hosts discovery started for %s", domain))
}

// ── CNAMEs ────────────────────────────────────────────────────────────────────

func scanCnames(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Domain, "Domain") { return }
	domain := *req.Domain
	scanID := generateScanID()
	go runScanInProcess(scanID, "cnames", domain, func() error {
		_, err := cnamesmod.CollectCNAMEs(domain)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("CNAME enumeration started for %s", domain))
}

// ── URLs ──────────────────────────────────────────────────────────────────────

func scanURLs(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Domain, "Domain") { return }
	domain := *req.Domain
	skipEnum := req.SkipSubdomainEnum != nil && *req.SkipSubdomainEnum
	scanID := generateScanID()
	go runScanInProcess(scanID, "urls", domain, func() error {
		_, err := urlsmod.CollectURLs(domain, 0, skipEnum)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("URL collection started for %s", domain))
}

// ── JS scan ───────────────────────────────────────────────────────────────────

func scanJS(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Domain, "Domain") { return }
	domain := *req.Domain
	sub := ""
	if req.Subdomain != nil {
		sub = *req.Subdomain
	}
	scanID := generateScanID()
	go runScanInProcess(scanID, "js", domain, func() error {
		_, err := jsscanmod.Run(jsscanmod.Options{Domain: domain, Subdomain: sub})
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("JavaScript scan started for %s", domain))
}

// ── Reflection ────────────────────────────────────────────────────────────────

func scanReflection(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Domain, "Domain") { return }
	domain := *req.Domain
	scanID := generateScanID()
	go runScanInProcess(scanID, "reflection", domain, func() error {
		_, err := reflectionmod.ScanReflection(domain)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Reflection scan started for %s", domain))
}

// ── Nuclei ────────────────────────────────────────────────────────────────────

func scanNuclei(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if (req.Domain == nil || *req.Domain == "") && (req.URL == nil || *req.URL == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Either domain or url is required"})
		return
	}
	if req.Domain != nil && *req.Domain != "" && req.URL != nil && *req.URL != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot use both domain and url together"})
		return
	}
	mode := "full"
	if req.Mode != nil && *req.Mode != "" {
		mode = *req.Mode
		valid := map[string]bool{"full": true, "cves": true, "panels": true, "default-logins": true, "vulnerabilities": true}
		if !valid[mode] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid mode"})
			return
		}
	}
	var target string
	opts := nucleimod.Options{Mode: nucleimod.ScanMode(mode)}
	if req.Domain != nil && *req.Domain != "" {
		target = *req.Domain
		opts.Domain = target
	} else {
		target = *req.URL
		opts.URL = target
	}
	scanID := generateScanID()
	go runScanInProcess(scanID, fmt.Sprintf("nuclei-%s", mode), target, func() error {
		_, err := nucleimod.RunNuclei(opts)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Nuclei %s scan started for %s", mode, target))
}

// ── Recon ─────────────────────────────────────────────────────────────────────

func scanRecon(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Domain, "Domain") { return }
	domain := *req.Domain
	scanID := generateScanID()
	go runScanInProcess(scanID, "recon", domain, func() error {
		_, err := reconmod.RunFullRecon(domain, 0)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Unified asset discovery started for %s", domain))
}

// ── Tech detect ───────────────────────────────────────────────────────────────

func scanTech(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Domain, "Domain") { return }
	domain := *req.Domain
	scanID := generateScanID()
	go runScanInProcess(scanID, "tech", domain, func() error {
		_, err := techmod.DetectTech(domain, 0)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Technology detection started for %s", domain))
}

// ── Ports ─────────────────────────────────────────────────────────────────────

func scanPorts(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Domain, "Domain") { return }
	domain := *req.Domain
	scanID := generateScanID()
	go runScanInProcess(scanID, "ports", domain, func() error {
		_, err := portsmod.ScanPorts(domain, 0)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Port scan started for %s", domain))
}

// ── GF patterns ───────────────────────────────────────────────────────────────

func scanGF(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Domain, "Domain") { return }
	domain := *req.Domain
	scanID := generateScanID()
	go runScanInProcess(scanID, "gf", domain, func() error {
		_, err := gfmod.ScanGF(domain)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("GF pattern scan started for %s", domain))
}

// ── DNS takeover (legacy endpoint) ────────────────────────────────────────────

func scanDNSTakeover(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Domain, "Domain") { return }
	domain := *req.Domain
	scanID := generateScanID()
	go runScanInProcess(scanID, "dns-takeover", domain, func() error {
		return dnsmod.Takeover(domain)
	})
	okStarted(c, scanID, fmt.Sprintf("DNS takeover scan started for %s", domain))
}

// ── DNS unified ───────────────────────────────────────────────────────────────

func scanDNS(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Domain, "Domain") { return }
	domain := *req.Domain
	dnsType := "takeover"
	if req.DNSType != nil && *req.DNSType != "" {
		dnsType = *req.DNSType
		if dnsType != "takeover" && dnsType != "dangling-ip" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "dns_type must be 'takeover' or 'dangling-ip'"})
			return
		}
	}
	scanID := generateScanID()
	go runScanInProcess(scanID, fmt.Sprintf("dns-%s", dnsType), domain, func() error {
		if dnsType == "dangling-ip" {
			return dnsmod.DanglingIP(domain)
		}
		return dnsmod.Takeover(domain)
	})
	okStarted(c, scanID, fmt.Sprintf("DNS %s scan started for %s", dnsType, domain))
}

// ── DNS CF1016 ────────────────────────────────────────────────────────────────

func scanDNSCF1016(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	var target string
	switch {
	case req.Domain != nil && *req.Domain != "":
		target = *req.Domain
	case req.Subdomain != nil && *req.Subdomain != "":
		target = *req.Subdomain
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain or subdomain is required"})
		return
	}
	scanID := generateScanID()
	go runScanInProcess(scanID, "dns_cf1016", target, func() error {
		return dnsmod.CNAME(target)
	})
	okStarted(c, scanID, fmt.Sprintf("Cloudflare 1016 dangling DNS scan started for %s", target))
}

// ── FFuf ──────────────────────────────────────────────────────────────────────

func scanFFuf(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Target, "target URL") { return }
	target := *req.Target
	opts := ffufmod.Options{Target: target}
	if req.Wordlist != nil { opts.Wordlist = *req.Wordlist }
	if req.Threads != nil && *req.Threads > 0 { opts.Threads = *req.Threads }
	if req.Recursion != nil { opts.Recursion = *req.Recursion }
	if req.RecursionDepth != nil { opts.RecursionDepth = *req.RecursionDepth }
	if req.Bypass403 != nil { opts.Bypass403 = *req.Bypass403 }
	if req.Extensions != nil { opts.Extensions = *req.Extensions }
	if req.CustomHeaders != nil { opts.CustomHeaders = *req.CustomHeaders }
	scanID := generateScanID()
	go runScanInProcess(scanID, "ffuf", target, func() error {
		_, err := ffufmod.RunFFuf(opts)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("FFuf fuzzing started for %s", target))
}

// ── Backup ────────────────────────────────────────────────────────────────────

func scanBackup(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Domain, "Domain") { return }
	domain := *req.Domain
	opts := backupmod.Options{Domain: domain}
	if req.Threads != nil && *req.Threads > 0 { opts.Threads = *req.Threads }
	scanID := generateScanID()
	go runScanInProcess(scanID, "backup", domain, func() error {
		_, err := backupmod.Run(opts)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Backup file discovery started for %s", domain))
}

// ── Misconfig ─────────────────────────────────────────────────────────────────

func scanMisconfig(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Domain, "Domain") { return }
	domain := *req.Domain
	opts := misconfigmod.Options{
		Target: domain,
		Action: "scan",
	}
	if req.ServiceID != nil { opts.ServiceID = *req.ServiceID }
	if req.Delay != nil && *req.Delay > 0 { opts.Delay = *req.Delay }
	if req.Permutations != nil { opts.EnablePerms = *req.Permutations }
	scanID := generateScanID()
	go runScanInProcess(scanID, "misconfig", domain, func() error {
		return misconfigmod.Run(opts)
	})
	okStarted(c, scanID, fmt.Sprintf("Misconfiguration scan started for %s", domain))
}

// ── Zerodays ──────────────────────────────────────────────────────────────────

func scanZerodays(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if (req.Domain == nil || *req.Domain == "") && (req.DomainsFile == nil || *req.DomainsFile == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Either domain or domains_file is required"})
		return
	}
	if req.Domain != nil && *req.Domain != "" && req.DomainsFile != nil && *req.DomainsFile != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot use both domain and domains_file"})
		return
	}
	opts := zerodaysmod.Options{}
	var target string
	if req.Domain != nil && *req.Domain != "" {
		target = *req.Domain
		opts.Domain = target
	} else {
		target = *req.DomainsFile
		opts.DomainsFile = target
	}
	if req.Threads != nil && *req.Threads > 0 { opts.Threads = *req.Threads }
	if req.DOSTest != nil { opts.DOSTest = *req.DOSTest }
	if req.EnableSourceExposure != nil { opts.EnableSourceExposure = *req.EnableSourceExposure }
	if req.CVEs != nil { opts.CVEs = *req.CVEs }
	if req.MongoDBHost != nil { opts.MongoDBHost = *req.MongoDBHost }
	if req.MongoDBPort != nil { opts.MongoDBPort = *req.MongoDBPort }
	if req.Silent != nil { opts.Silent = *req.Silent }
	scanID := generateScanID()
	go runScanInProcess(scanID, "zerodays", target, func() error {
		_, err := zerodaysmod.Run(opts)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Zerodays scan started for %s", target))
}

// ── JWT ───────────────────────────────────────────────────────────────────────
// JWT uses an external binary; keep subprocess but avoid forking autoar itself.

func scanJWT(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Token, "JWT token") { return }
	token := *req.Token
	scanID := generateScanID()
	command := []string{getAutoarScriptPath(), "jwt", "scan", "-t", token}
	if req.SkipCrack != nil && *req.SkipCrack { command = append(command, "--skip-crack") }
	if req.SkipPayloads != nil && *req.SkipPayloads { command = append(command, "--skip-payloads") }
	if req.WordlistPath != nil && *req.WordlistPath != "" { command = append(command, "--wordlist", *req.WordlistPath) }
	if req.MaxCrackAttempts != nil && *req.MaxCrackAttempts > 0 {
		command = append(command, "--max-crack-attempts", fmt.Sprintf("%d", *req.MaxCrackAttempts))
	}
	go executeScan(scanID, command, "jwt")
	okStarted(c, scanID, "JWT vulnerability scan started")
}

// ── S3 ────────────────────────────────────────────────────────────────────────

func scanS3(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Bucket, "Bucket name") { return }
	bucket := *req.Bucket
	opts := s3mod.Options{Bucket: bucket}
	if req.Region != nil { opts.Region = *req.Region }
	scanID := generateScanID()
	go runScanInProcess(scanID, "s3", bucket, func() error {
		return s3mod.Run(opts)
	})
	okStarted(c, scanID, fmt.Sprintf("S3 bucket scan started for %s", bucket))
}

// ── GitHub repo ───────────────────────────────────────────────────────────────

func scanGitHub(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Repo, "Repository") { return }
	repo := *req.Repo
	scanID := generateScanID()
	go runScanInProcess(scanID, "github", repo, func() error {
		_, err := githubmod.Run(githubmod.Options{Repo: repo})
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("GitHub scan started for %s", repo))
}

// ── GitHub org ────────────────────────────────────────────────────────────────

func scanGitHubOrg(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	var org string
	if req.Domain != nil && *req.Domain != "" {
		org = *req.Domain
	} else if req.Repo != nil {
		org = *req.Repo
	}
	if org == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Organization name is required (use 'domain' field)"})
		return
	}
	scanID := generateScanID()
	go runScanInProcess(scanID, "github_org", org, func() error {
		_, err := githubmod.Run(githubmod.Options{Org: org})
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("GitHub organization scan started for %s", org))
}

// ── Lite workflow ─────────────────────────────────────────────────────────────

func scanLite(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Domain, "Domain") { return }
	domain := *req.Domain
	opts := litemod.Options{
		Domain:  domain,
		Timeouts: make(map[string]int),
	}
	if req.SkipJS != nil { opts.SkipJS = *req.SkipJS }
	if req.PhaseTimeout != nil && *req.PhaseTimeout > 0 { opts.PhaseTimeoutDefault = *req.PhaseTimeout }
	if req.TimeoutLivehosts != nil { opts.Timeouts["livehosts"] = *req.TimeoutLivehosts }
	if req.TimeoutReflection != nil { opts.Timeouts["reflection"] = *req.TimeoutReflection }
	if req.TimeoutJS != nil { opts.Timeouts["js"] = *req.TimeoutJS }
	if req.TimeoutNuclei != nil { opts.Timeouts["nuclei"] = *req.TimeoutNuclei }
	msg := fmt.Sprintf("Lite scan started for %s", domain)
	if opts.SkipJS { msg += " (JavaScript scanning skipped)" }
	scanID := generateScanID()
	go runScanInProcess(scanID, "lite", domain, func() error {
		_, err := litemod.RunLite(opts)
		return err
	})
	okStarted(c, scanID, msg)
}

// ── Keyhack ───────────────────────────────────────────────────────────────────
// Keyhack uses an external binary; delegated to executeScan.

func keyhackSearch(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Query, "Search query") { return }
	query := *req.Query
	scanID := generateScanID()
	cmd := []string{getAutoarScriptPath(), "keyhack", "search", query}
	go executeScan(scanID, cmd, "keyhack_search")
	okStarted(c, scanID, fmt.Sprintf("Searching for templates matching: %s", query))
}

func keyhackValidate(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) { return }
	if !requireField(c, req.Provider, "Provider name") { return }
	if !requireField(c, req.APIKey, "API key") { return }
	scanID := generateScanID()
	cmd := []string{getAutoarScriptPath(), "keyhack", "validate", *req.Provider, *req.APIKey}
	go executeScan(scanID, cmd, "keyhack_validate")
	okStarted(c, scanID, fmt.Sprintf("Generating validation command for %s", *req.Provider))
}

// execCommand is a local alias so tests and future refactors can swap it out.
var execCommand = exec.Command
