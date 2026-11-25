package api

// scan_handlers.go — HTTP handlers for every scan type.
//
// All handlers call their module's Go API directly via runScanInProcess
// instead of spawning a child "autoar ..." subprocess. This eliminates the
// double-memory fork that was causing Docker OOM container restarts.

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/db"
	asrmod "github.com/h0tak88r/AutoAR/internal/scanner/asr"
	backupmod "github.com/h0tak88r/AutoAR/internal/scanner/backup"
	cf1016mod "github.com/h0tak88r/AutoAR/internal/scanner/cf1016"
	cnamesmod "github.com/h0tak88r/AutoAR/internal/scanner/cnames"
	dnsmod "github.com/h0tak88r/AutoAR/internal/scanner/dns"
	domainmod "github.com/h0tak88r/AutoAR/internal/scanner/domain"
	ffufmod "github.com/h0tak88r/AutoAR/internal/scanner/ffuf"
	firebasemod "github.com/h0tak88r/AutoAR/internal/scanner/firebase"
	gfmod "github.com/h0tak88r/AutoAR/internal/scanner/gf"
	githubmod "github.com/h0tak88r/AutoAR/internal/scanner/githubscan"
	jsendpointsmod "github.com/h0tak88r/AutoAR/internal/scanner/jsendpoints"
	jsscanmod "github.com/h0tak88r/AutoAR/internal/scanner/jsscan"
	livehostsmod "github.com/h0tak88r/AutoAR/internal/scanner/livehosts"
	"github.com/h0tak88r/AutoAR/internal/scanner/mcpdiscovery"
	misconfigmod "github.com/h0tak88r/AutoAR/internal/scanner/misconfig"
	nucleimod "github.com/h0tak88r/AutoAR/internal/scanner/nuclei"
	portsmod "github.com/h0tak88r/AutoAR/internal/scanner/ports"
	reconmod "github.com/h0tak88r/AutoAR/internal/scanner/recon"
	reflectionmod "github.com/h0tak88r/AutoAR/internal/scanner/reflection"
	s3mod "github.com/h0tak88r/AutoAR/internal/scanner/s3"
	"github.com/h0tak88r/AutoAR/internal/scanner/scope"
	subdomainmod "github.com/h0tak88r/AutoAR/internal/scanner/subdomain"
	subdomainsmod "github.com/h0tak88r/AutoAR/internal/scanner/subdomains"
	techmod "github.com/h0tak88r/AutoAR/internal/scanner/tech"
	urlsmod "github.com/h0tak88r/AutoAR/internal/scanner/urls"
	zerodaysmod "github.com/h0tak88r/AutoAR/internal/scanner/zerodays"
	"github.com/h0tak88r/AutoAR/internal/utils"
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

// maxScanTargetLen bounds a scan target (hosts, URLs, owner/repo, buckets).
const maxScanTargetLen = 2048

// validateScanTarget rejects targets that could escape the results tree once a
// scanner or the artifact indexer joins them into a filesystem path — parent-dir
// references, backslashes, NUL/control characters, whitespace and absolute
// paths. A {"domain":"../../../../app"} subdomain scan used to make the indexer
// copy /app/.env and DB dumps into the (viewer-readable, R2-uploaded) scan dir.
// Legit targets — hosts, URLs, owner/repo, bucket names — never need these.
func validateScanTarget(target string) error {
	t := target // not trimmed: handlers pass the raw value on to the scanners
	switch {
	case strings.TrimSpace(t) == "":
		return fmt.Errorf("target is empty")
	case len(t) > maxScanTargetLen:
		return fmt.Errorf("target is longer than %d characters", maxScanTargetLen)
	case strings.Contains(t, ".."):
		return fmt.Errorf("target must not contain \"..\"")
	case strings.HasPrefix(t, "/"):
		return fmt.Errorf("target must not be an absolute path")
	case strings.ContainsRune(t, '\\'):
		return fmt.Errorf("target must not contain backslashes")
	}
	for _, r := range t {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("target must not contain whitespace or control characters")
		}
	}
	return nil
}

// badTarget writes a 400 and returns true when any of targets is invalid.
func badTarget(c *gin.Context, targets ...string) bool {
	for _, t := range targets {
		if err := validateScanTarget(t); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid target: " + err.Error()})
			return true
		}
	}
	return false
}

// inprocessCommand renders the stored command of an in-process scan. opts are
// replayable scan options as "key=value" tokens (see boolOpt), appended after
// the target so Resume/Rescan restore them instead of silently dropping them
// (a skip_ffuf domain run used to run FFuf on resume). Targets are validated
// whitespace-free, so the tokens round-trip through strings.Fields.
func inprocessCommand(scanType, target string, opts ...string) string {
	cmd := fmt.Sprintf("inprocess:%s target=%s", scanType, target)
	for _, o := range opts {
		if o != "" {
			cmd += " " + o
		}
	}
	return cmd
}

// boolOpt returns the stored-command token for a boolean option ("" when off).
func boolOpt(key string, on bool) string {
	if !on {
		return ""
	}
	return key + "=true"
}

// commandFlag reports whether a stored in-process command carries key=true.
func commandFlag(command, key string) bool {
	for _, f := range strings.Fields(command) {
		if f == key+"=true" {
			return true
		}
	}
	return false
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
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Domain, "Domain") {
		return
	}
	domain := *req.Domain
	if badTarget(c, domain) {
		return
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "subdomains", domain, func() error {
		_, err := subdomainsmod.EnumerateSubdomains(domain, 0)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Subdomain enumeration started for %s", domain))
}

// ── Domain workflow ───────────────────────────────────────────────────────────

func scanDomainRun(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Domain, "Domain") {
		return
	}
	domain := *req.Domain
	if badTarget(c, domain) {
		return
	}
	skipFFuf := req.SkipFFuf != nil && *req.SkipFFuf
	scanID := generateScanID(c)
	cmd := inprocessCommand("domain_run", domain, boolOpt("skip_ffuf", skipFFuf))
	go RunScanInProcessWithCommand(scanID, "domain_run", domain, cmd, func() error {
		_, err := domainmod.RunDomain(domainmod.ScanOptions{Domain: domain, SkipFFuf: skipFFuf})
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Domain workflow scan started for %s", domain))
}

// ── Subdomain workflow ────────────────────────────────────────────────────────

func scanSubdomainRun(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Subdomain, "Subdomain") {
		return
	}
	sub := *req.Subdomain
	if badTarget(c, sub) {
		return
	}
	skipFFuf := req.SkipFFuf != nil && *req.SkipFFuf
	scanID := generateScanID(c)
	cmd := inprocessCommand("subdomain_run", sub, boolOpt("skip_ffuf", skipFFuf))
	go RunScanInProcessWithCommand(scanID, "subdomain_run", sub, cmd, func() error {
		_, err := subdomainmod.RunSubdomainWithOptions(sub, subdomainmod.RunOptions{SkipFFuf: skipFFuf})
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Subdomain workflow scan started for %s", sub))
}

// ── Live hosts ────────────────────────────────────────────────────────────────

func scanLivehosts(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Domain, "Domain") {
		return
	}
	domain := *req.Domain
	if badTarget(c, domain) {
		return
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "livehosts", domain, func() error {
		_, err := livehostsmod.FilterLiveHosts(domain, 0, false)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Live hosts discovery started for %s", domain))
}

// ── CNAMEs ────────────────────────────────────────────────────────────────────

func scanCnames(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Domain, "Domain") {
		return
	}
	domain := *req.Domain
	if badTarget(c, domain) {
		return
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "cnames", domain, func() error {
		_, err := cnamesmod.CollectCNAMEs(domain)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("CNAME enumeration started for %s", domain))
}

// ── URLs ──────────────────────────────────────────────────────────────────────

func scanURLs(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Domain, "Domain") {
		return
	}
	domain := *req.Domain
	if badTarget(c, domain) {
		return
	}
	skipEnum := req.SkipSubdomainEnum != nil && *req.SkipSubdomainEnum
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "urls", domain, func() error {
		_, err := urlsmod.CollectURLs(domain, 0, skipEnum)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("URL collection started for %s", domain))
}

// ── Client-side scan (formerly "JS scan") ─────────────────────────────────────

// scanJS serves POST /scan/clientside and its old name /scan/js: collect the
// JavaScript of a domain (every subdomain) or of one host (that app only),
// then run the JS secrets and client-side sink patterns over it in one pass.
// The scan type stays "js" so earlier scans, filters and phase keys still
// line up.
func scanJS(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Domain, "Domain") {
		return
	}
	domain := *req.Domain
	sub := ""
	if req.Subdomain != nil {
		sub = *req.Subdomain
	}
	if badTarget(c, domain) || (sub != "" && badTarget(c, sub)) {
		return
	}
	sub = clientSideHostMode(domain, sub)
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "js", domain, func() error {
		_, err := jsscanmod.Run(jsscanmod.Options{Domain: domain, Subdomain: sub})
		return err
	})
	what := "all subdomains of " + domain
	if sub != "" {
		what = sub + " only"
	}
	okStarted(c, scanID, fmt.Sprintf("Client-side scan started (JS secrets + client-side sinks) for %s", what))
}

// clientSideHostMode returns the subdomain a client-side scan is limited to:
// the given one, or the target itself when it is a host rather than a
// registrable domain (api.acme.com → that host's JS, not its sub-subdomains).
func clientSideHostMode(domain, sub string) string {
	if sub != "" {
		return sub
	}
	host := strings.ToLower(strings.TrimSpace(domain))
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	if i := strings.IndexAny(host, "/:"); i >= 0 {
		host = host[:i]
	}
	if reg, ok := scope.RegistrableDomain(host); ok && reg != host {
		return domain
	}
	return ""
}

// ── Reflection ────────────────────────────────────────────────────────────────

func scanReflection(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Domain, "Domain") {
		return
	}
	domain := *req.Domain
	if badTarget(c, domain) {
		return
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "reflection", domain, func() error {
		_, err := reflectionmod.ScanReflection(domain)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Reflection scan started for %s", domain))
}

// ── Nuclei ────────────────────────────────────────────────────────────────────

func scanNuclei(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
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
	if badTarget(c, target) {
		return
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, fmt.Sprintf("nuclei-%s", mode), target, func() error {
		_, err := nucleimod.RunNuclei(opts)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Nuclei %s scan started for %s", mode, target))
}

// ── Recon ─────────────────────────────────────────────────────────────────────

func scanRecon(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Domain, "Domain") {
		return
	}
	domain := *req.Domain
	if badTarget(c, domain) {
		return
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "recon", domain, func() error {
		_, err := reconmod.RunFullRecon(domain, 0)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Unified asset discovery started for %s", domain))
}

// ── Tech detect ───────────────────────────────────────────────────────────────

func scanTech(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Domain, "Domain") {
		return
	}
	domain := *req.Domain
	if badTarget(c, domain) {
		return
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "tech", domain, func() error {
		_, err := techmod.DetectTech(domain, 0)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Technology detection started for %s", domain))
}

// ── Ports ─────────────────────────────────────────────────────────────────────

func scanPorts(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Domain, "Domain") {
		return
	}
	domain := *req.Domain
	if badTarget(c, domain) {
		return
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "ports", domain, func() error {
		_, err := portsmod.ScanPorts(domain, 0)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Port scan started for %s", domain))
}

// ── GF patterns ───────────────────────────────────────────────────────────────

func scanGF(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Domain, "Domain") {
		return
	}
	domain := *req.Domain
	if badTarget(c, domain) {
		return
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "gf", domain, func() error {
		_, err := gfmod.ScanGF(domain)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("GF pattern scan started for %s", domain))
}

// ── DNS takeover (legacy endpoint) ────────────────────────────────────────────

func scanDNSTakeover(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Domain, "Domain") {
		return
	}
	domain := *req.Domain
	if badTarget(c, domain) {
		return
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "dns-takeover", domain, func() error {
		return dnsmod.Takeover(domain)
	})
	okStarted(c, scanID, fmt.Sprintf("DNS takeover scan started for %s", domain))
}

// ── DNS unified ───────────────────────────────────────────────────────────────

func scanDNS(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Domain, "Domain") {
		return
	}
	domain := *req.Domain
	if badTarget(c, domain) {
		return
	}
	dnsType := "takeover"
	if req.DNSType != nil && *req.DNSType != "" {
		dnsType = *req.DNSType
		if dnsType != "takeover" && dnsType != "dangling-ip" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "dns_type must be 'takeover' or 'dangling-ip'"})
			return
		}
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, fmt.Sprintf("dns-%s", dnsType), domain, func() error {
		if dnsType == "dangling-ip" {
			return dnsmod.DanglingIP(domain)
		}
		return dnsmod.Takeover(domain)
	})
	okStarted(c, scanID, fmt.Sprintf("DNS %s scan started for %s", dnsType, domain))
}

// ── DNS CF1016 ────────────────────────────────────────────────────────────────

func scanMCPDiscovery(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	target := ""
	if req.Domain != nil && *req.Domain != "" {
		target = *req.Domain
	} else if req.Subdomain != nil && *req.Subdomain != "" {
		target = *req.Subdomain
	}
	if target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain or subdomain is required"})
		return
	}
	if badTarget(c, target) {
		return
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "mcp-discovery", target, func() error {
		_, err := mcpdiscovery.Run(mcpdiscovery.Options{Target: target, Threads: 15})
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("MCP discovery scan started for %s", target))
}

func scanDNSCF1016(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
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
	if badTarget(c, target) {
		return
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "dns_cf1016", target, func() error {
		// Determine if target is a single subdomain (has >2 parts) or a root domain.
		// For a single host we pass it directly as SubdomainsFile so CF1016 doesn't
		// try to enumerate subdomains of it.
		clean := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
		parts := strings.Split(clean, ".")
		if len(parts) > 2 {
			// Single subdomain — write to a temp file and scan only that host.
			tmp, err := os.CreateTemp("", "autoar-cf1016-*.txt")
			if err != nil {
				return fmt.Errorf("cf1016: failed to create temp file: %w", err)
			}
			tmpPath := tmp.Name()
			defer os.Remove(tmpPath)
			if _, err := fmt.Fprintln(tmp, clean); err != nil {
				tmp.Close()
				return err
			}
			tmp.Close()
			// Root domain for DB lookups (last two parts)
			rootDomain := strings.Join(parts[len(parts)-2:], ".")
			_, err = cf1016mod.Run(cf1016mod.Options{
				Domain:         rootDomain,
				SubdomainsFile: tmpPath,
				Threads:        100,
				Timeout:        10 * time.Second,
				OutputDir:      filepath.Join("new-results", clean, "vulnerabilities", "dns-takeover"),
			})
			return err
		}
		// Root domain — enumerate subdomains then scan all.
		_, err := cf1016mod.Run(cf1016mod.Options{
			Domain:    clean,
			Threads:   100,
			Timeout:   10 * time.Second,
			OutputDir: filepath.Join("new-results", clean, "vulnerabilities", "dns-takeover"),
		})
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Cloudflare 1016 dangling DNS scan started for %s", target))
}

// ── Firebase ────────────────────────────────────────────────────────────────
func scanFirebase(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
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
	if badTarget(c, target) {
		return
	}
	aggressive := req.Aggressive != nil && *req.Aggressive
	scanID := generateScanID(c)
	cmd := inprocessCommand("firebase", target, boolOpt("aggressive", aggressive))
	go RunScanInProcessWithCommand(scanID, "firebase", target, cmd, func() error {
		return runFirebaseScan(target, aggressive)
	})
	msg := "Firebase exposure scan started for " + target
	if aggressive {
		msg += " (aggressive: write tests enabled)"
	}
	okStarted(c, scanID, msg)
}

// runFirebaseScan runs the Firebase exposure scan for target (shared by the
// handler and rescan so a replay keeps the original aggressive setting).
func runFirebaseScan(target string, aggressive bool) error {
	clean := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	parts := strings.Split(clean, ".")
	if len(parts) > 2 {
		// Single host — scan only this host (don't enumerate subdomains of it).
		tmp, err := os.CreateTemp("", "autoar-firebase-*.txt")
		if err != nil {
			return fmt.Errorf("firebase: failed to create temp file: %w", err)
		}
		defer os.Remove(tmp.Name())
		if _, err := fmt.Fprintln(tmp, clean); err != nil {
			tmp.Close()
			return err
		}
		tmp.Close()
		rootDomain := strings.Join(parts[len(parts)-2:], ".")
		_, err = firebasemod.Run(firebasemod.Options{Domain: rootDomain, LiveHostsFile: tmp.Name(), Threads: 20, Timeout: 15 * time.Second, Aggressive: aggressive})
		return err
	}
	// Root domain — scan its stored/live hosts.
	_, err := firebasemod.Run(firebasemod.Options{Domain: clean, Threads: 20, Timeout: 15 * time.Second, Aggressive: aggressive})
	return err
}

// ── FFuf ──────────────────────────────────────────────────────────────────────

func scanFFuf(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Target, "target URL") {
		return
	}
	target := *req.Target
	if badTarget(c, target) {
		return
	}
	opts := ffufmod.Options{Target: target}
	if req.Wordlist != nil {
		opts.Wordlist = *req.Wordlist
	}
	if req.Threads != nil && *req.Threads > 0 {
		opts.Threads = *req.Threads
	}
	if req.Recursion != nil {
		opts.Recursion = *req.Recursion
	}
	if req.RecursionDepth != nil {
		opts.RecursionDepth = *req.RecursionDepth
	}
	if req.Bypass403 != nil {
		opts.Bypass403 = *req.Bypass403
	}
	if req.Extensions != nil {
		opts.Extensions = *req.Extensions
	}
	if req.CustomHeaders != nil {
		opts.CustomHeaders = *req.CustomHeaders
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "ffuf", target, func() error {
		_, err := ffufmod.RunFFuf(opts)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("FFuf fuzzing started for %s", target))
}

// ── Backup ────────────────────────────────────────────────────────────────────

func scanBackup(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Domain, "Domain") {
		return
	}
	domain := *req.Domain
	if badTarget(c, domain) {
		return
	}
	opts := backupmod.Options{Domain: domain}
	if req.Threads != nil && *req.Threads > 0 {
		opts.Threads = *req.Threads
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "backup", domain, func() error {
		_, err := backupmod.Run(opts)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Backup file discovery started for %s", domain))
}

// ── Misconfig ─────────────────────────────────────────────────────────────────

func scanMisconfig(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Domain, "Domain") {
		return
	}
	domain := *req.Domain
	if badTarget(c, domain) {
		return
	}
	opts := misconfigmod.Options{
		Target: domain,
		Action: "scan",
	}
	if req.ServiceID != nil {
		opts.ServiceID = *req.ServiceID
	}
	if req.Delay != nil && *req.Delay > 0 {
		opts.Delay = *req.Delay
	}
	if req.Permutations != nil {
		opts.EnablePerms = *req.Permutations
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "misconfig", domain, func() error {
		return misconfigmod.Run(opts)
	})
	okStarted(c, scanID, fmt.Sprintf("Misconfiguration scan started for %s", domain))
}

// ── Zerodays ──────────────────────────────────────────────────────────────────

func scanZerodays(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
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
		if badTarget(c, target) {
			return
		}
	} else {
		target = *req.DomainsFile
		opts.DomainsFile = target
	}
	if req.Threads != nil && *req.Threads > 0 {
		opts.Threads = *req.Threads
	}
	if req.DOSTest != nil {
		opts.DOSTest = *req.DOSTest
	}
	if req.EnableSourceExposure != nil {
		opts.EnableSourceExposure = *req.EnableSourceExposure
	}
	if req.CVEs != nil {
		opts.CVEs = *req.CVEs
	}
	if req.WP2ShellConfirmSQLi != nil {
		opts.WP2ShellConfirmSQLi = *req.WP2ShellConfirmSQLi
	}
	if req.MongoDBHost != nil {
		opts.MongoDBHost = *req.MongoDBHost
	}
	if req.MongoDBPort != nil {
		opts.MongoDBPort = *req.MongoDBPort
	}
	if req.Silent != nil {
		opts.Silent = *req.Silent
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "zerodays", target, func() error {
		_, err := zerodaysmod.Run(opts)
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("Zerodays scan started for %s", target))
}

// ── ASR ───────────────────────────────────────────────────────────────────────

func scanASR(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Domain, "Domain") {
		return
	}
	domain := *req.Domain
	if badTarget(c, domain) {
		return
	}
	opts := asrmod.Options{Domain: domain}

	if req.Mode != nil && *req.Mode != "" {
		m, err := strconv.Atoi(*req.Mode)
		if err == nil && m >= 1 && m <= 5 {
			opts.Mode = m
		} else {
			opts.Mode = 5
		}
	} else {
		opts.Mode = 5 // default to deep mode
	}

	if req.Threads != nil && *req.Threads > 0 {
		opts.Threads = *req.Threads
	}
	if req.Resolvers != nil && *req.Resolvers != "" {
		opts.Resolvers = *req.Resolvers
	}

	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "asr", domain, func() error {
		return asrmod.Run(context.Background(), opts)
	})
	okStarted(c, scanID, fmt.Sprintf("ASR scan started for %s", domain))
}

// ── S3 ────────────────────────────────────────────────────────────────────────

func scanS3(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	// Accept either a specific bucket or a domain for enum+scan
	if req.Domain != nil && *req.Domain != "" {
		domain := *req.Domain
		if badTarget(c, domain) {
			return
		}
		opts := s3mod.Options{Root: domain, Action: "domain"}
		if req.Region != nil {
			opts.Region = *req.Region
		}
		if req.Threads != nil && *req.Threads > 0 {
			opts.Threads = *req.Threads
		}
		scanID := generateScanID(c)
		go RunScanInProcess(scanID, "s3", domain, func() error {
			return s3mod.Run(opts)
		})
		okStarted(c, scanID, fmt.Sprintf("S3 domain scan started for %s (enum + scan)", domain))
		return
	}
	if !requireField(c, req.Bucket, "Bucket name") {
		return
	}
	bucket := *req.Bucket
	if badTarget(c, bucket) {
		return
	}
	opts := s3mod.Options{Bucket: bucket}
	if req.Region != nil {
		opts.Region = *req.Region
	}
	// Accept a full S3 URL (e.g. bucket.s3.ap-south-1.amazonaws.com) in the bucket
	// field: use the clean bucket name for the scan record/title and adopt an embedded
	// region when none was supplied. handleScan re-parses + auto-detects too.
	if b, r := s3mod.ParseBucketInput(bucket); b != "" {
		bucket = b
		opts.Bucket = b
		if opts.Region == "" && r != "" {
			opts.Region = r
		}
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "s3", bucket, func() error {
		return s3mod.Run(opts)
	})
	okStarted(c, scanID, fmt.Sprintf("S3 bucket scan started for %s", bucket))
}

// ── JS Endpoint Extractor ─────────────────────────────────────────────────────

func scanJSEndpoints(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	var domain string
	if req.Domain != nil && *req.Domain != "" {
		domain = *req.Domain
	} else if req.Subdomain != nil && *req.Subdomain != "" {
		domain = *req.Subdomain
	}
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain or subdomain required"})
		return
	}
	if badTarget(c, domain) {
		return
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "js-endpoints", domain, func() error {
		_, err := jsendpointsmod.Run(jsendpointsmod.Options{Domain: domain, Threads: 30})
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("JS endpoint extraction started for %s", domain))
}

// ── GitHub repo ───────────────────────────────────────────────────────────────

func scanGitHub(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Repo, "Repository") {
		return
	}
	repo := *req.Repo
	if badTarget(c, repo) {
		return
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "github", repo, func() error {
		_, err := githubmod.Run(githubmod.Options{Mode: githubmod.ModeRepo, Repo: repo})
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("GitHub scan started for %s", repo))
}

// ── GitHub org ────────────────────────────────────────────────────────────────

func scanGitHubOrg(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
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
	if badTarget(c, org) {
		return
	}
	scanID := generateScanID(c)
	go RunScanInProcess(scanID, "github_org", org, func() error {
		_, err := githubmod.Run(githubmod.Options{Mode: githubmod.ModeOrg, Org: org})
		return err
	})
	okStarted(c, scanID, fmt.Sprintf("GitHub organization scan started for %s", org))
}

// ── Keyhack ───────────────────────────────────────────────────────────────────
// Keyhack uses an external binary; delegated to executeScan.

func keyhackSearch(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Query, "Search query") {
		return
	}
	query := *req.Query
	scanID := generateScanID(c)
	cmd := []string{utils.GetAutoarScriptPath(), "keyhack", "search", query}
	go executeScan(scanID, cmd, "keyhack_search")
	okStarted(c, scanID, fmt.Sprintf("Searching for templates matching: %s", query))
}

func keyhackValidate(c *gin.Context) {
	var req ScanRequest
	if !bindOrBad(c, &req) {
		return
	}
	if !requireField(c, req.Provider, "Provider name") {
		return
	}
	if !requireField(c, req.APIKey, "API key") {
		return
	}
	scanID := generateScanID(c)
	cmd := []string{utils.GetAutoarScriptPath(), "keyhack", "validate", *req.Provider, *req.APIKey}
	go executeScan(scanID, cmd, "keyhack_validate")
	okStarted(c, scanID, fmt.Sprintf("Generating validation command for %s", *req.Provider))
}

// apiResumeScanFromCheckpoint resumes a failed/timed_out/cancelled workflow scan
// from its last completed phase, reusing the SAME scan id so already-completed
// phases are skipped via db.IsPhaseCompleted (see utils.RunWorkflowPhase). Only
// the phase-checkpointed workflows (domain_run, subdomain_run) support this;
// recon/pipeline have no per-phase checkpoints and must be rescanned from scratch.
// POST /api/scans/:id/resume-run
func apiResumeScanFromCheckpoint(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan id required"})
		return
	}
	if ScanIsActiveInMemory(id) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan is still active"})
		return
	}
	rec, err := db.GetScan(id)
	if err != nil || rec == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}
	switch strings.ToLower(rec.Status) {
	case "failed", "timed_out", "cancelled", "stopped":
		// resumable
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "only failed / timed-out / cancelled scans can be resumed"})
		return
	}
	scanType := strings.ToLower(strings.TrimSpace(rec.ScanType))
	target := rec.Target
	// Replays the options the scan was started with (stored in its command).
	fn := checkpointResumeFunc(scanType, target, rec.Command)
	if fn == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "resume is only supported for domain_run and subdomain_run (recon/pipeline restart from scratch — use Rescan)"})
		return
	}
	command := strings.TrimSpace(rec.Command)
	if command == "" {
		command = inprocessCommand(scanType, target)
	}
	if err := startResumeScan(id, scanType, target, command+" (resumed)", currentUsername(c), fn); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "this scan already has a run queued or still stopping — wait for it to finish, then resume"})
		return
	}
	okStarted(c, id, fmt.Sprintf("Resuming %s for %s from the last completed phase", scanType, target))
}

// execCommand is a local alias so tests and future refactors can swap it out.
var execCommand = exec.Command

// runInProcessRescan re-runs an in-process scan (domain_run, subdomain_run, …)
// using the correct Go module. command is the scan's stored Command string —
// some scan types (nuclei) need extra parameters from it to replay. Returns the
// new scan ID and true if the scan type is handled; returns "", false if the
// scan type is not supported.
func runInProcessRescan(scanType, target, command, createdBy string) (newScanID string, ok bool) {
	newScanID = generateScanID(nil)
	recordScanInitiator(newScanID, createdBy)
	st := strings.ToLower(strings.TrimSpace(scanType))
	// Options recorded in the stored command are replayed, not dropped.
	skipFFuf := commandFlag(command, "skip_ffuf")
	switch st {
	case "domain_run":
		cmd := inprocessCommand(scanType, target, boolOpt("skip_ffuf", skipFFuf))
		go RunScanInProcessWithCommand(newScanID, scanType, target, cmd, func() error {
			_, err := domainmod.RunDomain(domainmod.ScanOptions{Domain: target, SkipFFuf: skipFFuf})
			return err
		})
		return newScanID, true
	case "subdomain_run":
		cmd := inprocessCommand(scanType, target, boolOpt("skip_ffuf", skipFFuf))
		go RunScanInProcessWithCommand(newScanID, scanType, target, cmd, func() error {
			_, err := subdomainmod.RunSubdomainWithOptions(target, subdomainmod.RunOptions{SkipFFuf: skipFFuf})
			return err
		})
		return newScanID, true
	case "mcp-discovery":
		go RunScanInProcess(newScanID, "mcp-discovery", target, func() error {
			_, err := mcpdiscovery.Run(mcpdiscovery.Options{Target: target, Threads: 15})
			return err
		})
		return newScanID, true
	case "dns_cf1016", "dns-cf1016":
		go RunScanInProcess(newScanID, "dns_cf1016", target, func() error {
			clean := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
			parts := strings.Split(clean, ".")
			if len(parts) > 2 {
				// Single subdomain — write to a temp file and scan only that host.
				tmp, err := os.CreateTemp("", "autoar-cf1016-*.txt")
				if err != nil {
					return fmt.Errorf("cf1016 rescan: failed to create temp file: %w", err)
				}
				tmpPath := tmp.Name()
				defer os.Remove(tmpPath)
				if _, err := fmt.Fprintln(tmp, clean); err != nil {
					tmp.Close()
					return err
				}
				tmp.Close()
				rootDomain := strings.Join(parts[len(parts)-2:], ".")
				_, err = cf1016mod.Run(cf1016mod.Options{
					Domain:         rootDomain,
					SubdomainsFile: tmpPath,
					Threads:        100,
					Timeout:        10 * time.Second,
					OutputDir:      filepath.Join("new-results", clean, "vulnerabilities", "dns-takeover"),
				})
				return err
			}
			// Root domain — enumerate subdomains then scan all.
			_, err := cf1016mod.Run(cf1016mod.Options{
				Domain:    clean,
				Threads:   100,
				Timeout:   10 * time.Second,
				OutputDir: filepath.Join("new-results", clean, "vulnerabilities", "dns-takeover"),
			})
			return err
		})
		return newScanID, true
	case "firebase":
		aggressive := commandFlag(command, "aggressive")
		cmd := inprocessCommand("firebase", target, boolOpt("aggressive", aggressive))
		go RunScanInProcessWithCommand(newScanID, "firebase", target, cmd, func() error {
			return runFirebaseScan(target, aggressive)
		})
		return newScanID, true
	case "nuclei":
		// Only plain global runs replay faithfully: a race pass targeted a capped,
		// fingerprinted host list that is not stored, so runGlobalNucleiScan would
		// turn it into a ~24h sweep of every live host (apiRescan explains why).
		if isRacePassTarget(target) {
			log.Printf("[rescan] nuclei race-pass scan cannot be replayed (host list not stored)")
			return "", false
		}
		// The template was stored in the command ("inprocess:nuclei target=…
		// template=…") when the scan started; without it there is nothing to replay.
		template := ""
		if idx := strings.Index(command, " template="); idx >= 0 {
			template = strings.TrimSpace(command[idx+len(" template="):])
		}
		if template == "" {
			log.Printf("[rescan] nuclei scan %s has no template in its stored command — cannot rescan", target)
			return "", false
		}
		// Absolute paths are the per-scan persisted raw-YAML templates; if the file
		// is gone the scan is not replayable. Relative values are nuclei template
		// IDs/paths resolved by nuclei itself, so they pass through unchecked.
		if filepath.IsAbs(template) {
			if _, err := os.Stat(template); err != nil {
				log.Printf("[rescan] nuclei template file %s no longer exists: %v", template, err)
				return "", false
			}
		}
		go RunScanInProcessWithCommand(newScanID, "nuclei", target, command, func() error {
			return runGlobalNucleiScan(newScanID, template)
		})
		return newScanID, true
	}
	return "", false
}

// isRacePassTarget reports whether a nuclei scan target is the race-pass label
// (see race_pass.go): those runs hit a capped, fingerprinted host list.
func isRacePassTarget(target string) bool {
	return strings.EqualFold(strings.TrimSpace(target), "race-pass")
}

// rescanRefusalReason explains why a scan can't be faithfully replayed by
// /api/scans/:id/rescan, or returns "" when a rescan may proceed.
func rescanRefusalReason(rec *db.ScanRecord) string {
	if rec == nil {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(rec.ScanType)) {
	case "nuclei":
		if isRacePassTarget(rec.Target) {
			return "race-pass scans ran against a capped list of fingerprinted hosts that isn't stored — a rescan would sweep every live host for up to 24h instead; run the template from the Scans page if that is what you want"
		}
		if strings.Contains(rec.Command, "targeted=true") {
			return "fingerprint-targeted runs matched hosts at launch time (not stored) — re-run the template with targeted on from the Scans page instead of rescanning"
		}
	case "keyhack_validate":
		// storedCommand redacts the API key (last argv) as "***" — replaying it
		// would "validate" the literal placeholder.
		if f := strings.Fields(rec.Command); len(f) > 0 && f[len(f)-1] == "***" {
			return "this keyhack validation's API key was redacted when it was stored — start a new validation instead"
		}
	}
	return ""
}
