package api

// MCP run_scan types. Besides the three sweep launchers (discover, ports,
// nuclei), every per-target module rides the dashboard's own /scan/* handler,
// invoked in-process as the "mcp" actor, so an MCP launch gets exactly the
// validation (badTarget, required fields) and tracking a dashboard launch gets.
//
// Only safe options pass through. Deliberately NOT exposed: domains_file and
// ffuf wordlist (server file paths), zerodays dos_test / wp2shell SQLi confirm /
// mongodb_host (DoS, intrusive, arbitrary host), firebase aggressive (write
// tests), custom resolvers and headers.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

// mcpScanActor is the initiator recorded for scans the MCP launches.
const mcpScanActor = "mcp"

type mcpScanType struct {
	handler gin.HandlerFunc
	field   string         // ScanRequest key the target goes in; "url|domain" picks by scheme
	fixed   map[string]any // constant request fields (dns_type, …)
	opts    []string       // run_scan args passed through: skip_ffuf, mode, cves, region
	takes   string         // what the target is (default "domain")
	help    string         // what the scan does, for the tool description
}

// mcpSweepTypes are launched by their own launchers (see mcpLaunchScan).
var mcpSweepTypes = map[string]string{
	"discover":  "root domain: subdomains, live hosts, tech",
	"ports":     "root domain, or blank for the whole live corpus",
	"nuclei":    "template on hosts=<product,…> fingerprint matches (minutes), or on every live host (needs template)",
	"php2shell": "root domain, or blank for the whole live corpus — CVE-2026-109618/109619 PHP version+presence+primitive scan. Args: php_only=true (only hosts fingerprinted as PHP — the fast path), workers=N (default 60, max 300)",
}

var mcpScanTypes = map[string]mcpScanType{
	"domain_run":      {handler: scanDomainRun, field: "domain", opts: []string{"skip_ffuf"}, help: "full domain workflow"},
	"subdomain_run":   {handler: scanSubdomainRun, field: "subdomain", opts: []string{"skip_ffuf"}, takes: "host", help: "full workflow on one host"},
	"recon":           {handler: scanRecon, field: "domain", help: "asset discovery"},
	"subdomains":      {handler: scanSubdomains, field: "domain", help: "subdomain enumeration"},
	"livehosts":       {handler: scanLivehosts, field: "domain", help: "live host probe"},
	"cnames":          {handler: scanCnames, field: "domain", help: "CNAME records"},
	"tech":            {handler: scanTech, field: "domain", help: "tech detection"},
	"urls":            {handler: scanURLs, field: "domain", help: "URL collection"},
	"clientside":      {handler: scanJS, field: "domain", takes: "root domain (every subdomain) or one host (that app only)", help: "client-side scan — JS secrets + DOM XSS / postMessage / open-redirect / prototype-pollution sink candidates; read them with clientside_results"},
	"js":              {handler: scanJS, field: "domain", takes: "domain or host", help: "old name of clientside"},
	"js_endpoints":    {handler: scanJSEndpoints, field: "domain", help: "endpoints from JS"},
	"gf":              {handler: scanGF, field: "domain", help: "GF pattern candidates"},
	"reflection":      {handler: scanReflection, field: "domain", help: "reflected parameters"},
	"backup":          {handler: scanBackup, field: "domain", help: "backup file discovery"},
	"misconfig":       {handler: scanMisconfig, field: "domain", help: "cloud/SaaS misconfig"},
	"zerodays":        {handler: scanZerodays, field: "domain", opts: []string{"cves"}, help: "zero-day checks"},
	"asr":             {handler: scanASR, field: "domain", opts: []string{"mode"}, help: "attack-surface recon, mode 1-5"},
	"dns_takeover":    {handler: scanDNSTakeover, field: "domain", help: "subdomain takeover"},
	"dns_dangling_ip": {handler: scanDNS, field: "domain", fixed: map[string]any{"dns_type": "dangling-ip"}, help: "dangling A records"},
	"dns_cf1016":      {handler: scanDNSCF1016, field: "domain", help: "Cloudflare 1016 dangling DNS"},
	"firebase":        {handler: scanFirebase, field: "domain", help: "Firebase exposure, read-only"},
	"mcp_discovery":   {handler: scanMCPDiscovery, field: "domain", help: "exposed MCP servers"},
	"s3":              {handler: scanS3, field: "domain", opts: []string{"region"}, help: "S3 bucket enum + scan"},
	"s3_bucket":       {handler: scanS3, field: "bucket", opts: []string{"region"}, takes: "bucket name or S3 URL", help: "one bucket"},
	"github":          {handler: scanGitHub, field: "repo", takes: "owner/repo", help: "secrets in one repo"},
	"github_org":      {handler: scanGitHubOrg, field: "domain", takes: "GitHub org", help: "secrets across an org"},
	"ffuf":            {handler: scanFFuf, field: "target", takes: "URL", help: "content fuzzing"},
	"nuclei_target":   {handler: scanNuclei, field: "url|domain", opts: []string{"mode"}, takes: "domain or URL", help: "nuclei on one target, mode full|cves|panels|default-logins|vulnerabilities"},
}

func (t mcpScanType) target() string {
	if t.takes == "" {
		return "domain"
	}
	return t.takes
}

// mcpScanTypeNames lists every run_scan type, sweeps first.
func mcpScanTypeNames() []string {
	names := []string{"discover", "ports", "nuclei", "php2shell"}
	rest := make([]string, 0, len(mcpScanTypes))
	for k := range mcpScanTypes {
		rest = append(rest, k)
	}
	sort.Strings(rest)
	return append(names, rest...)
}

// mcpScanTypeHelp renders "type (target)" lines for the tool description.
func mcpScanTypeHelp() string {
	var b strings.Builder
	for _, n := range mcpScanTypeNames() {
		help := mcpSweepTypes[n]
		if t, ok := mcpScanTypes[n]; ok {
			help = t.target() + ": " + t.help
		}
		fmt.Fprintf(&b, "%s (%s); ", n, help)
	}
	return strings.TrimSuffix(b.String(), "; ")
}

// normalizeMCPScanType accepts the dashboard's route spellings too
// (dns-takeover, js-endpoints, mcp-discovery, …).
func normalizeMCPScanType(typ string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(typ)), "-", "_")
}

var (
	mcpRegionRe = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	mcpCVERe    = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,7}$`)
)

// mcpScanBody builds the /scan/* request body from run_scan arguments.
func mcpScanBody(t mcpScanType, target string, args map[string]any) (map[string]any, error) {
	body := map[string]any{}
	for k, v := range t.fixed {
		body[k] = v
	}
	field := t.field
	if field == "url|domain" {
		field = "domain"
		if l := strings.ToLower(target); strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") {
			field = "url"
		}
	}
	body[field] = target
	for _, k := range t.opts {
		v, ok := args[k]
		if !ok || v == nil {
			continue
		}
		switch k {
		case "skip_ffuf":
			b, ok := v.(bool)
			if !ok {
				return nil, fmt.Errorf("skip_ffuf must be true or false")
			}
			body[k] = b
		case "mode":
			switch m := v.(type) {
			case string:
				if m = strings.TrimSpace(m); m != "" {
					body[k] = m
				}
			case float64: // asr takes 1-5; JSON numbers arrive as float64
				body[k] = fmt.Sprintf("%d", int(m))
			default:
				return nil, fmt.Errorf("mode must be a string")
			}
		case "region":
			s, _ := v.(string)
			if s = strings.TrimSpace(s); s == "" {
				continue
			}
			if !mcpRegionRe.MatchString(s) {
				return nil, fmt.Errorf("region must look like us-east-1")
			}
			body[k] = s
		case "cves":
			list, ok := v.([]any)
			if !ok {
				return nil, fmt.Errorf("cves must be an array of CVE IDs")
			}
			if len(list) > 50 {
				return nil, fmt.Errorf("at most 50 cves")
			}
			cves := make([]string, 0, len(list))
			for _, x := range list {
				s, _ := x.(string)
				if s = strings.TrimSpace(s); !mcpCVERe.MatchString(s) {
					return nil, fmt.Errorf("invalid CVE ID %q", s)
				}
				cves = append(cves, strings.ToUpper(s))
			}
			if len(cves) > 0 {
				body[k] = cves
			}
		}
	}
	return body, nil
}

// mcpInvokeScan runs a /scan/* handler in-process as actor and returns the
// scan id it started, or the handler's error message.
func mcpInvokeScan(h gin.HandlerFunc, body map[string]any, actor string) (string, string, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return "", "", err
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/scan/mcp", bytes.NewReader(raw))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("auth_sub", actor)
	h(c)
	var resp struct {
		ScanID  string `json:"scan_id"`
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if w.Code != http.StatusOK || resp.ScanID == "" {
		if resp.Error == "" {
			resp.Error = fmt.Sprintf("scan was not started (HTTP %d)", w.Code)
		}
		return "", "", fmt.Errorf("%s", resp.Error)
	}
	return resp.ScanID, resp.Message, nil
}

// mcpLaunchTargeted is a seam over launchTargetedNuclei for tests.
var mcpLaunchTargeted = launchTargetedNuclei

// mcpLaunchScan starts a whitelisted run_scan type and returns its scan id.
func mcpLaunchScan(typ, target, template, name string, args map[string]any) (string, string, error) {
	return launchScanByType(mcpScanActor, typ, target, template, name, args)
}

// launchScanByType starts any run_scan type as actor (mcp, scope-autopilot …).
func launchScanByType(actor, typ, target, template, name string, args map[string]any) (string, string, error) {
	typ = normalizeMCPScanType(typ)
	switch typ {
	case "discover":
		if target == "" {
			return "", "", fmt.Errorf("discover needs a root domain in target")
		}
		return launchAssetDiscovery(target, name, actor)
	case "ports":
		return launchPortSurface(target, name, actor)
	case "php2shell":
		phpOnly, _ := args["php_only"].(bool)
		workers := 0
		if f, ok := args["workers"].(float64); ok {
			workers = int(f)
		}
		return launchPhp2ShellSweep(target, name, actor, phpOnly, workers)
	case "nuclei":
		if strings.TrimSpace(template) == "" {
			return "", "", fmt.Errorf("nuclei needs a template (for one target use nuclei_target)")
		}
		if hosts, _ := args["hosts"].(string); strings.TrimSpace(hosts) != "" {
			maxHosts := 0
			if f, ok := args["max_hosts"].(float64); ok {
				maxHosts = int(f)
			}
			return mcpLaunchTargeted(template, hosts, maxHosts, name, actor)
		}
		// Auto-target by the template's own tech tags — runs alongside a full
		// sweep (not queued behind it), so check it before the busy gate.
		if targeted, _ := args["targeted"].(bool); targeted {
			return launchGlobalNuclei(template, name, actor, true)
		}
		if busy := globalNucleiSweepBusy(); busy != "" {
			if q, _ := args["queue"].(bool); !q {
				return "", "", fmt.Errorf("a full-corpus sweep is already running or queued (%s), so this one would wait hours — "+
					"pass hosts=<product,…> for a targeted pass on fingerprinted hosts (minutes), or targeted=true to auto-target by the template's tags, or queue=true to wait in line", busy)
			}
		}
		return launchGlobalNuclei(template, name, actor, false)
	}
	t, ok := mcpScanTypes[typ]
	if !ok {
		return "", "", fmt.Errorf("unknown scan type %q — use one of: %s", typ, strings.Join(mcpScanTypeNames(), ", "))
	}
	if target == "" {
		return "", "", fmt.Errorf("%s needs a target (%s)", typ, t.target())
	}
	body, err := mcpScanBody(t, target, args)
	if err != nil {
		return "", "", err
	}
	return mcpInvokeScan(t.handler, body, actor)
}
