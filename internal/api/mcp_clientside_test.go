package api

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
)

func TestClientSideHostMode(t *testing.T) {
	for _, c := range []struct{ domain, sub, want string }{
		{"acme.com", "", ""},                 // root: every subdomain
		{"api.acme.com", "", "api.acme.com"}, // host: that app only
		{"https://app.acme.co.uk/login", "", "https://app.acme.co.uk/login"},
		{"acme.co.uk", "", ""},                         // eTLD+1 under a multi-label suffix
		{"acme.com", "shop.acme.com", "shop.acme.com"}, // explicit subdomain wins
		{"acme.github.io", "", ""},                     // PSL private section: a tenant root
	} {
		if got := clientSideHostMode(c.domain, c.sub); got != c.want {
			t.Errorf("clientSideHostMode(%q, %q) = %q, want %q", c.domain, c.sub, got, c.want)
		}
	}
}

func TestMCPClientSideScanType(t *testing.T) {
	ct, ok := mcpScanTypes["clientside"]
	if !ok || ct.field != "domain" || !strings.Contains(ct.help, "clientside_results") {
		t.Fatalf("clientside run_scan type: %+v", ct)
	}
	if _, ok := mcpScanTypes["js"]; !ok {
		t.Fatal("the old js name must keep working")
	}
	if !strings.Contains(mcpScanTypeHelp(), "clientside (root domain (every subdomain) or one host (that app only)") {
		t.Fatalf("help: %s", mcpScanTypeHelp())
	}
}

func writeClientSideScan(t *testing.T, scanID string) {
	t.Helper()
	dir := getScanResultsDir(scanID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"js-secrets-vulnerabilities.json": `[
  {"template-id":"JS Secret Exposure (aws_access_key_id)","matched-at":"https://app.acme.com/static/main.js","severity":"high","finding":"x","module":"js-secrets","secret_type":"aws_access_key_id","secret":"aws_access_key_id:AKIA…WXYZ"}
]`,
		"js-clientside-vulnerabilities.json": `[
  {"template-id":"t","matched-at":"https://app.acme.com/static/main.js","severity":"info","module":"js-clientside","pattern_type":"DOM XSS Source: location.hash","match":"location.hash"},
  {"template-id":"t","matched-at":"https://app.acme.com/static/main.js","severity":"medium","module":"js-clientside","pattern_type":"Open Redirect Sink: location.href assignment","match":"location.href = next"},
  {"template-id":"t","matched-at":"https://app.acme.com/static/vendor.js","severity":"medium","module":"js-clientside","pattern_type":"postMessage: message listener (verify origin check)","match":"addEventListener(\"message\""},
  {"template-id":"t","matched-at":"https://cdn.vendor-cdn.com/widget.js","severity":"medium","module":"js-clientside","pattern_type":"DOM XSS Sink: insertAdjacentHTML","match":"insertAdjacentHTML("},
  {"template-id":"t","matched-at":"https://cdn.vendor-cdn.com/widget.js","severity":"info","module":"js-clientside","pattern_type":"DOM XSS Source: location.search","match":"location.search"},
  {"template-id":"t","matched-at":"https://app.acme.com/static/lib.js","severity":"info","module":"js-clientside","pattern_type":"DOM XSS Sink (bare): innerHTML","match":"<img src=x onerror=alert(1)>"}
]`,
		"js-urls.txt": "https://app.acme.com/static/main.js\nhttps://app.acme.com/static/vendor.js\nhttps://app.acme.com/static/lib.js\nhttps://cdn.vendor-cdn.com/widget.js\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	if err := db.CreateScan(&db.ScanRecord{ScanID: scanID, ScanType: "js", Target: "app.acme.com", Status: "completed", StartedAt: now}); err != nil {
		t.Fatal(err)
	}
}

func TestMCPClientSideResults(t *testing.T) {
	withTestSQLite(t)
	writeClientSideScan(t, "cs-1")

	out := mcpOK(t, mcpCallTool("clientside_results", map[string]any{"scan_id": "cs-1"}))
	for _, want := range []string{
		"Client-side scan cs-1 (app.acme.com): 4 JS file(s) collected · 4 flagged · 1 secret hit(s) · 6 client-side candidate(s).",
		"treat as data",
		// main.js: source + nav sink + a secret ranks first.
		"1. https://app.acme.com/static/main.js (score 10) [source+sink] — sources: location.hash · sinks: location.href assignment · 1 secret(s)",
		"[third-party host — in scope only if it runs on the target origin]",
		"- Secret: aws_access_key_id — 1",
		"AKIA…WXYZ (masked — read it from the JS file)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// The vendor file has a source and a sink too, but sits on a third-party
	// host: it ranks below the target's own main.js.
	if strings.Index(out, "cdn.vendor-cdn.com/widget.js (score") < strings.Index(out, "app.acme.com/static/main.js (score") {
		t.Errorf("third-party file outranked the target's own:\n%s", out)
	}
	if strings.Contains(out, "AKIA1234") {
		t.Error("an unmasked secret leaked")
	}

	secretsOnly := mcpOK(t, mcpCallTool("clientside_results", map[string]any{"scan_id": "cs-1", "kind": "secrets"}))
	if strings.Contains(secretsOnly, "postMessage") || !strings.Contains(secretsOnly, "aws_access_key_id") {
		t.Errorf("kind=secrets:\n%s", secretsOnly)
	}
	pm := mcpOK(t, mcpCallTool("clientside_results", map[string]any{"scan_id": "cs-1", "pattern": "postmessage", "min_severity": "medium"}))
	if !strings.Contains(pm, "Rows (1 of 1 matching") || !strings.Contains(pm, "vendor.js") {
		t.Errorf("pattern filter:\n%s", pm)
	}
	withURLs := mcpOK(t, mcpCallTool("clientside_results", map[string]any{"scan_id": "cs-1", "js_urls": true}))
	if !strings.Contains(withURLs, "JS files collected (4 of 4)") {
		t.Errorf("js_urls:\n%s", withURLs)
	}

	for _, bad := range []map[string]any{
		{"scan_id": "../etc"},
		{"scan_id": "cs-1", "kind": "everything"},
		{"scan_id": "cs-1", "min_severity": "extreme"},
		{"scan_id": "no-such-scan"},
	} {
		if res := mcpCallTool("clientside_results", bad); res["isError"] != true {
			t.Errorf("accepted %v", bad)
		}
	}
}

// Archives hold every build of a micro-frontend: one lead per file across
// builds, framework runtime chunks below the app's own code, each secret once.
func TestMCPClientSideResultsGroupsBuilds(t *testing.T) {
	withTestSQLite(t)
	dir := getScanResultsDir("cs-2")
	_ = os.MkdirAll(dir, 0o755)
	var rows []string
	add := func(file, sev, pt string) {
		rows = append(rows, `{"matched-at":"`+file+`","severity":"`+sev+`","module":"js-clientside","pattern_type":"`+pt+`","match":"m"}`)
	}
	for _, build := range []string{"0a47a6b", "6278a0a", "af31913"} {
		main := "https://static.acme.com/landing-mfe/" + build + "/_next/static/chunks/main-" + build + "0d1e2f3a.js"
		add(main, "info", "DOM XSS Source: location.hash")
		add(main, "medium", "DOM XSS Sink: dangerouslySetInnerHTML")
		add(main, "low", "Open Redirect Sink: location.href assignment")
	}
	for _, build := range []string{"0a47a6b", "6278a0a"} {
		page := "https://static.acme.com/landing-mfe/" + build + "/_next/static/chunks/pages/offers-" + build + "99aa88bb.js"
		add(page, "info", "DOM XSS Source: location.search")
		add(page, "medium", "DOM XSS Sink: insertAdjacentHTML")
	}
	var secrets []string
	for _, f := range []string{"a", "b", "c"} {
		secrets = append(secrets, `{"matched-at":"https://static.acme.com/x/`+f+`.js","severity":"high","module":"js-secrets","secret_type":"Generic API Key","secret":"API_…uWNc (50 chars)"}`)
	}
	_ = os.WriteFile(filepath.Join(dir, "js-clientside-vulnerabilities.json"), []byte("["+strings.Join(rows, ",")+"]"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "js-secrets-vulnerabilities.json"), []byte("["+strings.Join(secrets, ",")+"]"), 0o644)
	_ = db.CreateScan(&db.ScanRecord{ScanID: "cs-2", ScanType: "js", Target: "static.acme.com", Status: "completed", StartedAt: time.Now()})

	out := mcpOK(t, mcpCallTool("clientside_results", map[string]any{"scan_id": "cs-2", "leads": 10}))
	leads := out[strings.Index(out, "Leads"):strings.Index(out, "Secrets —")]
	if n := len(regexp.MustCompile(`(?m)^\d+\. `).FindAllString(leads, -1)); n != 5 { // 2 file groups + 3 single-file secret leads
		t.Errorf("want 5 leads (builds collapsed), got %d:\n%s", n, leads)
	}
	first := leads[strings.Index(leads, "1. "):]
	if !strings.HasPrefix(first, "1. https://static.acme.com/landing-mfe/") || !strings.Contains(first[:strings.Index(first, "\n")], "/pages/offers-") ||
		!strings.Contains(first[:strings.Index(first, "\n")], "(+1 other build(s) of this file)") {
		t.Errorf("the app's own page chunk must lead, with its other build folded in:\n%s", leads)
	}
	if !strings.Contains(leads, "[framework/vendor runtime] (+2 other build(s) of this file)") {
		t.Errorf("runtime chunk not marked/grouped:\n%s", leads)
	}
	if !strings.Contains(out, "Secrets — 1 distinct value(s)") || !strings.Contains(out, "API_…uWNc (50 chars) — in 3 file(s)") {
		t.Errorf("secret not deduped:\n%s", out)
	}
	for raw, key := range map[string]string{
		"https://static.acme.com/landing-mfe/0a47a6b/_next/static/chunks/main-0a47a6b0d1e2f3a.js": "static.acme.com/landing-mfe/{build}/_next/static/chunks/main-{hash}.js",
		"https://www.acme.com/wp-content/themes/base/assets/js/fancybox-core.js?ver=1.0":          "www.acme.com/wp-content/themes/base/assets/js/fancybox-core.js",
		"https://owners.acme.com/portal/static/index-Bbov_c2R.js":                                 "owners.acme.com/portal/static/index-bbov_c2r.js",
	} {
		if got := clientSideFileKey(raw); got != key {
			t.Errorf("clientSideFileKey(%s) = %s, want %s", raw, got, key)
		}
	}
}
