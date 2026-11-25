package api

import (
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func mcpRunScanTool(t *testing.T) mcpTool {
	t.Helper()
	for _, tool := range mcpTools {
		if tool.Name == "run_scan" {
			return tool
		}
	}
	t.Fatal("run_scan tool missing")
	return mcpTool{}
}

// Every type the dispatcher accepts is advertised (enum + description), so an
// agent can discover it from tools/list.
func TestMCPRunScanAdvertisesEveryType(t *testing.T) {
	tool := mcpRunScanTool(t)
	enum := tool.InputSchema["properties"].(map[string]any)["type"].(map[string]any)["enum"].([]string)
	if len(enum) != len(mcpScanTypes)+len(mcpSweepTypes) {
		t.Fatalf("enum has %d types, dispatcher %d", len(enum), len(mcpScanTypes)+len(mcpSweepTypes))
	}
	for _, n := range enum {
		if _, ok := mcpScanTypes[n]; !ok && mcpSweepTypes[n] == "" {
			t.Errorf("advertised type %q has no launcher", n)
		}
		if !strings.Contains(tool.Description, n+" (") {
			t.Errorf("description does not explain %q", n)
		}
	}
	for n, st := range mcpScanTypes {
		if st.handler == nil || st.field == "" || st.help == "" {
			t.Errorf("%s: incomplete spec %+v", n, st)
		}
	}
}

// The real /scan handlers validate the target before anything starts, and
// those errors reach the MCP caller.
func TestMCPRunScanUsesHandlerValidation(t *testing.T) {
	withTestSQLite(t)
	for _, tc := range []struct {
		args map[string]any
		want string
	}{
		{map[string]any{"type": "subdomains", "target": "../../app"}, "invalid target"},
		{map[string]any{"type": "dns-takeover", "target": "a b.com"}, "invalid target"},
		{map[string]any{"type": "github", "target": "/etc/passwd"}, "invalid target"},
		{map[string]any{"type": "tech"}, "needs a target (domain)"},
		{map[string]any{"type": "nuclei_target", "target": "acme.com", "mode": "everything"}, "Invalid mode"},
		{map[string]any{"type": "nuclei"}, "needs a template"},
		{map[string]any{"type": "keyhack_validate", "target": "x"}, "unknown scan type"},
		{map[string]any{"type": "zerodays", "target": "acme.com", "cves": []any{"CVE-2025-1; rm"}}, "invalid CVE"},
		{map[string]any{"type": "s3", "target": "acme.com", "region": "us-east-1;x"}, "region"},
		{map[string]any{"type": "domain_run", "target": "acme.com", "skip_ffuf": "yes"}, "skip_ffuf"},
	} {
		res := mcpCallTool("run_scan", tc.args)
		text := res["content"].([]map[string]any)[0]["text"].(string)
		if res["isError"] != true || !strings.Contains(text, tc.want) {
			t.Errorf("%v: want error containing %q, got %v %q", tc.args, tc.want, res["isError"], text)
		}
	}
}

func TestMCPScanBodyOptions(t *testing.T) {
	body := func(typ, target string, args map[string]any) map[string]any {
		t.Helper()
		b, err := mcpScanBody(mcpScanTypes[typ], target, args)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		return b
	}
	if b := body("nuclei_target", "https://app.acme.com/x", map[string]any{"mode": "cves"}); b["url"] != "https://app.acme.com/x" || b["domain"] != nil || b["mode"] != "cves" {
		t.Fatalf("nuclei_target url: %v", b)
	}
	if b := body("nuclei_target", "acme.com", nil); b["domain"] != "acme.com" || b["url"] != nil {
		t.Fatalf("nuclei_target domain: %v", b)
	}
	if b := body("asr", "acme.com", map[string]any{"mode": float64(3)}); b["mode"] != "3" {
		t.Fatalf("asr numeric mode: %v", b)
	}
	if b := body("dns_dangling_ip", "acme.com", nil); b["dns_type"] != "dangling-ip" || b["domain"] != "acme.com" {
		t.Fatalf("dangling: %v", b)
	}
	if b := body("s3_bucket", "acme-assets", map[string]any{"region": "eu-west-1"}); b["bucket"] != "acme-assets" || b["region"] != "eu-west-1" {
		t.Fatalf("s3_bucket: %v", b)
	}
	if b := body("zerodays", "acme.com", map[string]any{"cves": []any{"cve-2025-14847"}}); b["cves"].([]string)[0] != "CVE-2025-14847" {
		t.Fatalf("zerodays cves: %v", b)
	}
	// Intrusive options are dropped even when sent.
	b := body("zerodays", "acme.com", map[string]any{"dos_test": true, "domains_file": "/etc/passwd", "mongodb_host": "10.0.0.1"})
	f := body("firebase", "acme.com", map[string]any{"aggressive": true})
	ff := body("ffuf", "https://acme.com/FUZZ", map[string]any{"wordlist": "/app/.env"})
	for _, m := range []map[string]any{b, f, ff} {
		for _, k := range []string{"dos_test", "domains_file", "mongodb_host", "aggressive", "wordlist"} {
			if _, ok := m[k]; ok {
				t.Fatalf("%s must not pass through: %v", k, m)
			}
		}
	}
}

// A launch records the MCP as initiator and stashes name + description for
// the runner, exactly like a dashboard launch followed by an edit.
func TestMCPRunScanLaunchesThroughHandler(t *testing.T) {
	withTestSQLite(t)
	var got ScanRequest
	orig := mcpScanTypes["subdomain_run"]
	t.Cleanup(func() { mcpScanTypes["subdomain_run"] = orig })
	fake := orig
	fake.handler = func(c *gin.Context) {
		if !bindOrBad(c, &got) {
			return
		}
		okStarted(c, generateScanID(c), "started for "+*got.Subdomain)
	}
	mcpScanTypes["subdomain_run"] = fake

	out := mcpOK(t, mcpCallTool("run_scan", map[string]any{"type": "subdomain-run", "root": "app.acme.com",
		"skip_ffuf": true, "name": "  App host\tdeep run ", "description": "line 1\nline 2"}))
	if got.Subdomain == nil || *got.Subdomain != "app.acme.com" || got.SkipFFuf == nil || !*got.SkipFFuf {
		t.Fatalf("handler got %+v", got)
	}
	i := strings.Index(out, "(scan_id: ")
	if !strings.HasPrefix(out, "started for app.acme.com") || i < 0 {
		t.Fatalf("result: %q", out)
	}
	id := strings.TrimSuffix(out[i+len("(scan_id: "):], ")")
	if who := takeScanInitiator(id); who != mcpScanActor {
		t.Fatalf("initiator = %q", who)
	}
	if m := takeScanMeta(id); m.name != "App host deep run" || m.desc != "line 1\nline 2" {
		t.Fatalf("meta: %+v", m)
	}
}
