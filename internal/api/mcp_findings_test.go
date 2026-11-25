package api

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
)

func mcpOK(t *testing.T, res map[string]any) string {
	t.Helper()
	if res["isError"] == true {
		t.Fatalf("tool error: %v", res["content"])
	}
	return res["content"].([]map[string]any)[0]["text"].(string)
}

func TestMCPMergedFindingsAndScanTools(t *testing.T) {
	withTestSQLite(t)

	// scan_results: only scan_id is required (template/limit are optional).
	for _, tool := range mcpTools {
		if tool.Name == "scan_results" {
			if req := tool.InputSchema["required"].([]string); len(req) != 1 || req[0] != "scan_id" {
				t.Fatalf("scan_results required = %v", req)
			}
		}
	}

	now := time.Now()
	if err := db.CreateScan(&db.ScanRecord{ScanID: "scan-m1", ScanType: "nuclei", Target: "global-subdomains",
		Status: "running", StartedAt: now, LastUpdate: now}); err != nil {
		t.Fatal(err)
	}
	mcpOK(t, mcpCallTool("edit_scan", map[string]any{"scan_id": "scan-m1", "name": "Smarty sweep", "description": "why"}))
	if rec, _ := db.GetScan("scan-m1"); rec.Name != "Smarty sweep" || rec.Description != "why" {
		t.Fatalf("edit_scan: %+v", rec)
	}
	if res := mcpCallTool("edit_scan", map[string]any{"scan_id": "scan-m1"}); res["isError"] != true {
		t.Fatal("edit_scan with nothing to change must error")
	}

	f := &db.Finding{Title: "Exposed .env", Host: "app.acme.com", Severity: "high", Source: "scan:scan-m1", Status: "discovered",
		FKey: "fk-m1", ScanID: "scan-m1", Module: "nuclei", TemplateID: "exposed-env", MatchedAt: "https://app.acme.com/.env"}
	if err := db.CreateFinding(f); err != nil {
		t.Fatal(err)
	}
	mcpOK(t, mcpCallTool("set_finding_verdict", map[string]any{"id": float64(f.ID), "verdict": "true_positive"}))
	if res := mcpCallTool("set_finding_verdict", map[string]any{"id": float64(f.ID), "verdict": "pwned"}); res["isError"] != true {
		t.Fatal("bad verdict must error")
	}
	out := mcpOK(t, mcpCallTool("list_findings", map[string]any{"ai": "true_positive", "scan_id": "scan-m1"}))
	if !strings.Contains(out, "(total 1)") || !strings.Contains(out, `"human_verdict": "true_positive"`) {
		t.Fatalf("list_findings: %s", out)
	}
	if out := mcpOK(t, mcpCallTool("list_findings", map[string]any{"ai": "unreviewed"})); !strings.Contains(out, "(total 0)") {
		t.Fatalf("unreviewed should be empty: %s", out)
	}
}

// The MCP can read, create, edit any field, bulk-update and delete findings.
func TestMCPFindingsFullCRUD(t *testing.T) {
	withTestSQLite(t)
	out := mcpOK(t, mcpCallTool("create_finding", map[string]any{"title": "SSRF in /fetch", "host": "api.acme.com",
		"severity": "HIGH", "cvss": float64(8.6), "cve": "cve-2026-1", "matched_at": "https://api.acme.com/fetch?u=",
		"notes": "found by hand", "report_md": "## SSRF"}))
	var id int64
	fmt.Sscanf(out, "created finding #%d", &id)
	f, err := db.GetFinding(id)
	if err != nil || f.Severity != "high" || f.CVSS != 8.6 || f.CVE != "CVE-2026-1" || f.ReportMD != "## SSRF" || f.Source != "mcp" || f.Notes != "found by hand" {
		t.Fatalf("created: %+v %v", f, err)
	}
	mcpOK(t, mcpCallTool("update_finding", map[string]any{"id": float64(id), "title": "Blind SSRF in /fetch", "severity": "critical",
		"cvss": float64(9.1), "program": "acme", "platform": "h1", "notes": "", "status": "validated", "report_md": "## Blind SSRF"}))
	f, _ = db.GetFinding(id)
	if f.Title != "Blind SSRF in /fetch" || f.Severity != "critical" || f.CVSS != 9.1 || f.Program != "acme" || f.Notes != "" ||
		f.Status != "validated" || f.ReportMD != "## Blind SSRF" || f.Host != "api.acme.com" {
		t.Fatalf("updated: %+v", f)
	}
	for _, bad := range []map[string]any{
		{"id": float64(id), "severity": "extreme"},
		{"id": float64(id), "status": "pwned"},
		{"id": float64(id), "cvss": float64(11)},
		{"id": float64(id), "title": "  "},
		{"id": float64(id)},
		{"id": float64(999999), "title": "x"},
	} {
		if res := mcpCallTool("update_finding", bad); res["isError"] != true {
			t.Errorf("accepted %v", bad)
		}
	}
	second := &db.Finding{Title: "two", Status: "discovered"}
	_ = db.CreateFinding(second)
	if out := mcpOK(t, mcpCallTool("bulk_update_findings", map[string]any{"ids": []any{float64(id), float64(second.ID), float64(424242)}, "status": "drafted"})); !strings.Contains(out, "2 finding(s)") {
		t.Fatalf("bulk: %s", out)
	}
	if out := mcpOK(t, mcpCallTool("list_findings", map[string]any{"severity": "critical", "platform": "h1"})); !strings.Contains(out, "(total 1)") {
		t.Fatalf("list by severity/platform: %s", out)
	}
	if out := mcpOK(t, mcpCallTool("delete_findings", map[string]any{"ids": []any{float64(id), float64(second.ID)}})); !strings.Contains(out, "2 finding(s) deleted") {
		t.Fatalf("delete: %s", out)
	}
	if _, err := db.GetFinding(id); err == nil {
		t.Fatal("finding still there")
	}
	if res := mcpCallTool("delete_findings", map[string]any{"ids": []any{}}); res["isError"] != true {
		t.Fatal("empty delete must error")
	}
}

// list_findings filters by program (handle, "platform handle", or __none__),
// report link and closed status, and links each program to its page.
func TestMCPListFindingsByProgram(t *testing.T) {
	withTestSQLite(t)
	if _, err := db.UpsertCatalogProgram(db.CatalogProgram{Source: "h1", Handle: "alibaba", URL: "https://hackerone.com/alibaba"}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []*db.Finding{
		{Title: "ali-1", Host: "888kiss.aliexpress.com", Platform: "h1", Program: "alibaba", ProgramMatch: "related", Status: "discovered", ReportRef: "https://hackerone.com/reports/1"},
		{Title: "ali-2", Host: "x.aliexpress.com", Platform: "h1", Program: "alibaba", Status: "rejected"},
		{Title: "ywh-ali", Host: "y.alibaba.fr", Platform: "ywh", Program: "alibaba", Status: "discovered"},
		{Title: "orphan", Host: "nowhere.example.org", Status: "discovered"},
	} {
		if err := db.CreateFinding(f); err != nil {
			t.Fatal(err)
		}
	}
	titles := func(args map[string]any) string {
		t.Helper()
		out := mcpOK(t, mcpCallTool("list_findings", args))
		var got []string
		for _, n := range []string{"ali-1", "ali-2", "ywh-ali", "orphan"} {
			if strings.Contains(out, `"title": "`+n+`"`) {
				got = append(got, n)
			}
		}
		return strings.Join(got, ",")
	}
	for _, c := range []struct {
		args map[string]any
		want string
	}{
		{map[string]any{"program": "alibaba"}, "ali-1,ali-2,ywh-ali"},
		{map[string]any{"program": "AliBaba", "platform": "h1"}, "ali-1,ali-2"},
		{map[string]any{"program": "h1 alibaba"}, "ali-1,ali-2"},
		{map[string]any{"program": "hackerone alibaba", "hide_closed": true}, "ali-1"},
		{map[string]any{"program": "__none__"}, "orphan"},
		{map[string]any{"program": "alibaba", "report": "1"}, "ali-1"},
		{map[string]any{"program": "alibaba", "report": "0", "status": "rejected", "hide_closed": true}, "ali-2"},
	} {
		if got := titles(c.args); got != c.want {
			t.Errorf("%v: %s, want %s", c.args, got, c.want)
		}
	}
	out := mcpOK(t, mcpCallTool("list_findings", map[string]any{"program": "h1 alibaba", "hide_closed": true}))
	if !strings.Contains(out, `"program_url": "https://hackerone.com/alibaba"`) || !strings.Contains(out, `"program_match": "related"`) {
		t.Fatalf("rows carry the program link and match: %s", out)
	}
	if res := mcpCallTool("list_findings", map[string]any{"report": "yes"}); res["isError"] != true {
		t.Fatal("report must be 1 or 0")
	}
	for _, tool := range mcpTools {
		if tool.Name == "list_findings" {
			props := tool.InputSchema["properties"].(map[string]any)
			for _, k := range []string{"program", "report", "hide_closed"} {
				if props[k] == nil {
					t.Errorf("list_findings schema lacks %s", k)
				}
			}
		}
	}
}
