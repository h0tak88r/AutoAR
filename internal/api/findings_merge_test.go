package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/h0tak88r/AutoAR/internal/brain"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/triage"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

func writeScanFile(t *testing.T, scanID, name, body string) string {
	t.Helper()
	dir := filepath.Join(utils.GetResultsDir(), scanID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIngestScanFindingsAcrossModules(t *testing.T) {
	withTestSQLite(t)
	const scanID = "scan-ing-1"
	now := time.Now()
	if err := db.CreateScan(&db.ScanRecord{ScanID: scanID, ScanType: "domain_run", Target: "acme.com",
		Status: "completed", StartedAt: now, LastUpdate: now}); err != nil {
		t.Fatal(err)
	}
	nuclei := writeScanFile(t, scanID, "nuclei-results.jsonl", strings.Join([]string{
		`{"template-id":"exposed-env","info":{"name":"Exposed .env","severity":"high"},"type":"http","host":"https://app.acme.com","matched-at":"https://app.acme.com/.env"}`,
		`{"template-id":"tech-detect","info":{"name":"nginx","severity":"info"},"type":"http","host":"https://app.acme.com","matched-at":"https://app.acme.com/"}`,
	}, "\n"))
	if err := db.AppendScanArtifact(&db.ScanArtifact{ScanID: scanID, FileName: "nuclei-results.jsonl", LocalPath: nuclei, Module: "nuclei"}); err != nil {
		t.Fatal(err)
	}
	writeScanFile(t, scanID, "zerodays-results.json", `[{"template-id":"mongobleed","matched-at":"db.acme.com:27017","severity":"high","module":"zerodays","finding":"MongoDB memory leak (CVE-2025-14847) — leaked 512 bytes","cve":"CVE-2025-14847","request":"OP_MSG probe","response":"leaked bytes..."}]`)
	// Candidate lists are not findings.
	writeScanFile(t, scanID, "gf-xss.txt", "https://app.acme.com/search?q=FUZZ\nhttps://app.acme.com/p?id=1\n")

	got, created, err := ingestScanFindings(scanID, false)
	if err != nil {
		t.Fatal(err)
	}
	if created != 2 || len(got) != 2 {
		t.Fatalf("created=%d returned=%d (want nuclei high + zerodays; info and GF skipped): %+v", created, len(got), got)
	}
	rows, total, err := db.ListFindings(db.FindingFilter{ScanID: scanID})
	if err != nil || total != 2 {
		t.Fatalf("list: total=%d err=%v", total, err)
	}
	mods := map[string]*db.Finding{}
	for _, r := range rows {
		mods[r.Module] = r
	}
	if n := mods["nuclei"]; n == nil || n.Host != "app.acme.com" || n.Severity != "high" || n.Status != "discovered" || n.FKey == "" {
		t.Fatalf("nuclei finding: %+v", n)
	}
	if z := mods["zerodays"]; z == nil || z.CVE != "CVE-2025-14847" || z.Host != "db.acme.com" || z.Severity != "high" {
		t.Fatalf("zerodays finding: %+v", z)
	}
	if mods["nuclei"].AI != nil {
		t.Fatalf("no AI review yet, AI must be nil: %+v", mods["nuclei"].AI)
	}

	// Re-ingesting the same scan adds nothing; the operator's status survives.
	if err := db.UpdateFindingStatus(mods["nuclei"].ID, "validated", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, created, _ := ingestScanFindings(scanID, false); created != 0 {
		t.Fatalf("re-ingest created %d", created)
	}
	if f, _ := db.GetFinding(mods["nuclei"].ID); f.Status != "validated" {
		t.Fatalf("re-scan must not reset status: %s", f.Status)
	}
	// Explicit import with info pulls the detection in too.
	if _, created, _ := ingestScanFindings(scanID, true); created != 1 {
		t.Fatalf("include_info created %d, want 1", created)
	}
}

func findingsRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("auth_role", "admin"); c.Set("auth_sub", "owner"); c.Next() })
	g := r.Group("/api")
	g.GET("/findings", apiListFindings)
	g.GET("/findings/:id", apiGetFinding)
	g.POST("/findings/:id/ai-review", apiFindingAIReview)
	g.POST("/findings/:id/verdict", apiFindingVerdict)
	g.POST("/findings/bulk-delete", apiFindingsBulkDelete)
	return r
}

func doJSON(r *gin.Engine, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func TestFindingAIReviewVerdictFiltersAndDelete(t *testing.T) {
	withTestSQLite(t)
	t.Setenv(brain.ProviderEnv, "deepseek")
	t.Setenv("DEEPSEEK_API_KEY", "test-key")
	calls := 0
	orig := triageEngine
	t.Cleanup(func() { triageEngine = orig })
	triageEngine = triage.New(triage.Deps{
		Store: dbTriageStore{},
		Complete: func(context.Context, string, string, brain.Options) (string, error) {
			calls++
			return `{"verdict":"true_positive","confidence":90,"severity":"low","title":"Verbose error","reason":"Stack trace shown.","reportable":false}`, nil
		},
		Provider: func() (string, string) { return "deepseek", "deepseek-flash" },
		Allow:    func() bool { return true },
	})

	manual := &db.Finding{Title: "Verbose error page", Host: "app.acme.com", Severity: "info", Source: "manual", Status: "discovered"}
	if err := db.CreateFinding(manual); err != nil {
		t.Fatal(err)
	}
	scanHit := &db.Finding{Title: "Open redirect", Host: "acme.com", Severity: "medium", Source: "scan:s1", Status: "discovered",
		FKey: "fk-scan-1", ScanID: "s1", Module: "nuclei", TemplateID: "open-redirect", MatchedAt: "https://acme.com/r?u=x"}
	if err := db.CreateFinding(scanHit); err != nil {
		t.Fatal(err)
	}
	r := findingsRouter()

	// AI review works on an info-level manual finding (no severity floor on demand).
	w, out := doJSON(r, http.MethodPost, "/api/findings/"+idStr(manual.ID)+"/ai-review", `{}`)
	if w.Code != http.StatusOK || calls != 1 {
		t.Fatalf("ai-review: %d %s calls=%d", w.Code, w.Body.String(), calls)
	}
	ai := out["finding"].(map[string]any)["ai"].(map[string]any)
	if ai["verdict"] != "true_positive" || ai["severity"] != "low" {
		t.Fatalf("ai: %+v", ai)
	}

	// Operator verdict on a never-reviewed finding creates the review row.
	w, out = doJSON(r, http.MethodPost, "/api/findings/"+idStr(scanHit.ID)+"/verdict", `{"verdict":"false_positive"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("verdict: %d %s", w.Code, w.Body.String())
	}
	if ai := out["finding"].(map[string]any)["ai"].(map[string]any); ai["human_verdict"] != "false_positive" || ai["status"] != "human" {
		t.Fatalf("human verdict: %+v", ai)
	}
	if w, _ := doJSON(r, http.MethodPost, "/api/findings/"+idStr(scanHit.ID)+"/verdict", `{"verdict":"pwned"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad verdict should be 400, got %d", w.Code)
	}

	// Filters and facets.
	_, out = doJSON(r, http.MethodGet, "/api/findings?ai=false_positive&facets=1", "")
	if out["total"].(float64) != 1 {
		t.Fatalf("ai=false_positive: %+v", out)
	}
	facets := out["facets"].(map[string]any)["ai"].(map[string]any)
	if facets["false_positive"].(float64) != 1 || facets["true_positive"].(float64) != 1 || facets["unreviewed"].(float64) != 0 {
		t.Fatalf("facets: %+v", facets)
	}
	if _, out = doJSON(r, http.MethodGet, "/api/findings?q=redirect", ""); out["total"].(float64) != 1 {
		t.Fatalf("q=redirect: %+v", out)
	}
	if w, _ := doJSON(r, http.MethodGet, "/api/findings?ai=nonsense", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown ai filter should be 400, got %d", w.Code)
	}

	// Detail carries evidence + AI; delete removes both rows.
	if w, _ := doJSON(r, http.MethodGet, "/api/findings/"+idStr(manual.ID), ""); w.Code != http.StatusOK {
		t.Fatalf("detail: %d", w.Code)
	}
	w, out = doJSON(r, http.MethodPost, "/api/findings/bulk-delete", `{"ids":[`+idStr(manual.ID)+`,`+idStr(scanHit.ID)+`,999999]}`)
	if w.Code != http.StatusOK || out["deleted"].(float64) != 2 {
		t.Fatalf("bulk delete: %d %s", w.Code, w.Body.String())
	}
}

func idStr(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// The dashboard PATCH edits any field; the old {status, report_ref, notes}
// form keeps its "empty = keep" meaning.
func TestPatchFindingFields(t *testing.T) {
	withTestSQLite(t)
	f := &db.Finding{Title: "XSS", Host: "a.acme.com", Status: "discovered", Notes: "keep me", ReportRef: "H1#1"}
	if err := db.CreateFinding(f); err != nil {
		t.Fatal(err)
	}
	r := findingsRouter()
	r.PATCH("/api/findings/:id", apiUpdateFinding)
	if w, _ := doJSON(r, http.MethodPatch, "/api/findings/"+idStr(f.ID), `{"status":"validated","report_ref":"","notes":""}`); w.Code != http.StatusOK {
		t.Fatalf("legacy status form: %d %s", w.Code, w.Body.String())
	}
	got, _ := db.GetFinding(f.ID)
	if got.Status != "validated" || got.Notes != "keep me" || got.ReportRef != "H1#1" {
		t.Fatalf("legacy form must keep notes/report_ref: %+v", got)
	}
	if w, _ := doJSON(r, http.MethodPatch, "/api/findings/"+idStr(f.ID), `{"title":"Stored XSS","severity":"high","cvss":7.4,"host":"b.acme.com"}`); w.Code != http.StatusOK {
		t.Fatalf("field edit: %d %s", w.Code, w.Body.String())
	}
	got, _ = db.GetFinding(f.ID)
	if got.Title != "Stored XSS" || got.Severity != "high" || got.CVSS != 7.4 || got.Host != "b.acme.com" || got.Status != "validated" {
		t.Fatalf("edited: %+v", got)
	}
	if w, _ := doJSON(r, http.MethodPatch, "/api/findings/"+idStr(f.ID), `{}`); w.Code != http.StatusBadRequest {
		t.Fatalf("empty patch should be 400, got %d", w.Code)
	}
	if w, _ := doJSON(r, http.MethodPatch, "/api/findings/999999", `{"title":"x"}`); w.Code != http.StatusNotFound {
		t.Fatalf("unknown id should be 404, got %d", w.Code)
	}
}

// The report link can be added, edited and removed on its own, and only an
// http(s) URL or a platform id is accepted (the dashboard renders it as a
// link).
func TestPatchFindingReportLink(t *testing.T) {
	withTestSQLite(t)
	f := &db.Finding{Title: "XSS", Host: "a.acme.com", Status: "submitted"}
	if err := db.CreateFinding(f); err != nil {
		t.Fatal(err)
	}
	r := findingsRouter()
	r.PATCH("/api/findings/:id", apiUpdateFinding)
	r.GET("/api/findings-list", apiListFindings)
	path := "/api/findings/" + idStr(f.ID)
	if w, _ := doJSON(r, http.MethodPatch, path, `{"report_ref":"https://hackerone.com/reports/2401337"}`); w.Code != http.StatusOK {
		t.Fatalf("add: %d %s", w.Code, w.Body.String())
	}
	if got, _ := db.GetFinding(f.ID); got.ReportRef != "https://hackerone.com/reports/2401337" || got.Status != "submitted" {
		t.Fatalf("added: %+v", got)
	}
	if w, _ := doJSON(r, http.MethodPatch, path, `{"report_ref":"javascript:alert(document.cookie)"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("javascript: link accepted: %d", w.Code)
	}
	if w, _ := doJSON(r, http.MethodPatch, path, `{"status":"submitted","report_ref":"data:text/html,x"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("data: link accepted via status form: %d", w.Code)
	}
	if w, _ := doJSON(r, http.MethodPatch, path, `{"report_ref":""}`); w.Code != http.StatusOK {
		t.Fatalf("remove: %d", w.Code)
	}
	if got, _ := db.GetFinding(f.ID); got.ReportRef != "" {
		t.Fatalf("not removed: %+v", got)
	}
	if err := db.UpdateFindingStatus(f.ID, "submitted", "vbscript:x", ""); err == nil {
		t.Fatal("status path accepted a vbscript: link")
	}
	_, out := doJSON(r, http.MethodGet, "/api/findings-list?program=__none__&report=0&facets=1", "")
	if out["total"].(float64) != 1 || out["facets"].(map[string]any)["no_program"].(float64) != 1 {
		t.Fatalf("list filters: %v", out)
	}
}

// closed=0 (the dashboard's default) leaves rejected / dup / wontfix out of
// the list and the counts; the API without it still returns everything.
func TestListFindingsHidesClosed(t *testing.T) {
	withTestSQLite(t)
	for i, st := range []string{"discovered", "rejected", "rejected", "dup", "validated"} {
		if err := db.CreateFinding(&db.Finding{Title: "f", Status: st, FKey: "lc" + idStr(int64(i))}); err != nil {
			t.Fatal(err)
		}
	}
	r := findingsRouter()
	_, out := doJSON(r, http.MethodGet, "/api/findings?closed=0&facets=1", "")
	fc := out["facets"].(map[string]any)
	if out["total"].(float64) != 2 || fc["total"].(float64) != 2 || fc["closed"].(float64) != 3 {
		t.Fatalf("closed=0: total %v facets %v", out["total"], fc)
	}
	if _, out := doJSON(r, http.MethodGet, "/api/findings?closed=0&status=rejected", ""); out["total"].(float64) != 2 {
		t.Fatalf("status=rejected must still list them: %v", out["total"])
	}
	if _, out := doJSON(r, http.MethodGet, "/api/findings", ""); out["total"].(float64) != 5 {
		t.Fatalf("API default keeps everything: %v", out["total"])
	}
}
