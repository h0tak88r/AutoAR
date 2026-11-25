package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/h0tak88r/AutoAR/internal/db"
)

func TestCleanScanText(t *testing.T) {
	cases := []struct {
		in        string
		max       int
		multiline bool
		want      string
	}{
		{"  Smarty   sweep \t v2 ", 120, false, "Smarty sweep v2"},
		{"line1\nline2\r\n", 120, false, "line1 line2"},
		{"why:\nfollow-up on #12\n", 2000, true, "why:\nfollow-up on #12"},
		{"bell\x07 esc\x1b[31m red", 120, false, "bell esc[31m red"},
		{strings.Repeat("é", 200), 120, false, strings.Repeat("é", 120)}, // runes, not bytes
	}
	for _, c := range cases {
		if got := cleanScanText(c.in, c.max, c.multiline); got != c.want {
			t.Errorf("cleanScanText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNucleiTemplateTitle(t *testing.T) {
	yamlTpl := "id: smarty-app-detect-cve-2026-82531\n\ninfo:\n  name: Smarty-based Application Detection (CVE-2026-82531 triage)\n  severity: info\n"
	if got := nucleiTemplateTitle(yamlTpl); got != "Nuclei: Smarty-based Application Detection (CVE-2026-82531 triage)" {
		t.Errorf("yaml info.name: %q", got)
	}
	if got := nucleiTemplateTitle("id: only-an-id\nhttp: []\n"); got != "Nuclei: only-an-id" {
		t.Errorf("yaml id fallback: %q", got)
	}
	if got := nucleiTemplateTitle("http/cves/2026/CVE-2026-21589.yaml"); got != "Nuclei: CVE-2026-21589" {
		t.Errorf("template path: %q", got)
	}
	if got := nucleiTemplateTitle("id: [unclosed\n  - nope"); got != "" {
		t.Errorf("unparseable yaml must give no title, got %q", got)
	}
	long := "id: x\ninfo:\n  name: " + strings.Repeat("A", 500) + "\n"
	if got := nucleiTemplateTitle(long); len([]rune(got)) > scanNameMax {
		t.Errorf("title over %d runes: %d", scanNameMax, len([]rune(got)))
	}
}

func patchScan(t *testing.T, id, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("auth_role", "admin")
	c.Set("auth_sub", "owner")
	c.Params = gin.Params{{Key: "id", Value: id}}
	c.Request = httptest.NewRequest(http.MethodPatch, "/api/scans/"+id, bytes.NewBufferString(body))
	c.Request.Header.Set("Content-Type", "application/json")
	apiUpdateScanMeta(c)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func TestUpdateScanMetaEndpoint(t *testing.T) {
	withTestSQLite(t)
	now := time.Now()
	if err := db.CreateScan(&db.ScanRecord{ScanID: "scan-a", ScanType: "nuclei", Target: "global-subdomains",
		Status: "running", StartedAt: now, LastUpdate: now}); err != nil {
		t.Fatal(err)
	}

	w, out := patchScan(t, "scan-a", `{"name":"  Smarty   sweep ","description":"follow-up\non triage #12"}`)
	if w.Code != http.StatusOK || out["status"] != "saved" {
		t.Fatalf("patch existing: %d %v", w.Code, out)
	}
	rec, err := db.GetScan("scan-a")
	if err != nil || rec.Name != "Smarty sweep" || rec.Description != "follow-up\non triage #12" {
		t.Fatalf("stored: %+v (%v)", rec, err)
	}

	// Name-only edit leaves the description alone; "" clears a field.
	if w, _ := patchScan(t, "scan-a", `{"name":"Renamed"}`); w.Code != http.StatusOK {
		t.Fatalf("rename: %d", w.Code)
	}
	if rec, _ := db.GetScan("scan-a"); rec.Name != "Renamed" || rec.Description == "" {
		t.Fatalf("partial update clobbered: %+v", rec)
	}
	if w, _ := patchScan(t, "scan-a", `{"description":""}`); w.Code != http.StatusOK {
		t.Fatalf("clear: %d", w.Code)
	}
	if rec, _ := db.GetScan("scan-a"); rec.Description != "" || rec.Name != "Renamed" {
		t.Fatalf("clear description: %+v", rec)
	}

	// Bad input.
	if w, _ := patchScan(t, "scan-a", `{}`); w.Code != http.StatusBadRequest {
		t.Errorf("empty body should be 400, got %d", w.Code)
	}
	if w, _ := patchScan(t, "a/b", `{"name":"x"}`); w.Code != http.StatusBadRequest {
		t.Errorf("slash in id should be 400, got %d", w.Code)
	}
}

// An edit that lands before the runner writes the row must not be lost: it
// is stashed and applied at CreateScan.
func TestScanMetaBeforeRowExistsIsApplied(t *testing.T) {
	withTestSQLite(t)
	w, out := patchScan(t, "scan-early", `{"name":"Early title","description":"set before the row existed"}`)
	if w.Code != http.StatusOK || out["status"] != "pending" {
		t.Fatalf("early patch: %d %v", w.Code, out)
	}
	m := takeScanMeta("scan-early")
	if !m.hasName || m.name != "Early title" || !m.hasDesc || m.desc != "set before the row existed" {
		t.Fatalf("stash: %+v", m)
	}
	// Once applied to an existing row, the stash is dropped (no stale reuse).
	now := time.Now()
	_ = db.CreateScan(&db.ScanRecord{ScanID: "scan-late", ScanType: "ports", Target: "corpus", Status: "running", StartedAt: now, LastUpdate: now})
	if _, out := patchScan(t, "scan-late", `{"name":"x"}`); out["status"] != "saved" {
		t.Fatalf("existing row: %v", out)
	}
	if m := takeScanMeta("scan-late"); m.hasName {
		t.Fatalf("stash should be dropped once saved: %+v", m)
	}
}
