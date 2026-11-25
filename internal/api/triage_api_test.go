package api

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
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
)

// TestTriageScanEndToEnd drives a real scan record + indexed nuclei JSONL
// through runTriageJob with a stubbed model and a fake Discord webhook, then
// reads the verdicts back through the HTTP API.
func TestTriageScanEndToEnd(t *testing.T) {
	setupUsersTestDB(t)

	// Fake Discord: capture the multipart payload + attachment.
	var gotContent, gotFile string
	var gotMentions any
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			p, err := mr.NextPart()
			if err != nil {
				break
			}
			b, _ := io.ReadAll(p)
			switch p.FormName() {
			case "payload_json":
				var pj map[string]any
				_ = json.Unmarshal(b, &pj)
				gotContent, _ = pj["content"].(string)
				gotMentions = pj["allowed_mentions"]
			case "files[0]":
				gotFile = string(b)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer hook.Close()
	t.Setenv("WEBHOOK_FINDINGS", hook.URL)

	// A finished scan with one real + one noise finding in an indexed JSONL file.
	dir := t.TempDir()
	jsonl := filepath.Join(dir, "nuclei-results.jsonl")
	lines := []string{
		`{"template-id":"exposed-env","info":{"name":"Exposed .env","severity":"high"},"type":"http","host":"https://app.acme.com","matched-at":"https://app.acme.com/.env","request":"GET /.env HTTP/1.1","response":"HTTP/1.1 200 OK\r\n\r\nDB_PASSWORD=x"}`,
		`{"template-id":"tech-detect","info":{"name":"nginx","severity":"info"},"type":"http","matched-at":"https://app.acme.com/"}`,
		`not json`,
	}
	if err := os.WriteFile(jsonl, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := db.CreateScan(&db.ScanRecord{ScanID: "scan-tri-1", ScanType: "nuclei", Target: "acme.com",
		Status: "completed", StartedAt: now, LastUpdate: now}); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if err := db.AppendScanArtifact(&db.ScanArtifact{ScanID: "scan-tri-1", FileName: "nuclei-results.jsonl",
		LocalPath: jsonl, Module: "nuclei"}); err != nil {
		t.Fatalf("AppendScanArtifact: %v", err)
	}

	calls := 0
	orig := triageEngine
	t.Cleanup(func() { triageEngine = orig })
	triageEngine = triage.New(triage.Deps{
		Store: dbTriageStore{},
		Complete: func(context.Context, string, string, brain.Options) (string, error) {
			calls++
			return `{"verdict":"true_positive","confidence":95,"severity":"high","title":"Exposed .env file","reason":"DB_PASSWORD in body.","reportable":true,"report_markdown":"## Title\nExposed .env"}`, nil
		},
		Provider: func() (string, string) { return "deepseek", "deepseek-chat" },
		Scope:    func(string) triage.Scope { return triage.Scope{Status: "in", Program: "h1 acme"} },
		Allow:    triageAllow,
		Notify:   triage.NotifyDiscord,
	})

	sum := runTriageJob(triageJob{ScanID: "scan-tri-1", Reason: "test", AI: true})
	if calls != 1 || sum.Triaged != 1 || sum.Reportable != 1 || sum.Notified != 1 || sum.BelowSeverity != 0 {
		t.Fatalf("summary %+v calls=%d", sum, calls)
	}
	if !strings.Contains(gotContent, "Exposed .env file") || !strings.Contains(gotFile, "## Title") {
		t.Fatalf("discord content=%q file=%q", gotContent, gotFile)
	}
	if m, ok := gotMentions.(map[string]any); !ok || m["parse"] == nil {
		t.Fatalf("allowed_mentions not sent: %#v", gotMentions)
	}
	if triageUsedToday() != 1 {
		t.Fatalf("budget counter = %d, want 1", triageUsedToday())
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api")
	g.GET("/triage", apiTriageList)
	g.GET("/triage/item/:id", apiTriageGet)
	g.POST("/triage/item/:id/verdict", apiTriageVerdict)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/triage?reportable=1", nil))
	var list struct {
		Items []db.TriageRecord `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list.Items) != 1 {
		t.Fatalf("list: %s", w.Body.String())
	}
	it := list.Items[0]
	if it.Verdict != "true_positive" || it.Scope != "in" || it.NotifiedAt == 0 || it.Evidence != "" {
		t.Fatalf("item %+v", it)
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/triage/item/"+it.ID, nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "DB_PASSWORD") {
		t.Fatalf("item detail should carry evidence: %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/triage/item/"+it.ID+"/verdict", strings.NewReader(`{"verdict":"false_positive"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if got, _ := db.GetTriage(it.ID); w.Code != http.StatusOK || got.HumanVerdict != "false_positive" {
		t.Fatalf("verdict override: %d %+v", w.Code, got)
	}

	// Re-running keeps the cached verdict: no new model call, no new alert.
	gotContent = ""
	sum = runTriageJob(triageJob{ScanID: "scan-tri-1", AI: true})
	if calls != 1 || sum.Cached != 1 || gotContent != "" || sum.NewFindings != 0 {
		t.Fatalf("rerun %+v calls=%d content=%q", sum, calls, gotContent)
	}
	// The hit is one Finding linked to its AI verdict (the info line is not).
	fs, total, err := db.ListFindings(db.FindingFilter{ScanID: "scan-tri-1"})
	if err != nil || total != 1 || fs[0].AI == nil || fs[0].AI.HumanVerdict != "false_positive" || fs[0].Module != "nuclei" {
		t.Fatalf("findings: total=%d err=%v %+v", total, err, fs)
	}
}

func TestTriagePollerWatermark(t *testing.T) {
	setupUsersTestDB(t)
	t.Setenv(brain.ProviderEnv, "deepseek")
	t.Setenv("DEEPSEEK_API_KEY", "k")
	triageQ.mu.Lock()
	triageQ.pending = nil
	triageQ.mu.Unlock()

	// First poll only arms the watermark — no back-fill of historical scans.
	triagePollOnce()
	if db.GetSettingInt(triageWatermarkKey, 0) == 0 {
		t.Fatal("watermark not armed")
	}
	_ = db.SetSetting(triageWatermarkKey, "1000")
	done := time.Unix(2000, 0)
	for _, s := range []*db.ScanRecord{
		{ScanID: "old", ScanType: "nuclei", Target: "a.com", Status: "completed"},
		{ScanID: "rp", ScanType: "nuclei", Target: "race-pass", Status: "completed"},
		{ScanID: "running", ScanType: "nuclei", Target: "b.com", Status: "running"},
	} {
		s.StartedAt, s.LastUpdate = done, done
		if err := db.CreateScan(s); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.UpdateScanStatus("old", "completed")
	_ = db.UpdateScanStatus("rp", "completed")
	triagePollOnce()
	triageQ.mu.Lock()
	pending := append([]triageJob(nil), triageQ.pending...)
	triageQ.pending = nil
	triageQ.mu.Unlock()
	if len(pending) != 2 || pending[0].ScanID != "rp" {
		t.Fatalf("pending %+v (race pass must be first, running scan excluded)", pending)
	}
}
