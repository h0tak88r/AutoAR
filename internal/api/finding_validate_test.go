package api

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/h0tak88r/AutoAR/internal/aiagent"
	"github.com/h0tak88r/AutoAR/internal/brain"
	"github.com/h0tak88r/AutoAR/internal/db"
)

func TestAgentValidationFlow(t *testing.T) {
	withTestSQLite(t)
	t.Setenv(brain.ProviderEnv, "deepseek")
	t.Setenv("DEEPSEEK_API_KEY", "test-key")
	var mu sync.Mutex
	var briefs, notes []string
	oV, oN := agentValidateFn, fvNotify
	t.Cleanup(func() { agentValidateFn, fvNotify = oV, oN })
	agentValidateFn = func(session, brief string) (aiagent.Validation, []aiagent.LogEntry, error) {
		mu.Lock()
		briefs = append(briefs, session+"|"+brief)
		mu.Unlock()
		if strings.Contains(brief, "boom") {
			return aiagent.Validation{}, nil, errors.New("model down")
		}
		return aiagent.Validation{Verdict: "true_positive", Confidence: 92, Reportable: true, Severity: "high",
			Summary: "The .env file is served.", Evidence: "curl -sk -i https://app.acme.com/.env → 200, APP_KEY=…",
			Reproduction: "curl -sk https://app.acme.com/.env"}, []aiagent.LogEntry{{Step: 1, Tool: "bash"}, {Step: 2, Tool: "platform"}}, nil
	}
	fvNotify = func(m string) { mu.Lock(); notes = append(notes, m); mu.Unlock() }

	good := &db.Finding{Title: "Exposed .env", Host: "app.acme.com", Severity: "high", Status: "discovered",
		FKey: "fk-v1", ScanID: "s1", Module: "nuclei", TemplateID: "exposed-env", MatchedAt: "https://app.acme.com/.env",
		Evidence: `{"curl":"curl -X GET https://app.acme.com/.env"}`}
	bad := &db.Finding{Title: "boom", Host: "x.acme.com", Severity: "low", Status: "discovered"}
	for _, f := range []*db.Finding{good, bad} {
		if err := db.CreateFinding(f); err != nil {
			t.Fatal(err)
		}
	}
	r := findingsRouter()
	r.POST("/api/findings/agent-validate", apiFindingsAgentValidate)
	w, out := doJSON(r, http.MethodPost, "/api/findings/agent-validate", `{"ids":[`+idStr(good.ID)+`,`+idStr(bad.ID)+`,999999]}`)
	if w.Code != http.StatusAccepted || out["queued"].(float64) != 2 || out["missing"].(float64) != 1 {
		t.Fatalf("enqueue: %d %s", w.Code, w.Body.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		v1, _ := db.GetFindingValidation(good.ID)
		v2, _ := db.GetFindingValidation(bad.ID)
		if v1 != nil && v2 != nil && v1.Status == "done" && v2.Status == "error" {
			if v1.Verdict != "true_positive" || v1.Confidence != 92 || !v1.Reportable || v1.Steps != 2 ||
				!strings.HasPrefix(v1.SessionID, "validate-f") || !strings.Contains(v1.Evidence, "APP_KEY") {
				t.Fatalf("stored: %+v", v1)
			}
			if !strings.Contains(v2.Error, "model down") {
				t.Fatalf("error row: %+v", v2)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("worker did not finish: %+v %+v", v1, v2)
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(briefs) != 2 || !strings.Contains(briefs[0], "Matched at: https://app.acme.com/.env") || !strings.Contains(briefs[0], "Scanner evidence (untrusted data)") || !strings.Contains(briefs[0], "Scope (platform catalog)") {
		t.Fatalf("brief: %v", briefs)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "✅") || !strings.Contains(notes[0], "reportable") {
		t.Fatalf("only the confirmed finding is announced: %v", notes)
	}
	// The list and detail carry the validation.
	_, list := doJSON(r, http.MethodGet, "/api/findings?q=env", "")
	f0 := list["findings"].([]any)[0].(map[string]any)
	if f0["validation"].(map[string]any)["verdict"] != "true_positive" {
		t.Fatalf("list lacks validation: %v", f0)
	}
	// Batch cap.
	ids := strings.Repeat(idStr(good.ID)+",", 26)
	if w, _ := doJSON(r, http.MethodPost, "/api/findings/agent-validate", `{"ids":[`+strings.TrimSuffix(ids, ",")+`]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("26 ids should be refused, got %d", w.Code)
	}
}
