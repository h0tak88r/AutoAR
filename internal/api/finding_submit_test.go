package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// fakeH1 stands in for api.hackerone.com/v1/hackers/reports.
func fakeH1(t *testing.T, wantUser, wantToken string, status int, respBody string) *[]map[string]any {
	t.Helper()
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		if u != wantUser || p != wantToken {
			w.WriteHeader(401)
			return
		}
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		got = append(got, m)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	old := h1APIBase
	h1APIBase = srv.URL
	t.Cleanup(func() { h1APIBase = old })
	return &got
}

func TestSubmitToHackerOne(t *testing.T) {
	withTestSQLite(t)
	// Two h1 accounts; alibaba is visible only to "Samii".
	for _, a := range []struct{ label, user string }{{"0x88", "u0x88"}, {"Samii", "usamii"}} {
		if _, err := db.UpsertBBPAccount(db.BBPAccount{Platform: "h1", Label: a.label, Username: a.user, Token: "tok-" + a.label, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	got := fakeH1(t, "usamii", "tok-Samii", 201, `{"data":{"id":"2401337","type":"report"}}`)

	f := &db.Finding{Title: "Exposed .env", Host: "app.alibaba.com", Platform: "h1", Program: "alibaba",
		Severity: "high", Status: "drafted", FKey: "fk-sub"}
	if err := db.CreateFinding(f); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateFindingReport(f.ID, "## Steps\n1. curl"); err != nil {
		t.Fatal(err)
	}
	_ = db.SetSetting("bbp_program_accounts", `{"h1|alibaba":["Samii"]}`)
	progAcctMu.Lock()
	progAcctCache = nil
	progAcctMu.Unlock()

	r := findingsRouter()
	r.GET("/api/findings/:id/submit", apiFindingSubmitPreview)
	r.POST("/api/findings/:id/submit", apiFindingSubmit)

	// Preview picks the visible account and is ready to submit.
	w, out := doJSON(r, http.MethodGet, "/api/findings/"+idStr(f.ID)+"/submit", "")
	if w.Code != 200 || out["via"] != "api" || out["account"] != "Samii" || out["can_submit"] != true {
		t.Fatalf("preview: %d %v", w.Code, out)
	}

	// Submit files via the API as that account, saves the URL + status.
	w, out = doJSON(r, http.MethodPost, "/api/findings/"+idStr(f.ID)+"/submit", `{}`)
	if w.Code != 200 || out["url"] != "https://hackerone.com/reports/2401337" || out["status"] != "submitted" {
		t.Fatalf("submit: %d %v", w.Code, out)
	}
	if len(*got) != 1 {
		t.Fatalf("expected one API call, got %d", len(*got))
	}
	attrs := (*got)[0]["data"].(map[string]any)["attributes"].(map[string]any)
	if attrs["team_handle"] != "alibaba" || attrs["title"] != "Exposed .env" || attrs["severity_rating"] != "high" ||
		!strings.Contains(attrs["vulnerability_information"].(string), "curl") {
		t.Fatalf("payload: %v", attrs)
	}
	g, _ := db.GetFinding(f.ID)
	if g.Status != "submitted" || g.ReportRef != "https://hackerone.com/reports/2401337" {
		t.Fatalf("stored: %+v", g)
	}
}

func TestSubmitPreviewBlockers(t *testing.T) {
	withTestSQLite(t)
	_, _ = db.UpsertBBPAccount(db.BBPAccount{Platform: "h1", Label: "0x88", Username: "u", Token: "t", Enabled: true})
	r := findingsRouter()
	r.GET("/api/findings/:id/submit", apiFindingSubmitPreview)
	r.POST("/api/findings/:id/submit", apiFindingSubmit)

	// No report body → blocked.
	noBody := &db.Finding{Title: "x", Platform: "h1", Program: "acme", Status: "discovered", FKey: "fk-nb"}
	_ = db.CreateFinding(noBody)
	_, out := doJSON(r, http.MethodGet, "/api/findings/"+idStr(noBody.ID)+"/submit", "")
	if out["can_submit"] == true || !strings.Contains(out["blocker"].(string), "no report") {
		t.Fatalf("no-body preview: %v", out)
	}
	w, _ := doJSON(r, http.MethodPost, "/api/findings/"+idStr(noBody.ID)+"/submit", `{}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("submit without a report must 400, got %d", w.Code)
	}

	// Bugcrowd → manual, never an API submit.
	bc := &db.Finding{Title: "y", Platform: "bc", Program: "epam", Status: "drafted", FKey: "fk-bc"}
	_ = db.CreateFinding(bc)
	_ = db.UpdateFindingReport(bc.ID, "body")
	_, out = doJSON(r, http.MethodGet, "/api/findings/"+idStr(bc.ID)+"/submit", "")
	if out["via"] != "manual" || out["can_submit"] == true {
		t.Fatalf("bc preview: %v", out)
	}
	w, out = doJSON(r, http.MethodPost, "/api/findings/"+idStr(bc.ID)+"/submit", `{}`)
	if w.Code != http.StatusBadRequest || out["via"] != "manual" {
		t.Fatalf("bc submit must refuse with manual: %d %v", w.Code, out)
	}
}

func TestSubmitAccountAmbiguous(t *testing.T) {
	withTestSQLite(t)
	for _, l := range []string{"0x88", "Samii"} {
		_, _ = db.UpsertBBPAccount(db.BBPAccount{Platform: "h1", Label: l, Username: "u" + l, Token: "t" + l, Enabled: true})
	}
	f := &db.Finding{Title: "z", Platform: "h1", Program: "bothsee", Status: "drafted", FKey: "fk-amb"}
	_ = db.CreateFinding(f)
	_ = db.UpdateFindingReport(f.ID, "b")
	_ = db.SetSetting("bbp_program_accounts", `{"h1|bothsee":["0x88","Samii"]}`)
	progAcctMu.Lock()
	progAcctCache = nil
	progAcctMu.Unlock()

	r := findingsRouter()
	r.POST("/api/findings/:id/submit", apiFindingSubmit)
	// No account chosen and two can see it → 409 asking which.
	w, out := doJSON(r, http.MethodPost, "/api/findings/"+idStr(f.ID)+"/submit", `{}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("ambiguous submit must 409, got %d %v", w.Code, out)
	}
	opts, _ := out["account_options"].([]any)
	if len(opts) != 2 {
		t.Fatalf("want two options, got %v", out["account_options"])
	}
}
