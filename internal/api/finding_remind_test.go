package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
)

func TestFindingReminderFlow(t *testing.T) {
	withTestSQLite(t)
	f := &db.Finding{Title: "nginx CVE", CVE: "CVE-2017-7529", Host: "h.example.com", Platform: "h1", Program: "acme",
		Status: "drafted", FKey: "fk-rem"}
	if err := db.CreateFinding(f); err != nil {
		t.Fatal(err)
	}
	r := findingsRouter() // already has GET /api/findings
	r.POST("/api/findings/:id/remind", apiFindingRemind)

	// Set a 30-day reminder.
	w, out := doJSON(r, http.MethodPost, "/api/findings/"+idStr(f.ID)+"/remind", `{"days":30}`)
	at := int64(out["remind_at"].(float64))
	if w.Code != 200 || at <= time.Now().Unix() {
		t.Fatalf("remind: %d %v", w.Code, out)
	}
	if g, _ := db.GetFinding(f.ID); g.RemindAt != at {
		t.Fatalf("stored remind_at %d != %d", g.RemindAt, at)
	}
	// Not due yet → the due filter excludes it.
	_, out = doJSON(r, http.MethodGet, "/api/findings?remind=due", "")
	if int(out["total"].(float64)) != 0 {
		t.Fatalf("a 30-day reminder is not due: %v", out["total"])
	}
	// Force it due; fireDueReminders surfaces and clears it (fires once).
	if err := db.SetFindingReminder(f.ID, time.Now().Add(-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if due, _ := db.DueFindingReminders(time.Now().Unix(), 10); len(due) != 1 || due[0].ID != f.ID {
		t.Fatalf("due list: %v", due)
	}
	_, out = doJSON(r, http.MethodGet, "/api/findings?remind=due", "")
	if int(out["total"].(float64)) != 1 {
		t.Fatalf("due filter should show it: %v", out["total"])
	}
	fireDueReminders()
	if g, _ := db.GetFinding(f.ID); g.RemindAt != 0 {
		t.Fatalf("reminder should be cleared after firing, got %d", g.RemindAt)
	}
	// Clearing (days<=0) zeroes it.
	_, _ = doJSON(r, http.MethodPost, "/api/findings/"+idStr(f.ID)+"/remind", `{"days":30}`)
	w, out = doJSON(r, http.MethodPost, "/api/findings/"+idStr(f.ID)+"/remind", `{"days":0}`)
	if w.Code != 200 || out["remind_at"].(float64) != 0 {
		t.Fatalf("clear: %v", out)
	}
	// Over the cap is clamped to a year, not rejected.
	_, out = doJSON(r, http.MethodPost, "/api/findings/"+idStr(f.ID)+"/remind", `{"days":9999}`)
	if got := int64(out["remind_at"].(float64)); got > time.Now().Add(366*24*time.Hour).Unix() {
		t.Fatalf("not clamped: %d", got)
	}
}
