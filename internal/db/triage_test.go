package db

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestTriageStoreRoundTripSQLite(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "triage.db"))
	triageRoundTrip(t)
}

// TestTriageStoreRoundTripPostgres runs the same contract against a real
// Postgres when AUTOAR_TEST_PG_URL is set (e.g. postgres://postgres@127.0.0.1:5432/test).
func TestTriageStoreRoundTripPostgres(t *testing.T) {
	url := os.Getenv("AUTOAR_TEST_PG_URL")
	if url == "" {
		t.Skip("AUTOAR_TEST_PG_URL not set")
	}
	t.Setenv("DB_TYPE", "postgresql")
	t.Setenv("DB_HOST", url)
	triageRoundTrip(t)
	if c, err := triageDB(); err == nil {
		_ = c.exec(`DROP TABLE IF EXISTS ai_triage`)
	}
}

func triageRoundTrip(t *testing.T) {
	t.Helper()
	t.Setenv("AUTOAR_SILENT", "true")
	SetDB(nil)
	t.Cleanup(func() { SetDB(nil) })
	if c, err := triageDB(); err == nil {
		_ = c.exec(`DELETE FROM ai_triage`)
	}

	if _, err := GetTriage("missing"); !errors.Is(err, ErrTriageNotFound) {
		t.Fatalf("missing: %v", err)
	}
	a := &TriageRecord{ID: "a", ScanID: "s1", TemplateID: "t1", Title: "A", Verdict: "true_positive",
		Confidence: 91, Reportable: true, Status: "done", CreatedAt: 100, UpdatedAt: 100}
	b := &TriageRecord{ID: "b", ScanID: "s2", Verdict: "false_positive", Confidence: 80, Status: "done", CreatedAt: 200, UpdatedAt: 200}
	for _, r := range []*TriageRecord{a, b} {
		if err := UpsertTriage(r); err != nil {
			t.Fatalf("upsert %s: %v", r.ID, err)
		}
	}
	if err := SetTriageHumanVerdict("a", "false_positive", 150); err != nil {
		t.Fatal(err)
	}
	if err := SetTriageNotified("a", 160, "sent to Discord"); err != nil {
		t.Fatal(err)
	}
	// Re-triage must keep the operator override, the notification state and created_at.
	a2 := *a
	a2.Confidence, a2.UpdatedAt, a2.CreatedAt = 50, 300, 999
	if err := UpsertTriage(&a2); err != nil {
		t.Fatal(err)
	}
	got, err := GetTriage("a")
	if err != nil {
		t.Fatal(err)
	}
	if got.Confidence != 50 || got.HumanVerdict != "false_positive" || got.NotifiedAt != 160 || got.CreatedAt != 100 || !got.Reportable {
		t.Fatalf("after re-triage: %+v", got)
	}

	all, err := ListTriage(TriageFilter{})
	if err != nil || len(all) != 2 || all[0].ID != "b" {
		t.Fatalf("list newest-first: %v %+v", err, all)
	}
	rep, _ := ListTriage(TriageFilter{ReportableOnly: true})
	if len(rep) != 1 || rep[0].ID != "a" {
		t.Fatalf("reportable filter: %+v", rep)
	}
	byScan, _ := ListTriage(TriageFilter{ScanID: "s2"})
	if len(byScan) != 1 || byScan[0].ID != "b" {
		t.Fatalf("scan filter: %+v", byScan)
	}
	counts, err := TriageCounts()
	if err != nil || counts["total"] != 2 || counts["reportable"] != 1 || counts["false_positive"] != 1 {
		t.Fatalf("counts %v %v", counts, err)
	}
}
