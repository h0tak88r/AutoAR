package db

import (
	"path/filepath"
	"strings"
	"testing"
)

func findingsTestDB(t *testing.T) {
	t.Helper()
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "findings.db"))
	t.Setenv("AUTOAR_SILENT", "true")
	s := &SQLiteDB{}
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := s.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	dbInstance = s
}

func TestFindingLifecycle(t *testing.T) {
	findingsTestDB(t)
	f := &Finding{Title: "Zammad WS session leak", Host: "devel-teenused.telia.ee", Platform: "h1",
		Program: "telia_eesti", Severity: "critical", CVSS: 9.8, Source: "zammad-verifier", Status: "submitted",
		ReportRef: "https://hackerone.com/reports/4103286"}
	if err := CreateFinding(f); err != nil {
		t.Fatalf("CreateFinding: %v", err)
	}
	if f.ID == 0 {
		t.Fatal("ID not populated")
	}
	got, err := GetFinding(f.ID)
	if err != nil || got.Title != f.Title || got.Status != "submitted" {
		t.Fatalf("GetFinding = %+v err=%v", got, err)
	}
	if err := UpdateFindingStatus(f.ID, "resolved", "", "bounty paid"); err != nil {
		t.Fatalf("UpdateFindingStatus: %v", err)
	}
	got, _ = GetFinding(f.ID)
	if got.Status != "resolved" || got.Notes != "bounty paid" {
		t.Errorf("update lost: %+v", got)
	}
	// Invalid status rejected.
	if err := UpdateFindingStatus(f.ID, "hacked", "", ""); err == nil {
		t.Error("invalid status accepted")
	}
	// Filter by status + age.
	rows, total, err := ListFindings(FindingFilter{Status: "resolved"})
	if err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("filter: total=%d err=%v", total, err)
	}
	_, total, _ = ListFindings(FindingFilter{Status: "resolved", MinAgeH: 1})
	if total != 0 {
		t.Errorf("min-age filter must exclude fresh rows, got %d", total)
	}
}

func TestHostPorts(t *testing.T) {
	findingsTestDB(t)
	if err := UpsertHostPort("gw.example.com", 8291, "tcp", 1000); err != nil {
		t.Fatalf("UpsertHostPort: %v", err)
	}
	if err := UpsertHostPort("gw.example.com", 8291, "tcp", 2000); err != nil {
		t.Fatalf("re-UpsertHostPort: %v", err)
	}
	rows, total, err := ListHostPorts("", 8291, 10)
	if err != nil || total != 1 {
		t.Fatalf("ListHostPorts: total=%d err=%v", total, err)
	}
	if rows[0].LastSeen != 2000 || rows[0].FirstSeen != 1000 {
		t.Errorf("upsert semantics wrong: %+v", rows[0])
	}
	// Invalid port rejected.
	if err := UpsertHostPort("x", 99999, "tcp", 1); err == nil {
		t.Error("invalid port accepted")
	}
}

func TestFindingReportRoundTrip(t *testing.T) {
	findingsTestDB(t)
	f := &Finding{Title: "report test", Platform: "h1"}
	if err := CreateFinding(f); err != nil {
		t.Fatalf("CreateFinding: %v", err)
	}
	if err := UpdateFindingReport(f.ID, "## Title\nX\n\n## POC\nY"); err != nil {
		t.Fatalf("UpdateFindingReport: %v", err)
	}
	got, _ := GetFinding(f.ID)
	if got.ReportMD == "" || !strings.Contains(got.ReportMD, "## POC") {
		t.Errorf("report_md roundtrip failed: %q", got.ReportMD)
	}
}
