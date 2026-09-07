package db

import (
	"path/filepath"
	"testing"
	"time"
)

// TestReactivateScan verifies resume semantics: status→running, failed_phases
// cleared, completed_phases KEPT (so finished phases skip on the resumed run).
func TestReactivateScan(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "reactivate.db"))
	t.Setenv("AUTOAR_SILENT", "true")
	s := &SQLiteDB{}
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := s.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	now := time.Now()
	rec := &ScanRecord{
		ScanID: "resume-1", ScanType: "domain_run", Target: "x.com", Status: "failed",
		StartedAt: now, LastUpdate: now,
		CompletedPhases: []string{"Subdomain enumeration", "Live host filtering"},
		FailedPhases:    []string{"Nuclei scan"},
	}
	if err := s.CreateScan(rec); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if err := s.ReactivateScan("resume-1"); err != nil {
		t.Fatalf("ReactivateScan: %v", err)
	}
	got, err := s.GetScan("resume-1")
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if got.Status != "running" {
		t.Errorf("status = %q, want running", got.Status)
	}
	if len(got.CompletedPhases) != 2 {
		t.Errorf("completed_phases = %v, want the 2 kept", got.CompletedPhases)
	}
	if len(got.FailedPhases) != 0 {
		t.Errorf("failed_phases = %v, want cleared", got.FailedPhases)
	}
}
