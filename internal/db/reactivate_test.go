package db

import (
	"errors"
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

	// The row is running now: a second (racing / double-clicked) resume must not
	// "win" too, and an unknown scan is never reported as reactivated.
	if err := s.ReactivateScan("resume-1"); !errors.Is(err, ErrScanNotResumable) {
		t.Errorf("reactivating a running scan: err = %v, want ErrScanNotResumable", err)
	}
	if err := s.ReactivateScan("no-such-scan"); !errors.Is(err, ErrScanNotResumable) {
		t.Errorf("reactivating a missing scan: err = %v, want ErrScanNotResumable", err)
	}
	for _, st := range []string{"timed_out", "cancelled", "stopped", "FAILED"} {
		id := "resume-" + st
		if err := s.CreateScan(&ScanRecord{ScanID: id, ScanType: "domain_run", Target: "x.com", Status: st, StartedAt: now, LastUpdate: now}); err != nil {
			t.Fatalf("CreateScan(%s): %v", st, err)
		}
		if err := s.ReactivateScan(id); err != nil {
			t.Errorf("status %q must be resumable: %v", st, err)
		}
	}
}

// TestCreateScanDefaultsTimestamps guards the CLI path (setupCurrentScanManaged
// inserts no timestamps): a zero started_at/last_update made the orphan reaper
// see a running CLI scan as idle since year 1 and close it within minutes.
func TestCreateScanDefaultsTimestamps(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "defaults.db"))
	t.Setenv("AUTOAR_SILENT", "true")
	s := &SQLiteDB{}
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := s.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := s.CreateScan(&ScanRecord{ScanID: "cli-1", ScanType: "dns_cf1016", Target: "x.com", Status: "running"}); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	active, err := s.ListActiveScans()
	if err != nil || len(active) != 1 {
		t.Fatalf("ListActiveScans = %v, %v", active, err)
	}
	if active[0].StartedAt.IsZero() || active[0].LastUpdate.IsZero() {
		t.Fatalf("timestamps not defaulted: started=%v last=%v", active[0].StartedAt, active[0].LastUpdate)
	}
	if age := time.Since(active[0].LastUpdate); age < 0 || age > time.Hour {
		t.Fatalf("last_update age %v, want ~now", age)
	}

	// Legacy rows written with zero timestamps are backfilled from created_at.
	if _, err := s.db.Exec(`UPDATE scans SET started_at = ?, last_update = ? WHERE scan_id = ?`, time.Time{}, time.Time{}, "cli-1"); err != nil {
		t.Fatalf("zero timestamps: %v", err)
	}
	active, err = s.ListActiveScans()
	if err != nil || len(active) != 1 {
		t.Fatalf("ListActiveScans (legacy row) = %v, %v", active, err)
	}
	if active[0].StartedAt.IsZero() || active[0].LastUpdate.IsZero() {
		t.Fatalf("legacy zero timestamps not backfilled from created_at: started=%v last=%v", active[0].StartedAt, active[0].LastUpdate)
	}
}
