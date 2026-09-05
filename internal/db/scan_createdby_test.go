package db

import (
	"path/filepath"
	"testing"
	"time"
)

// TestScanCreatedByRoundTrip verifies the created_by column round-trips through
// CreateScan (INSERT) and both read paths (GetScan + ListActiveScans) — guarding
// the bulk SELECT/Scan edits that added the scan-initiator username.
func TestScanCreatedByRoundTrip(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "scan_createdby.db"))
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
		ScanID: "scan-createdby-1", ScanType: "subdomains", Target: "example.com",
		Status: "running", StartedAt: now, LastUpdate: now, Command: "test", CreatedBy: "alice",
	}
	if err := s.CreateScan(rec); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	got, err := s.GetScan("scan-createdby-1")
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if got.CreatedBy != "alice" {
		t.Errorf("GetScan CreatedBy = %q, want alice", got.CreatedBy)
	}

	active, err := s.ListActiveScans()
	if err != nil {
		t.Fatalf("ListActiveScans: %v", err)
	}
	found := false
	for _, a := range active {
		if a.ScanID == "scan-createdby-1" {
			found = true
			if a.CreatedBy != "alice" {
				t.Errorf("ListActiveScans CreatedBy = %q, want alice", a.CreatedBy)
			}
		}
	}
	if !found {
		t.Error("created scan missing from ListActiveScans")
	}

	// A scan with no initiator (system/automated) round-trips as empty.
	sys := &ScanRecord{
		ScanID: "scan-createdby-2", ScanType: "nuclei", Target: "global",
		Status: "running", StartedAt: now, LastUpdate: now,
	}
	if err := s.CreateScan(sys); err != nil {
		t.Fatalf("CreateScan system: %v", err)
	}
	got2, err := s.GetScan("scan-createdby-2")
	if err != nil {
		t.Fatalf("GetScan system: %v", err)
	}
	if got2.CreatedBy != "" {
		t.Errorf("system scan CreatedBy = %q, want empty", got2.CreatedBy)
	}
}
