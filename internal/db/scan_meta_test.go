package db

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Title/description must survive every scan read path (GetScan,
// ListActiveScans, ListRecentScans) — each hand-lists its columns, so a
// SELECT/Scan mismatch on either backend breaks the whole scans page.
func TestScanMetaSQLite(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "scan_meta.db"))
	scanMetaContract(t)
}

func TestScanMetaPostgres(t *testing.T) {
	url := os.Getenv("AUTOAR_TEST_PG_URL")
	if url == "" {
		t.Skip("AUTOAR_TEST_PG_URL not set")
	}
	t.Setenv("DB_TYPE", "postgresql")
	t.Setenv("DB_HOST", url)
	scanMetaContract(t)
}

func scanMetaContract(t *testing.T) {
	t.Helper()
	t.Setenv("AUTOAR_SILENT", "true")
	SetDB(nil)
	t.Cleanup(func() { SetDB(nil) })
	if err := Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	id := "scan-meta-" + time.Now().Format("150405.000000")
	now := time.Now()
	if err := CreateScan(&ScanRecord{ScanID: id, ScanType: "nuclei", Target: "global-subdomains",
		Status: "running", StartedAt: now, LastUpdate: now, Name: "launch title"}); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	t.Cleanup(func() { _ = DeleteScan(id) })

	name, desc := "Smarty sweep", "why: follow-up\nwhat: templates_c listings"
	found, err := UpdateScanMeta(id, &name, &desc)
	if err != nil || !found {
		t.Fatalf("UpdateScanMeta: found=%v err=%v", found, err)
	}
	if found, err := UpdateScanMeta("scan-does-not-exist", &name, nil); err != nil || found {
		t.Fatalf("missing row: found=%v err=%v", found, err)
	}

	got, err := GetScan(id)
	if err != nil || got.Name != name || got.Description != desc {
		t.Fatalf("GetScan: %+v (%v)", got, err)
	}
	check := func(where string, list []*ScanRecord, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", where, err)
		}
		for _, s := range list {
			if s.ScanID == id {
				if s.Name != name || s.Description != desc {
					t.Fatalf("%s: name=%q desc=%q", where, s.Name, s.Description)
				}
				return
			}
		}
		t.Fatalf("%s: scan %s not listed", where, id)
	}
	active, err := ListActiveScans()
	check("ListActiveScans", active, err)
	// Recent lists finished scans only.
	if err := UpdateScanStatus(id, "completed"); err != nil {
		t.Fatalf("UpdateScanStatus: %v", err)
	}
	recent, err := ListRecentScans(50)
	check("ListRecentScans", recent, err)
}
