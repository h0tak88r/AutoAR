package utils

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// A scan's finding counter (scan list badge, Discord "scan complete") counts
// result rows, never recon lists or "no findings" placeholders. A client-side
// scan that found nothing used to report "1 finding": its urls.json
// ({"items": [homepage]}) was counted.
func TestScanFindingCounterSkipsRecon(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(dir, "count.db"))
	t.Setenv("AUTOAR_SILENT", "true")
	t.Setenv("AUTOAR_RESULTS_DIR", filepath.Join(dir, "results"))
	db.SetDB(nil)
	t.Cleanup(func() { db.SetDB(nil) })
	if err := db.Init(); err != nil {
		t.Fatal(err)
	}
	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}
	const id = "count-1"
	if err := db.CreateScan(&db.ScanRecord{ScanID: id, ScanType: "js", Target: "www.acme.com", Status: "running", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		rec, err := db.GetScan(id)
		if err != nil || rec == nil {
			t.Fatalf("scan: %v", err)
		}
		return rec.FilesUploaded
	}
	_ = WriteLinesAsJSON(id, "www.acme.com", "urls", "urls.json", []string{"https://www.acme.com/"})
	_ = WriteLinesAsJSON(id, "www.acme.com", "js-urls", "js-urls.json", []string{"https://www.acme.com/a.js"})
	_ = WriteNoFindingsJSON(id, "www.acme.com", "js-scan", "js-secrets-vulnerabilities.json")
	if n := count(); n != 0 {
		t.Fatalf("recon lists / placeholders counted as findings: %d", n)
	}
	_ = WriteJSONToScanDir(id, "js-clientside-vulnerabilities.json", []map[string]string{
		{"matched-at": "https://www.acme.com/a.js", "pattern_type": "DOM XSS Sink: innerHTML"},
		{"matched-at": "https://www.acme.com/a.js", "pattern_type": "postMessage: wildcard target origin '*'"},
	})
	if n := count(); n != 2 {
		t.Fatalf("real rows: %d, want 2", n)
	}
}
