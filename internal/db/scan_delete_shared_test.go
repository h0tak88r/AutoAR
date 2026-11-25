package db

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// TestListR2KeysReferencedByOtherScans guards scan delete: artifact keys are
// path-based, so two scans of one target index the same object and deleting
// one scan must keep the objects the other still references.
func TestListR2KeysReferencedByOtherScans(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "shared_keys.db"))
	t.Setenv("AUTOAR_SILENT", "true")
	s := &SQLiteDB{}
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := s.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	now := time.Now()
	add := func(scanID, key string) {
		t.Helper()
		if err := s.AppendScanArtifact(&ScanArtifact{ScanID: scanID, FileName: filepath.Base(key), R2Key: key, PublicURL: "https://r2.example/" + key, CreatedAt: now}); err != nil {
			t.Fatalf("AppendScanArtifact(%s, %s): %v", scanID, key, err)
		}
	}
	add("scan-a", "new-results/example.com/vulnerabilities/xss.json")
	add("scan-b", "new-results/example.com/vulnerabilities/xss.json")
	add("scan-a", "new-results/scan-a/own.json")

	// More keys than one query chunk, to exercise chunking.
	keys := []string{"new-results/example.com/vulnerabilities/xss.json", "new-results/scan-a/own.json"}
	for i := 0; i < r2KeyQueryChunk+10; i++ {
		keys = append(keys, fmt.Sprintf("new-results/none/%d.json", i))
	}
	shared, err := s.ListR2KeysReferencedByOtherScans("scan-a", keys)
	if err != nil {
		t.Fatalf("ListR2KeysReferencedByOtherScans: %v", err)
	}
	if len(shared) != 1 || !shared["new-results/example.com/vulnerabilities/xss.json"] {
		t.Fatalf("shared = %v, want only the key scan-b also indexes", shared)
	}
}
