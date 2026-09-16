package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression: watch-scan JSONL files regularly exceed scanResultMaxBody
// (12 MB) because every row embeds the encoded template; the parsed-results
// endpoint used to silently skip them, showing "No parseable findings" while
// the scans list badge counted thousands. parseOversizedJSONLFile must stream
// such files and surface rows.
func TestParseOversizedJSONLFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nuclei-watch.jsonl")

	var b strings.Builder
	for i := 0; i < 50; i++ {
		b.WriteString(`{"template-id":"CVE-2026-30352","host":"https://host` + string(rune('a'+i%26)) + `.example.com","matched-at":"https://host.example.com/devserver/start","matcher-status":true,"info":{"name":"Autocoder cmd injection","severity":"critical"},"template-encoded":"QUJDREVGR0g="}` + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		t.Fatal(err)
	}

	rows := parseOversizedJSONLFile(path, "nuclei", "vulnerability", 1200)
	if len(rows) == 0 {
		t.Fatal("expected findings from oversized JSONL stream, got 0")
	}
	if len(rows) > 50 {
		t.Fatalf("expected at most 50 rows, got %d", len(rows))
	}

	// maxRows must bound the output
	bounded := parseOversizedJSONLFile(path, "nuclei", "vulnerability", 7)
	if len(bounded) != 7 {
		t.Fatalf("expected maxRows=7 to bound output at 7, got %d", len(bounded))
	}

	// Missing file must yield nil, not panic
	if rows := parseOversizedJSONLFile(filepath.Join(dir, "missing.jsonl"), "nuclei", "vulnerability", 10); rows != nil {
		t.Fatalf("expected nil for missing file, got %d rows", len(rows))
	}
}
