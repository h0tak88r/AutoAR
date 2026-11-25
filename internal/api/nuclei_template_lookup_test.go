package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

const cachePoisonTpl = `id: nextjs-cache-poisoning
info:
  name: "Next.js Cache Poisoning Detection (CVE-2024-46982)"
  severity: high
requests:
  - method: GET
    path:
      - "{{BaseURL}}/poc?__nextDataReq=1"
    matchers:
      - type: word
        words: ["pageProps"]
`

func TestTemplateByID(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "cves"), 0o755)
	os.WriteFile(filepath.Join(root, "cves", "CVE-2024-46982.yaml"), []byte(cachePoisonTpl), 0o644)
	os.WriteFile(filepath.Join(root, "other.yaml"), []byte("id: something-else\ninfo:\n  name: x\n"), 0o644)
	os.WriteFile(filepath.Join(root, "notes.txt"), []byte("id: nextjs-cache-poisoning\n"), 0o644) // not yaml, ignored

	// Exact id match wins and returns the full YAML.
	y, p := templateByID(root, "nextjs-cache-poisoning", "")
	if !strings.Contains(y, "CVE-2024-46982") || filepath.Base(p) != "CVE-2024-46982.yaml" {
		t.Fatalf("by id: %q %q", y, p)
	}
	// Case-insensitive id.
	if y, _ := templateByID(root, "NEXTJS-CACHE-POISONING", ""); y == "" {
		t.Fatal("id match should be case-insensitive")
	}
	// Falls back to the <cve>.yaml filename when the id is unknown.
	if y, _ := templateByID(root, "no-such-id", "CVE-2024-46982"); !strings.Contains(y, "pageProps") {
		t.Fatalf("cve fallback: %q", y)
	}
	// Nothing matches → empty.
	if y, _ := templateByID(root, "nope", "CVE-0000-0000"); y != "" {
		t.Fatalf("unexpected match: %q", y)
	}
}

func TestWithinAny(t *testing.T) {
	base := t.TempDir()
	in := filepath.Join(base, "templates", "a.yaml")
	if !withinAny(in, base) {
		t.Fatal("a child path should be within")
	}
	if withinAny(filepath.Join(base, "..", "etc", "passwd"), base) {
		t.Fatal("a parent-escaping path must be rejected")
	}
	if withinAny("/etc/passwd", base) {
		t.Fatal("an unrelated absolute path must be rejected")
	}
}

// A nuclei finding resolves its template through the path its scan recorded.
func TestNucleiTemplateForFinding(t *testing.T) {
	withTestSQLite(t)
	resDir := utils.GetResultsDir() // "new-results" under the test's temp cwd
	os.MkdirAll(resDir, 0o755)
	tplPath := filepath.Join(resDir, "scanfoo.yaml")
	os.WriteFile(tplPath, []byte(cachePoisonTpl), 0o644)

	if err := db.CreateScan(&db.ScanRecord{ScanID: "s-tpl", ScanType: "nuclei", Target: "global-subdomains",
		Status: "completed", Command: "inprocess:nuclei target=global-subdomains template=" + tplPath}); err != nil {
		t.Fatal(err)
	}
	f := &db.Finding{Title: "Next.js cache poisoning", Host: "clearpools-api.dflow.net", TemplateID: "nextjs-cache-poisoning",
		CVE: "CVE-2024-46982", Module: "nuclei", ScanID: "s-tpl", MatchedAt: "https://clearpools-api.dflow.net/poc?__nextDataReq=1", FKey: "fk-tpl"}
	if err := db.CreateFinding(f); err != nil {
		t.Fatal(err)
	}
	label, yaml := nucleiTemplateForFinding(f)
	if !strings.Contains(yaml, "pageProps") || !strings.Contains(label, "s-tpl") {
		t.Fatalf("resolved: %q %q", label, yaml)
	}
	// A non-template finding (no template id) resolves to nothing.
	if _, y := nucleiTemplateForFinding(&db.Finding{Title: "manual", Host: "h"}); y != "" {
		t.Fatalf("non-template finding returned %q", y)
	}
	// A scan command pointing outside the allowed roots is refused.
	_ = db.CreateScan(&db.ScanRecord{ScanID: "s-evil", ScanType: "nuclei", Status: "completed",
		Command: "inprocess:nuclei target=x template=/etc/hostname"})
	bad := &db.Finding{Title: "evil", Host: "h", TemplateID: "whatever", ScanID: "s-evil", FKey: "fk-evil"}
	_ = db.CreateFinding(bad)
	if _, y := nucleiTemplateForFinding(bad); y != "" {
		t.Fatalf("out-of-root template path must be refused, got %q", y)
	}
}
