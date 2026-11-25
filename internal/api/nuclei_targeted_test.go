package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/h0tak88r/AutoAR/internal/db"
)

func TestTemplateTechKeywords(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "wp.yaml"), []byte("id: wp-cve\ninfo:\n  name: x\n  tags: cve,cve2026,wordpress,rce\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "jira.yml"), []byte(`id: jira-x
info:
  tags: ["jira","atlassian","sqli"]
`), 0o644)
	os.WriteFile(filepath.Join(dir, "note.txt"), []byte("tags: ignored\n"), 0o644)

	got := map[string]bool{}
	for _, k := range templateTechKeywords(dir) {
		got[k] = true
	}
	// Product tags kept; class tags (cve/rce/sqli) dropped.
	for _, want := range []string{"wordpress", "jira", "atlassian"} {
		if !got[want] {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	for _, no := range []string{"cve", "cve2026", "rce", "sqli", "ignored"} {
		if got[no] {
			t.Errorf("should have dropped %q", no)
		}
	}
	// A single file, and raw YAML, both work.
	if ks := templateTechKeywords(filepath.Join(dir, "wp.yaml")); len(ks) != 1 || ks[0] != "wordpress" {
		t.Fatalf("single file: %v", ks)
	}
	if ks := templateTechKeywords("id: x\ninfo:\n  tags: grafana, cve\n"); len(ks) != 1 || ks[0] != "grafana" {
		t.Fatalf("raw yaml: %v", ks)
	}
}

func TestBatchesFromHosts(t *testing.T) {
	hosts := []string{"https://a", "https://b", "https://c", "https://d", "https://e"}
	b, err := batchesFromHosts(hosts, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer b.remove()
	if len(b.files) != 3 || b.total != 5 || b.hosts[0] != 2 || b.hosts[2] != 1 {
		t.Fatalf("batches: files=%d total=%d hosts=%v", len(b.files), b.total, b.hosts)
	}
	raw, _ := os.ReadFile(b.files[0])
	if strings.TrimSpace(string(raw)) != "https://a\nhttps://b" {
		t.Fatalf("batch 0: %q", raw)
	}
}

func TestFingerprintedHostURLs(t *testing.T) {
	withTestSQLite(t)
	for _, h := range []struct{ sub, techs string }{
		{"wp1.example.com", "WordPress,PHP"},
		{"wp2.example.com", "nginx,WordPress"},
		{"j1.example.com", "Java,Tomcat"},
	} {
		if err := db.InsertSubdomain("example.com", h.sub, true, "", "https://"+h.sub, 0, 200); err != nil {
			t.Fatal(err)
		}
		_ = db.UpdateSubdomainTech("example.com", h.sub, h.techs)
	}
	urls, err := fingerprintedHostURLs([]string{"wordpress"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 2 || urls[0] != "https://wp1.example.com" {
		t.Fatalf("wordpress hosts: %v", urls)
	}
	if u, _ := fingerprintedHostURLs([]string{"drupal"}, 100); len(u) != 0 {
		t.Fatalf("no drupal hosts expected: %v", u)
	}
	if u, _ := fingerprintedHostURLs(nil, 100); len(u) != 0 {
		t.Fatalf("no keywords → no hosts: %v", u)
	}
}
