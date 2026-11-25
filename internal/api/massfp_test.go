package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/h0tak88r/AutoAR/internal/db"
)

func TestSuspectFPTallyPath(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "nuclei-test.json")
	os.WriteFile(f, []byte(
		`{"template-id":"CVE-2026-11111","host":"a.example.com"}`+"\n"+
			`{"template-id":"CVE-2026-11111","host":"b.example.com"}`+"\n"+
			`{"template-id":"real-template","host":"c.example.com"}`+"\n"), 0o644)

	tally := suspectFPTallyPath(f)
	if tally["CVE-2026-11111"] != 2 || tally["real-template"] != 1 {
		t.Fatalf("tally = %v", tally)
	}
	if got := suspectFPTallyPath(filepath.Join(dir, "missing.json")); got != nil {
		t.Fatalf("missing file must return nil, got %v", got)
	}
}

func TestSuspectFPFilter(t *testing.T) {
	ts := []pdcpTemplate{{ID: "keep-me"}, {ID: "drop-me"}}
	if got := suspectFPFilter(nil, ts); len(got) != 2 {
		t.Fatalf("no suspects should keep all, got %d", len(got))
	}
	got := suspectFPFilter(map[string]bool{"drop-me": true}, ts)
	if len(got) != 1 || got[0].ID != "keep-me" {
		t.Fatalf("filtered = %v", got)
	}
}

// TestSuspectFPRevisionKeyed: a verdict on one revision (id@hash) must not
// exclude a fixed re-publish of the same template ID.
func TestSuspectFPRevisionKeyed(t *testing.T) {
	broken := pdcpTemplate{ID: "CVE-2026-7", Raw: "id: CVE-2026-7\n# broken matcher\n"}
	fixed := pdcpTemplate{ID: "CVE-2026-7", Raw: "id: CVE-2026-7\n# fixed matcher\n"}
	suspects := map[string]bool{nucleiTemplateRevKey(broken.ID, broken.Raw): true}
	if got := suspectFPFilter(suspects, []pdcpTemplate{broken}); len(got) != 0 {
		t.Error("flagged revision must be excluded")
	}
	if got := suspectFPFilter(suspects, []pdcpTemplate{fixed}); len(got) != 1 {
		t.Error("a fixed revision of a flagged template ID must auto-run again")
	}
}

// TestSuspectFPTallyCountsDistinctHosts: one host hit by several matchers /
// paths is ONE host, not N events.
func TestSuspectFPTallyCountsDistinctHosts(t *testing.T) {
	f := filepath.Join(t.TempDir(), "nuclei-x.json")
	os.WriteFile(f, []byte(
		`{"template-id":"T","host":"https://a.example.com","matched-at":"https://a.example.com/1"}`+"\n"+
			`{"template-id":"T","host":"https://a.example.com","matched-at":"https://a.example.com/2"}`+"\n"+
			`{"template-id":"T","host":"a.example.com:443","matched-at":"https://a.example.com/3"}`+"\n"+
			`{"template-id":"T","host":"https://b.example.com","matched-at":"https://b.example.com/"}`+"\n"), 0o644)
	if got := suspectFPTallyPath(f)["T"]; got != 2 {
		t.Fatalf("distinct hosts = %d, want 2", got)
	}
}

func TestSuspectFPScaledThreshold(t *testing.T) {
	cases := []struct {
		base       int
		pct        float64
		hosts, out int
	}{
		{100, 2, 300, 100},      // small corpus: floor applies
		{100, 2, 430000, 8600},  // large corpus: 2%
		{100, 0, 430000, 100},   // pct 0 = flat threshold
		{5000, 2, 100000, 5000}, // explicit base above the scaled value
		{100, 0.1, 430000, 430}, // operator-tuned percentage
	}
	for _, c := range cases {
		if got := suspectFPScaledThreshold(c.base, c.pct, c.hosts); got != c.out {
			t.Errorf("suspectFPScaledThreshold(%d, %.1f, %d) = %d, want %d", c.base, c.pct, c.hosts, got, c.out)
		}
	}
}

func TestSuspectFPThresholdDefault(t *testing.T) {
	if got := suspectFPThreshold(); got != suspectFPDefault {
		t.Fatalf("threshold default = %d, want %d", got, suspectFPDefault)
	}
}

func TestRaceScopeTag(t *testing.T) {
	if got := raceScopeTag(nil); got != "⚪ no program match" {
		t.Errorf("no-program tag = %q", got)
	}
	if got := raceScopeTag([]db.CatalogDomainMatch{testCatalogMatch("h1", "acme", true)}); got != "🟢 IN SCOPE — h1 `acme`" {
		t.Errorf("in-scope tag = %q", got)
	}
	if got := raceScopeTag([]db.CatalogDomainMatch{testCatalogMatch("ywh", "other", false)}); got != "🔴 catalog OOS — ywh `other`" {
		t.Errorf("oos tag = %q", got)
	}
}

func testCatalogMatch(source, handle string, in bool) db.CatalogDomainMatch {
	m := db.CatalogDomainMatch{InScope: in}
	m.Source = source
	m.Handle = handle
	return m
}
