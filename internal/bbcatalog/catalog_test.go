package bbcatalog

import (
	"path/filepath"
	"testing"

	"github.com/h0tak88r/AutoAR/internal/db"
	bbscope "github.com/sw33tLie/bbscope/pkg/scope"
)

func TestHasBountyFiltersVDPs(t *testing.T) {
	cases := []struct {
		rewards []string
		want    bool
	}{
		{[]string{"*bounty"}, true},
		{[]string{"*recognition"}, false}, // VDP
		{[]string{"*swag"}, false},        // swag-only, not a cash bounty
		{nil, false},                      // no reward info
		{[]string{"*recognition", "*bounty"}, true},
	}
	for _, c := range cases {
		if got := hasBounty(c.rewards); got != c.want {
			t.Errorf("hasBounty(%v)=%v want %v", c.rewards, got, c.want)
		}
	}
}

func TestHandleFromURL(t *testing.T) {
	cases := map[string]string{
		"https://hackerone.com/acme":            "acme",
		"https://bugcrowd.com/acme":             "acme",
		"https://yeswehack.com/programs/acme-x": "acme-x",
		// Intigriti URLs end in a literal "detail" segment (C9: every IT
		// program used to collapse into one "detail" row).
		"https://app.intigriti.com/researcher/programs/acmecorp/acme-bbp/detail":  "acme-bbp",
		"https://app.intigriti.com/researcher/programs/acmecorp/acme-bbp/detail/": "acme-bbp",
		"https://app.intigriti.com/researcher/programs/acmecorp//other//detail":   "other",
	}
	for u, want := range cases {
		if got := handleFromURL(u); got != want {
			t.Errorf("handleFromURL(%q)=%q want %q", u, got, want)
		}
	}
}

func TestCatalogSearchInOutScope(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cat.db")
	t.Setenv("AUTOAR_SILENT", "true")
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", dbPath)
	if err := db.EnsureSchema(); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	// as93 program (keyword-only, no domains)
	if _, err := db.UpsertCatalogProgram(db.CatalogProgram{Source: "as93", Company: "Acme Corp", Handle: "acme", URL: "https://acme.com/security", OffersBounty: true}); err != nil {
		t.Fatalf("upsert as93: %v", err)
	}
	// h1 program with in + out-of-scope domains
	id2, err := db.UpsertCatalogProgram(db.CatalogProgram{Source: "h1", Company: "Acme", Handle: "acme-h1", URL: "https://hackerone.com/acme-h1", OffersBounty: true})
	if err != nil {
		t.Fatalf("upsert h1: %v", err)
	}
	if err := db.ReplaceCatalogDomains(id2, []db.CatalogDomain{{Domain: "acme.com", InScope: true}, {Domain: "staging.acme.io", InScope: false}}); err != nil {
		t.Fatalf("replace domains: %v", err)
	}

	// keyword search hits both programs
	if kw, _ := db.SearchCatalogByKeyword("acme", 50); len(kw) < 2 {
		t.Fatalf("keyword 'acme' = %d; want >= 2", len(kw))
	}

	// domain search: in-scope
	dm, _ := db.SearchCatalogByDomain("acme.com", 50)
	if len(dm) == 0 || !dm[0].InScope {
		t.Fatalf("acme.com should match IN-SCOPE; got %+v", dm)
	}
	// domain search: out-of-scope flagged correctly
	oos, _ := db.SearchCatalogByDomain("staging.acme.io", 50)
	if len(oos) == 0 || oos[0].InScope {
		t.Fatalf("staging.acme.io should match OUT-OF-SCOPE; got %+v", oos)
	}

	// clear a source
	if err := db.ClearCatalogSource("as93"); err != nil {
		t.Fatalf("clear: %v", err)
	}
	kw2, _ := db.SearchCatalogByKeyword("acme", 50)
	for _, p := range kw2 {
		if p.Source == "as93" {
			t.Fatalf("as93 rows should be cleared; found %+v", p)
		}
	}
}

// C8: a source is never replaced by an empty fetch or one under half its size.
func TestReplaceAllowed(t *testing.T) {
	cases := []struct {
		prev, next int
		want       bool
	}{
		{0, 0, false},   // nothing fetched
		{217, 0, false}, // bbscope 401 → nil,nil must not wipe 217 programs
		{0, 5, true},    // first sync
		{100, 50, true},
		{100, 49, false},
		{100, 150, true},
	}
	for _, c := range cases {
		if got := replaceAllowed(c.prev, c.next); got != c.want {
			t.Errorf("replaceAllowed(%d,%d) = %v, want %v", c.prev, c.next, got, c.want)
		}
	}
	t.Setenv("CATALOG_SYNC_FORCE", "true")
	if !replaceAllowed(100, 10) || replaceAllowed(100, 0) {
		t.Error("CATALOG_SYNC_FORCE overrides the ratio but never allows an empty replace")
	}
}

func TestPlatformCatalogProgramsMergesAndKeepsHosts(t *testing.T) {
	progs := platformCatalogPrograms([]bbscope.ProgramData{
		{Url: "https://app.intigriti.com/researcher/programs/acme/acme-bbp/detail", InScope: []bbscope.ScopeElement{
			{Target: "app.acme.com", Category: "Url"},
			{Target: "*.api.acme.com", Category: "Wildcard"},
		}},
		{Url: "https://app.intigriti.com/researcher/programs/other/other-bbp/detail", InScope: []bbscope.ScopeElement{
			{Target: "other.io", Category: "Url"},
		}},
		// The same program seen by a second account, with an exclusion.
		{Url: "https://app.intigriti.com/researcher/programs/acme/acme-bbp/detail",
			InScope:    []bbscope.ScopeElement{{Target: "app.acme.com", Category: "Url"}},
			OutOfScope: []bbscope.ScopeElement{{Target: "status.acme.com", Category: "Url"}}},
	})
	if len(progs) != 2 {
		t.Fatalf("programs = %+v, want 2 (merged by handle)", progs)
	}
	got := map[string]bool{}
	for _, d := range progs[0].Domains {
		got[d.Domain] = d.InScope
	}
	want := map[string]bool{"app.acme.com": true, "*.api.acme.com": true, "status.acme.com": false}
	if progs[0].Program.Handle != "acme-bbp" || len(got) != len(want) {
		t.Fatalf("acme-bbp = %+v", progs[0])
	}
	for d, in := range want {
		if g, ok := got[d]; !ok || g != in {
			t.Errorf("%s = %v,%v want %v", d, g, ok, in)
		}
	}
	if _, widened := got["acme.com"]; widened {
		t.Error("specific hosts must not be widened to the registrable root")
	}
}

func TestTailBufferKeepsLastBytes(t *testing.T) {
	tb := NewTailBuffer(8)
	tb.Write([]byte("hello "))
	tb.Write([]byte("world"))
	if got := tb.String(); got != "…lo world" {
		t.Errorf("tail = %q", got)
	}
	tb.Write([]byte("0123456789fatal"))
	if got := tb.String(); got != "…789fatal" {
		t.Errorf("tail after big write = %q", got)
	}
	if LastLine("a\nb\nlog.Fatal: Invalid auth token\n", 0) != "log.Fatal: Invalid auth token" {
		t.Error("LastLine")
	}
}
