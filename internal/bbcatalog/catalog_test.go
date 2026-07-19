package bbcatalog

import (
	"path/filepath"
	"testing"

	"github.com/h0tak88r/AutoAR/internal/db"
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
