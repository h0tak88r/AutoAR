package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// fakeCatalog stands in for the catalog: domain rows keyed by the exact
// catalog entry, programs searchable by keyword.
func fakeCatalog(t *testing.T, domains map[string][]db.CatalogDomainMatch, programs []db.CatalogProgram) {
	t.Helper()
	oD, oK := catalogByDomain, catalogByKeyword
	t.Cleanup(func() {
		catalogByDomain, catalogByKeyword = oD, oK
		hostProgramMu.Lock()
		hostProgramCache = map[string]hostProgramEntry{}
		hostProgramMu.Unlock()
	})
	hostProgramMu.Lock()
	hostProgramCache = map[string]hostProgramEntry{}
	hostProgramMu.Unlock()
	catalogByDomain = func(q string, limit int) ([]db.CatalogDomainMatch, error) {
		host := db.NormalizeCatalogHost(q)
		var rows []db.CatalogDomainMatch
		labels := strings.Split(host, ".")
		for i := 0; i+2 <= len(labels); i++ {
			s := strings.Join(labels[i:], ".")
			rows = append(rows, domains[s]...)
			rows = append(rows, domains["*."+s]...)
		}
		return db.ClassifyCatalogMatches(host, rows, limit), nil
	}
	catalogByKeyword = func(q string, limit int) ([]db.CatalogProgram, error) {
		var out []db.CatalogProgram
		for _, p := range programs {
			if strings.Contains(strings.ToLower(p.Company), strings.ToLower(q)) || strings.Contains(strings.ToLower(p.Handle), strings.ToLower(q)) {
				out = append(out, p)
			}
		}
		return out, nil
	}
}

func dm(id int64, source, handle, entry string, in bool) db.CatalogDomainMatch {
	return db.CatalogDomainMatch{CatalogProgram: db.CatalogProgram{ID: id, Source: source, Handle: handle, Company: handle},
		MatchedDomain: entry, InScope: in}
}

func TestResolveHostProgram(t *testing.T) {
	withTestSQLite(t)
	fakeCatalog(t, map[string][]db.CatalogDomainMatch{
		"*.acme.com":       {dm(1, "h1", "acme", "*.acme.com", true)},
		"legacy.acme.com":  {dm(1, "h1", "acme", "legacy.acme.com", false)},
		"aliexpress.com":   {dm(2, "h1", "alibaba", "aliexpress.com", true)},
		"*.shop.globex.io": {dm(3, "as93", "globex", "*.shop.globex.io", true)},
	}, []db.CatalogProgram{
		{ID: 4, Source: "bc", Handle: "originenergy", Company: "Origin Energy", OffersBounty: true},
		{ID: 5, Source: "h1", Handle: "originenergyfans", Company: "Origin Energy Fans"},
		{ID: 6, Source: "ywh", Handle: "blablacar-bbp", Company: "BlaBlaCar", OffersBounty: true},
		{ID: 7, Source: "h1", Handle: "carta", Company: "Carta"},
	})
	for host, want := range map[string]string{
		"api.acme.com":                            "in h1 acme",              // wildcard
		"legacy.acme.com":                         "out h1 acme",             // exact out-of-scope entry wins
		"888kiss.aliexpress.com":                  "related h1 alibaba",      // only the root is listed
		"https://spike-app.originenergy.com.au/x": "guess bc originenergy",   // named like the root
		"newsroom.blablacar.fr":                   "guess ywh blablacar-bbp", // handle = name + separator
		"api.carta.example.io":                    "",                        // root name "example": no program called that
		"x.io":                                    "",                        // name too short to guess
		"nothing.unknown-corp.com":                "",
	} {
		hp := resolveHostProgram(host)
		got := strings.TrimSpace(hp.Match + " " + hp.Label())
		if got != want {
			t.Errorf("%s: %q, want %q", host, got, want)
		}
	}
	// The aggregator source carries the real platform only in its URL.
	if p, h := catalogPlatform("as93", "globex", "https://bugcrowd.com/globex"); p != "bc" || h != "globex" {
		t.Errorf("as93 → %s %s", p, h)
	}
	if p, _ := catalogPlatform("as93", "x", "https://immunefi.com/bounty/x"); p != "immunefi" {
		t.Errorf("immunefi → %s", p)
	}
	// "originenergyfans" must not stand in for originenergy (no separator).
	if _, progs := rootNamePrograms("a.originenergy.com.au"); len(progs) != 1 || progs[0].Handle != "originenergy" {
		t.Errorf("name match too loose: %+v", progs)
	}
}

func TestProgramLookupRootFallback(t *testing.T) {
	withTestSQLite(t)
	fakeCatalog(t, nil, []db.CatalogProgram{{ID: 1, Source: "h1", Handle: "aliexpress", Company: "AliExpress", OffersBounty: true}})
	r := findingsRouter()
	r.GET("/api/assets/program-lookup", apiProgramLookup)
	// SearchCatalogByDomain in the endpoint is the real one (empty catalog);
	// the fallback uses the keyword seam.
	w, out := doJSON(r, http.MethodGet, "/api/assets/program-lookup?q=888kiss.aliexpress.com", "")
	if w.Code != http.StatusOK || out["root"] != "aliexpress.com" {
		t.Fatalf("%d %v", w.Code, out)
	}
	res := out["results"].([]any)
	if len(res) == 0 || res[0].(map[string]any)["match_kind"] != "guess" || res[0].(map[string]any)["handle"] != "aliexpress" {
		t.Fatalf("results: %v", res)
	}
	if _, ok := res[0].(map[string]any)["in_scope"]; ok {
		t.Fatal("a name match must not carry an in-scope verdict")
	}
}

func TestProgramLookupShowsAccounts(t *testing.T) {
	withTestSQLite(t)
	if _, err := db.UpsertCatalogProgram(db.CatalogProgram{Source: "h1", Handle: "datagrail", Company: "Datagrail",
		URL: "https://hackerone.com/datagrail", OffersBounty: true}); err != nil {
		t.Fatal(err)
	}
	_ = db.SetSetting("bbp_program_accounts", `{"h1|datagrail":["0x88","Samii"]}`)
	progAcctMu.Lock()
	progAcctCache, progAcctAt = nil, time.Time{}
	progAcctMu.Unlock()

	r := findingsRouter()
	r.GET("/api/assets/program-lookup", apiProgramLookup)
	w, out := doJSON(r, http.MethodGet, "/api/assets/program-lookup?q=datagrail&mode=keyword", "")
	if w.Code != http.StatusOK {
		t.Fatalf("code %d", w.Code)
	}
	res := out["results"].([]any)
	if len(res) == 0 {
		t.Fatal("no results")
	}
	accts, _ := res[0].(map[string]any)["accounts"].([]any)
	if len(accts) != 2 || accts[0] != "0x88" || accts[1] != "Samii" {
		t.Fatalf("accounts on lookup result: %v", res[0])
	}
}

func TestFindingProgramBackfill(t *testing.T) {
	withTestSQLite(t)
	fakeCatalog(t, map[string][]db.CatalogDomainMatch{
		"aliexpress.com": {dm(2, "h1", "alibaba", "aliexpress.com", true)},
	}, nil)
	for _, f := range []*db.Finding{
		{Title: "a", Host: "888kiss.aliexpress.com", FKey: "k1"},
		{Title: "b", Host: "hoomall.aliexpress.com", FKey: "k2"},
		{Title: "c", Host: "nowhere.example.org", FKey: "k3"},
		{Title: "d", Host: "set.aliexpress.com", FKey: "k4", Platform: "ywh", Program: "mine"},
	} {
		if err := db.CreateFinding(f); err != nil {
			t.Fatal(err)
		}
	}
	filled, checked := backfillFindingPrograms()
	if filled != 2 || checked != 3 {
		t.Fatalf("filled %d of %d", filled, checked)
	}
	rows, _, _ := db.ListFindings(db.FindingFilter{Limit: 10})
	got := map[string]string{}
	for _, f := range rows {
		got[f.Title] = f.Platform + " " + f.Program + " " + f.ProgramMatch
	}
	if got["a"] != "h1 alibaba related" || got["b"] != "h1 alibaba related" || got["c"] != "  " || got["d"] != "ywh mine " {
		t.Fatalf("after backfill: %v", got)
	}
}

func TestAttachProgramURLs(t *testing.T) {
	withTestSQLite(t)
	for _, p := range []db.CatalogProgram{
		{Source: "h1", Handle: "alibaba", URL: "https://hackerone.com/alibaba"},
		{Source: "as93", Handle: "alibaba", URL: "https://security.alibaba.com/"},
		{Source: "ywh", Handle: "edf", URL: "https://api.yeswehack.com/programs/edf"},
		{Source: "h1", Handle: "evil", URL: "javascript:alert(1)"},
		{Source: "it", Handle: "fortnox", URL: "https://app.intigriti.com/researcher/programs/fortnox/fortnox/detail"},
		{Source: "bc", Handle: "epam-mbb-og", Company: "EPAM", URL: "https://bugcrowd.com/engagements/epam-mbb-og"},
	} {
		if _, err := db.UpsertCatalogProgram(p); err != nil {
			t.Fatal(err)
		}
	}
	rows := []*db.Finding{
		{Platform: "h1", Program: "Alibaba"},
		{Platform: "other", Program: "alibaba"},
		{Platform: "ywh", Program: "edf"},
		{Platform: "bc", Program: "epam"},     // short handle → the real epam-mbb-og engagement URL
		{Platform: "h1", Program: "evil"},     // a non-http catalog URL is never used
		{Platform: "it", Program: "fortnox"},  // only the catalog knows Intigriti URLs
		{Platform: "it", Program: "unlisted"}, // ... so no link
		{Platform: "bc", Program: "nosuch"},   // no catalog match → no fabricated engagements/ link
		{AI: &db.FindingAI{ScopeProgram: "h1 sea (in scope)"}},
		{},
	}
	// Which accounts can see each program (catalog-sync blob).
	_ = db.SetSetting("bbp_program_accounts", `{"h1|alibaba":["0x88","Samii"],"bc|epam-mbb-og":["h0x88"]}`)
	progAcctMu.Lock()
	progAcctCache, progAcctAt = nil, time.Time{}
	progAcctMu.Unlock()
	attachProgramURLs(rows...)
	if got := strings.Join(rows[0].ProgramAccounts, ","); got != "0x88,Samii" {
		t.Errorf("alibaba accounts = %q", got)
	}
	if got := strings.Join(rows[3].ProgramAccounts, ","); got != "h0x88" {
		t.Errorf("epam (short handle) accounts = %q, want h0x88 via epam-mbb-og", got)
	}
	if len(rows[2].ProgramAccounts) != 0 {
		t.Errorf("edf has no blob entry, want no accounts, got %v", rows[2].ProgramAccounts)
	}
	want := []string{
		"https://hackerone.com/alibaba",
		"https://security.alibaba.com/",
		"https://yeswehack.com/programs/edf",
		"https://bugcrowd.com/engagements/epam-mbb-og",
		"https://hackerone.com/evil",
		"https://app.intigriti.com/researcher/programs/fortnox/fortnox/detail",
		"",
		"",
		"https://hackerone.com/sea",
		"",
	}
	for i, f := range rows {
		if f.ProgramURL != want[i] {
			t.Errorf("row %d (%s %s): %q, want %q", i, f.Platform, f.Program, f.ProgramURL, want[i])
		}
	}
}
