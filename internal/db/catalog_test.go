package db

import (
	"path/filepath"
	"testing"
	"time"
)

func newCatalogTestDB(t *testing.T) *SQLiteDB {
	t.Helper()
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "catalog.db"))
	t.Setenv("AUTOAR_SILENT", "true")
	s := &SQLiteDB{}
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := s.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return s
}

// C10: on the ON CONFLICT DO UPDATE path SQLite's LastInsertId is the
// connection's previous insert — re-upserting alpha used to return beta's id.
func TestSQLiteUpsertsReturnOwnID(t *testing.T) {
	s := newCatalogTestDB(t)
	s.db.SetMaxOpenConns(1) // one connection: LastInsertId staleness is deterministic
	a, _ := s.UpsertCatalogProgram(CatalogProgram{Source: "h1", Handle: "alpha"})
	b, _ := s.UpsertCatalogProgram(CatalogProgram{Source: "h1", Handle: "beta"})
	again, err := s.UpsertCatalogProgram(CatalogProgram{Source: "h1", Handle: "alpha", Company: "Alpha"})
	if err != nil || a == b || again != a {
		t.Fatalf("catalog upsert ids alpha=%d beta=%d re-upsert(alpha)=%d err=%v", a, b, again, err)
	}

	h1, _ := s.AddHunterMonitorTarget("alice", 60)
	h2, _ := s.AddHunterMonitorTarget("bob", 60)
	h1b, err := s.AddHunterMonitorTarget("alice", 120)
	if err != nil || h1 == h2 || h1b != h1 {
		t.Fatalf("hunter upsert ids alice=%d bob=%d re-upsert(alice)=%d err=%v", h1, h2, h1b, err)
	}

	x, _ := s.UpsertBBPAccount(BBPAccount{Platform: "h1", Label: "x", Token: "t1", Enabled: true})
	y, _ := s.UpsertBBPAccount(BBPAccount{Platform: "h1", Label: "y", Token: "t2", Enabled: true})
	x2, err := s.UpsertBBPAccount(BBPAccount{Platform: "h1", Label: "x", Token: "t3", Enabled: true})
	if err != nil || x == y || x2 != x {
		t.Fatalf("account upsert ids x=%d y=%d re-upsert(x)=%d err=%v", x, y, x2, err)
	}
}

func TestCatalogDomainSearchExactAndWildcard(t *testing.T) {
	s := newCatalogTestDB(t)
	SetDB(s)
	t.Cleanup(func() { SetDB(nil) })

	err := ReplaceCatalogSource("h1", []CatalogSourceProgram{
		{Program: CatalogProgram{Handle: "acme", Company: "Acme"}, Domains: []CatalogDomain{
			{Domain: "app.acme.com", InScope: true},
			{Domain: "*.api.acme.com", InScope: true},
			{Domain: "status.acme.com", InScope: false},
		}},
		{Program: CatalogProgram{Handle: "example", Company: "Example"}, Domains: []CatalogDomain{
			{Domain: "example.com", InScope: true},
			{Domain: "*.example.com", InScope: true},
			{Domain: "*.legacy.example.com", InScope: false},
		}},
		{Program: CatalogProgram{Handle: "notexample", Company: "NotExample"}, Domains: []CatalogDomain{
			{Domain: "notexample.com", InScope: true},
			{Domain: "example.com.evil.io", InScope: true},
		}},
	})
	if err != nil {
		t.Fatalf("ReplaceCatalogSource: %v", err)
	}

	type want struct {
		handle, kind string
		in           bool
	}
	cases := map[string][]want{
		"app.acme.com":             {{"acme", CatalogMatchExact, true}},
		"v2.api.acme.com":          {{"acme", CatalogMatchWildcard, true}},
		"status.acme.com":          {{"acme", CatalogMatchExact, false}}, // explicitly OOS
		"x.acme.com":               nil,                                  // app.acme.com-only program: not covered
		"example.com":              {{"example", CatalogMatchExact, true}},
		"api.example.com":          {{"example", CatalogMatchWildcard, true}},  // parent walk finds *.example.com
		"old.legacy.example.com":   {{"example", CatalogMatchWildcard, false}}, // OOS wildcard beats in-scope wildcard
		"https://Example.com/path": {{"example", CatalogMatchExact, true}},
	}
	for q, wants := range cases {
		got, err := SearchCatalogByDomain(q, 20)
		if err != nil {
			t.Fatalf("search %q: %v", q, err)
		}
		var covering []CatalogDomainMatch
		for _, m := range got {
			if m.MatchKind != CatalogMatchRelated {
				covering = append(covering, m)
			}
		}
		if len(covering) != len(wants) {
			t.Errorf("search %q: covering=%+v want %+v", q, covering, wants)
			continue
		}
		for i, w := range wants {
			m := covering[i]
			if m.Handle != w.handle || m.MatchKind != w.kind || m.InScope != w.in {
				t.Errorf("search %q[%d] = %s/%s/in=%v, want %s/%s/in=%v", q, i, m.Handle, m.MatchKind, m.InScope, w.handle, w.kind, w.in)
			}
		}
	}
	// A host under an exact-only listing is related, never in scope.
	got, _ := SearchCatalogByDomain("deep.app.acme.com", 20)
	if len(got) != 1 || got[0].MatchKind != CatalogMatchRelated || got[0].InScope {
		t.Errorf("deep.app.acme.com should be related-only, got %+v", got)
	}
	// LIKE metacharacters in keyword search are literal.
	if kw, _ := SearchCatalogByKeyword("%", 50); len(kw) != 0 {
		t.Errorf("keyword %% matched %d programs, want 0", len(kw))
	}
}

// Infra-11 / C8 plumbing: a source replace is atomic and counted, and the
// cross-process lease admits one holder at a time.
func TestCatalogSourceReplaceAndLock(t *testing.T) {
	s := newCatalogTestDB(t)
	SetDB(s)
	t.Cleanup(func() { SetDB(nil) })

	if err := ReplaceCatalogSource("ywh", []CatalogSourceProgram{
		{Program: CatalogProgram{Handle: "a"}, Domains: []CatalogDomain{{Domain: "a.com", InScope: true}}},
		{Program: CatalogProgram{Handle: "b"}, Domains: []CatalogDomain{{Domain: "b.com", InScope: true}}},
	}); err != nil {
		t.Fatal(err)
	}
	if n, _ := CatalogSourceCount("ywh"); n != 2 {
		t.Fatalf("count = %d, want 2", n)
	}
	if err := ReplaceCatalogSource("ywh", []CatalogSourceProgram{
		{Program: CatalogProgram{Handle: "c"}, Domains: []CatalogDomain{{Domain: "c.com", InScope: true}}},
	}); err != nil {
		t.Fatal(err)
	}
	if n, _ := CatalogSourceCount("ywh"); n != 1 {
		t.Fatalf("count after replace = %d, want 1", n)
	}
	if _, doms, _ := s.CatalogCounts(); doms != 1 {
		t.Fatalf("domains after replace = %d, want 1 (cascade)", doms)
	}

	rel, ok, err := TryCatalogSyncLock(time.Hour)
	if err != nil || !ok {
		t.Fatalf("first lock: ok=%v err=%v", ok, err)
	}
	if _, ok2, _ := TryCatalogSyncLock(time.Hour); ok2 {
		t.Fatal("second lock must fail while the first is held")
	}
	rel()
	rel2, ok3, _ := TryCatalogSyncLock(time.Hour)
	if !ok3 {
		t.Fatal("lock must be free after release")
	}
	rel2()
	// An expired lease is taken over.
	if _, ok4, _ := TryCatalogSyncLock(-time.Second); !ok4 {
		t.Fatal("lock with negative ttl")
	}
	if _, ok5, _ := TryCatalogSyncLock(time.Hour); !ok5 {
		t.Fatal("expired lease must be taken over")
	}
}

func TestClassifyCatalogMatchesRelatedAndPrecedence(t *testing.T) {
	row := func(id int64, handle, dom string, in bool) CatalogDomainMatch {
		m := CatalogDomainMatch{MatchedDomain: dom, InScope: in}
		m.ID, m.Handle = id, handle
		return m
	}
	got := ClassifyCatalogMatches("x.acme.com", []CatalogDomainMatch{
		row(1, "parent-only", "acme.com", true),
		row(2, "wild", "*.acme.com", true),
		row(3, "excl", "*.acme.com", true),
		row(3, "excl", "x.acme.com", false),
	}, 10)
	if len(got) != 3 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Handle != "wild" || !got[0].InScope || got[0].MatchKind != CatalogMatchWildcard {
		t.Errorf("first = %+v, want wild in-scope wildcard", got[0])
	}
	if got[1].Handle != "excl" || got[1].InScope || got[1].MatchKind != CatalogMatchExact {
		t.Errorf("second = %+v, want excl OOS exact", got[1])
	}
	if got[2].Handle != "parent-only" || got[2].InScope || got[2].MatchKind != CatalogMatchRelated {
		t.Errorf("third = %+v, want parent-only related", got[2])
	}
	if NormalizeCatalogHost("https://User@API.Example.com:8443/x?y") != "api.example.com" {
		t.Error("NormalizeCatalogHost")
	}
	if NormalizeCatalogHost("%") != "" || NormalizeCatalogHost("localhost") != "" {
		t.Error("NormalizeCatalogHost must reject non-hosts")
	}
}
