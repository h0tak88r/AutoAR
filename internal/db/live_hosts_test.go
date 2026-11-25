package db

import (
	"path/filepath"
	"testing"
)

func TestLiveHostHelpersSQLite(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "live.db"))
	t.Setenv("AUTOAR_SILENT", "true")
	s := &SQLiteDB{}
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := s.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	prev := dbInstance
	SetDB(s)
	t.Cleanup(func() { SetDB(prev) })

	for _, h := range []struct {
		sub  string
		live bool
	}{
		{"a.example.com", true},
		{"b.example.com", false},
		{"c.example.com", true},
		{"d.example.com", true},
	} {
		if err := s.InsertSubdomain("example.com", h.sub, h.live, "", "https://"+h.sub, 0, 200); err != nil {
			t.Fatalf("InsertSubdomain(%s): %v", h.sub, err)
		}
	}

	// Keyset pages of 2 cover every live host exactly once, then end.
	var got []string
	var cursor int64
	for pages := 0; pages < 10; pages++ {
		subs, next, err := ListLiveSubdomainsAfter(cursor, 2)
		if err != nil {
			t.Fatalf("ListLiveSubdomainsAfter: %v", err)
		}
		if len(subs) == 0 {
			break
		}
		if next <= cursor {
			t.Fatalf("cursor did not advance: %d -> %d", cursor, next)
		}
		cursor = next
		for _, g := range subs {
			got = append(got, g.Subdomain)
			if g.BestURL() != "https://"+g.Subdomain {
				t.Errorf("BestURL(%s) = %q", g.Subdomain, g.BestURL())
			}
		}
	}
	if len(got) != 3 || got[0] != "a.example.com" || got[1] != "c.example.com" || got[2] != "d.example.com" {
		t.Fatalf("live hosts = %v, want a, c, d", got)
	}

	live, err := FilterLiveSubdomains([]string{"A.example.com", "b.example.com", "gone.example.org", ""})
	if err != nil {
		t.Fatalf("FilterLiveSubdomains: %v", err)
	}
	if !live["a.example.com"] || live["b.example.com"] || live["gone.example.org"] || len(live) != 1 {
		t.Fatalf("FilterLiveSubdomains = %v, want only a.example.com", live)
	}
}

func TestListLivePHPSubdomains(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "php.db"))
	t.Setenv("AUTOAR_SILENT", "true")
	s := &SQLiteDB{}
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := s.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	prev := dbInstance
	SetDB(s)
	t.Cleanup(func() { SetDB(prev) })

	for _, h := range []struct {
		sub, techs string
		live       bool
	}{
		{"php1.example.com", "Nginx,PHP:8.1.2", true},
		{"php2.example.com", "PHP", true},
		{"java.example.com", "Java,Tomcat", true},
		{"none.example.com", "", true},
		{"phpdead.example.com", "PHP", false}, // not live → excluded
		{"mixed.example.com", "phpMyAdmin", true},
	} {
		if err := s.InsertSubdomain("example.com", h.sub, h.live, "", "https://"+h.sub, 0, 200); err != nil {
			t.Fatalf("Insert(%s): %v", h.sub, err)
		}
		if h.techs != "" {
			if err := s.UpdateSubdomainTech("example.com", h.sub, h.techs); err != nil {
				t.Fatalf("tech(%s): %v", h.sub, err)
			}
		}
	}
	got := map[string]bool{}
	var cursor int64
	for pages := 0; pages < 10; pages++ {
		subs, next, err := ListLivePHPSubdomainsAfter(cursor, 2)
		if err != nil {
			t.Fatalf("ListLivePHPSubdomainsAfter: %v", err)
		}
		if len(subs) == 0 {
			break
		}
		cursor = next
		for _, g := range subs {
			got[g.Subdomain] = true
		}
	}
	// Only LIVE hosts whose techs mention php (case-insensitive), nothing else.
	want := map[string]bool{"php1.example.com": true, "php2.example.com": true, "mixed.example.com": true}
	if len(got) != len(want) {
		t.Fatalf("php-only live hosts = %v, want %v", got, want)
	}
	for w := range want {
		if !got[w] {
			t.Fatalf("missing %s; got %v", w, got)
		}
	}
}
