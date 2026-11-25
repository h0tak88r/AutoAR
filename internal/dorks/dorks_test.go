package dorks

import (
	"strings"
	"testing"
)

func TestLoadCorpus(t *testing.T) {
	db, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if db.Count() < 50 {
		t.Fatalf("corpus too small: %d dorks", db.Count())
	}
	// Every dork must carry the {T} placeholder and list a known platform.
	for _, cat := range db.Categories {
		if cat.Severity == "" {
			t.Errorf("category %q has no severity", cat.ID)
		}
		for _, d := range cat.Dorks {
			if !strings.Contains(d.Query, "{T}") {
				t.Errorf("dork %q has no {T} placeholder: %q", d.Title, d.Query)
			}
			if _, ok := db.Platforms[d.PrimaryPlatform()]; !ok {
				t.Errorf("dork %q uses unknown platform %q", d.Title, d.PrimaryPlatform())
			}
		}
	}
}

func TestBuildURLGoogleNative(t *testing.T) {
	db := &DB{Platforms: map[string]Platform{"google": {URLTemplate: "https://www.google.com/search?q={Q}"}}}
	d := Dork{Platforms: []string{"google"}, Query: `site:{T} ext:env`}
	// Target substituted + encoded.
	got := db.BuildURL(d, "google", "example.com")
	if !strings.Contains(got, "site%3Aexample.com") {
		t.Fatalf("google url = %q", got)
	}
	// Empty target keeps {T} literal (page substitutes).
	keep := db.BuildURL(d, "google", "")
	if !strings.Contains(keep, "{T}") {
		t.Fatalf("expected literal {T}, got %q", keep)
	}
}

func TestBuildURLShodanTemplate(t *testing.T) {
	db := &DB{Platforms: map[string]Platform{"shodan": {URLTemplate: "https://www.shodan.io/search?query={Q}"}}}
	d := Dork{Platforms: []string{"shodan"}, Query: `hostname:"{T}" port:9200`}
	got := db.BuildURL(d, "shodan", "acme.com")
	if !strings.HasPrefix(got, "https://www.shodan.io/search?query=") || strings.Contains(got, "{T}") {
		t.Fatalf("shodan url = %q", got)
	}
	if !strings.Contains(got, "acme.com") {
		t.Fatalf("target not substituted: %q", got)
	}
}

func TestBuildURLFofaBase64(t *testing.T) {
	db := &DB{Platforms: map[string]Platform{"fofa": {URLTemplate: "https://fofa.info/result?qbase64={Q64}"}}}
	d := Dork{Platforms: []string{"fofa"}, Query: `domain="{T}"`}
	got := db.BuildURL(d, "fofa", "acme.com")
	if !strings.HasPrefix(got, "https://fofa.info/result?qbase64=") {
		t.Fatalf("fofa url = %q", got)
	}
	// {Q64} must be base64 of the substituted query, not literal.
	if strings.Contains(got, "{T}") || strings.Contains(got, "domain=") {
		t.Fatalf("fofa query not base64-encoded: %q", got)
	}
}

func TestBuildURLPassthroughFullURL(t *testing.T) {
	db := &DB{Platforms: map[string]Platform{}}
	d := Dork{Platforms: []string{"shodan"}, Query: `https://www.shodan.io/search?query=hostname%3A%22{T}%22`}
	got := db.BuildURL(d, "shodan", "acme.com")
	if got != `https://www.shodan.io/search?query=hostname%3A%22acme.com%22` {
		t.Fatalf("passthrough url = %q", got)
	}
}

func TestResolveFilterAndSubstitute(t *testing.T) {
	db, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	all := db.Resolve(FilterOpts{}, "")
	if len(all) != db.Count() {
		t.Fatalf("Resolve all = %d, want %d", len(all), db.Count())
	}
	// Target substitution leaves no placeholders in query or url.
	for _, r := range db.Resolve(FilterOpts{}, "target.io") {
		if strings.Contains(r.Query, "{T}") {
			t.Fatalf("unsubstituted query: %q", r.Query)
		}
	}
	// Severity filter.
	crit := db.Resolve(FilterOpts{Severity: "critical"}, "")
	if len(crit) == 0 {
		t.Fatal("no critical dorks")
	}
	for _, r := range crit {
		if r.Severity != "critical" {
			t.Fatalf("severity filter leaked %q", r.Severity)
		}
	}
	// Text filter.
	if got := db.Resolve(FilterOpts{Query: "zzz-no-such-dork-zzz"}, ""); len(got) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(got))
	}
}

func TestLegacyGroupedShape(t *testing.T) {
	db, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	g := db.LegacyGrouped()
	total := 0
	for sev, items := range g {
		if sev == "" {
			t.Error("empty severity key")
		}
		for _, it := range items {
			total++
			primary := "google"
			if len(it.Platforms) > 0 {
				primary = it.Platforms[0]
			}
			// Non-google items must be full URLs; google items stay raw queries.
			if primary == "google" {
				if isHTTPURL(it.Query) {
					t.Errorf("google dork should stay raw: %q", it.Query)
				}
			} else if !isHTTPURL(it.Query) {
				t.Errorf("%s dork should be a full URL: %q", primary, it.Query)
			}
		}
	}
	if total != db.Count() {
		t.Fatalf("legacy total %d != count %d", total, db.Count())
	}
}

func TestSanitizeTarget(t *testing.T) {
	cases := map[string]string{
		"https://example.com/path?x=1": "example.com",
		"  Acme.COM  ":                 "Acme.COM",
		"":                             "example.com",
		"http://a.b.c/":                "a.b.c",
	}
	for in, want := range cases {
		if got := SanitizeTarget(in); got != want {
			t.Errorf("SanitizeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}
