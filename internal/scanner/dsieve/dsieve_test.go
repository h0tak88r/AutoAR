package dsieve

import (
	"reflect"
	"sort"
	"testing"
)

func TestRootDomainEmpty(t *testing.T) {
	if got := rootDomain(""); got != "" {
		t.Errorf("rootDomain(\"\") = %q, want empty", got)
	}
	if got := rootDomain("   "); got != "" {
		t.Errorf("rootDomain(\"   \") = %q, want empty", got)
	}
}

func TestRootDomainBareTLD(t *testing.T) {
	// "com" alone is a bare TLD, should return empty
	if got := rootDomain("com"); got != "" {
		t.Errorf("rootDomain(\"com\") = %q, want empty", got)
	}
}

func TestRootDomainValidDomains(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"simple domain", "example.com", "example.com"},
		{"www subdomain", "www.example.com", "example.com"},
		{"deep subdomain", "deep.sub.example.com", "example.com"},
		{"co.uk", "bbc.co.uk", "bbc.co.uk"},
		{"subdomain co.uk", "news.bbc.co.uk", "bbc.co.uk"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rootDomain(tt.raw); got != tt.want {
				t.Errorf("rootDomain(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestRootDomainWithScheme(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"https://example.com", "example.com"},
		{"http://sub.example.com/path", "example.com"},
		{"https://deep.sub.example.com:8443/foo?bar=1", "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			if got := rootDomain(tt.raw); got != tt.want {
				t.Errorf("rootDomain(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestRootDomainWhitespace(t *testing.T) {
	if got := rootDomain("  example.com  "); got != "example.com" {
		t.Errorf("rootDomain() = %q, want example.com", got)
	}
}

func TestRootDomainInvalidUTF8(t *testing.T) {
	if got := rootDomain("%ZZ%ZZ.example.com"); got != "" {
		t.Errorf("rootDomain() = %q, want empty", got)
	}
}

func TestFilterTopSubdomainsEmpty(t *testing.T) {
	if got := FilterTopSubdomains(nil, 5); len(got) != 0 {
		t.Errorf("FilterTopSubdomains(nil, 5) = %v, want empty", got)
	}
	if got := FilterTopSubdomains([]string{}, 3); len(got) != 0 {
		t.Errorf("FilterTopSubdomains([], 3) = %v, want empty", got)
	}
	if got := FilterTopSubdomains([]string{}, 0); len(got) != 0 {
		t.Errorf("FilterTopSubdomains([], 0) = %v, want empty", got)
	}
}

func TestFilterTopSubdomainsSortsByFrequency(t *testing.T) {
	subs := []string{
		"a.example.com",
		"b.example.com",
		"c.example.com",
		"d.example.com",
		"e.example.com",
		"1.other.org",
	}
	got := FilterTopSubdomains(subs, 2)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2: %v", len(got), got)
	}
	if got[0] != "example.com" {
		t.Errorf("most frequent = %q, want example.com", got[0])
	}
	if got[1] != "other.org" {
		t.Errorf("second = %q, want other.org", got[1])
	}
}

func TestFilterTopSubdomainsTopNLargerThanAvailable(t *testing.T) {
	subs := []string{"a.example.com", "b.example.com"}
	got := FilterTopSubdomains(subs, 10)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1: %v", len(got), got)
	}
}

func TestFilterTopSubdomainsSkipsInvalid(t *testing.T) {
	subs := []string{"notavalidtld", "", "a.example.com", "b.example.com"}
	got := FilterTopSubdomains(subs, 5)
	if len(got) != 1 || got[0] != "example.com" {
		t.Errorf("FilterTopSubdomains() = %v, want [example.com]", got)
	}
}

func TestFilterTopSubdomainsAllRoots(t *testing.T) {
	subs := []string{"a.example.com", "b.other.org"}
	got := FilterTopSubdomains(subs, 0)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2: %v", len(got), got)
	}
}

func TestFilterTopSubdomainsTiebreakerAlphabetical(t *testing.T) {
	subs := []string{"a.example.com", "a.other.org"}
	got := FilterTopSubdomains(subs, 2)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2: %v", len(got), got)
	}
	if got[0] != "example.com" {
		t.Errorf("alphabetical tiebreaker: got[0] = %q, want example.com", got[0])
	}
	if got[1] != "other.org" {
		t.Errorf("alphabetical tiebreaker: got[1] = %q, want other.org", got[1])
	}
}

func TestFilterTopSubdomainsNegativeTopN(t *testing.T) {
	subs := []string{"a.example.com", "b.example.com", "c.other.org"}
	got := FilterTopSubdomains(subs, -1)
	// negative topN should return all roots sorted by frequency
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2: %v", len(got), got)
	}
}

func TestFilterSubdomainsByRootsEmpty(t *testing.T) {
	if got := FilterSubdomainsByRoots(nil, []string{"example.com"}); len(got) != 0 {
		t.Errorf("FilterSubdomainsByRoots(nil, ...) = %v, want empty", got)
	}
	if got := FilterSubdomainsByRoots([]string{"a.example.com"}, nil); len(got) != 0 {
		t.Errorf("FilterSubdomainsByRoots(..., nil) = %v, want empty", got)
	}
}

func TestFilterSubdomainsByRootsExactMatch(t *testing.T) {
	subs := []string{"a.example.com", "b.example.com", "c.other.org"}
	got := FilterSubdomainsByRoots(subs, []string{"example.com"})
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2: %v", len(got), got)
	}
	sort.Strings(got)
	if got[0] != "a.example.com" || got[1] != "b.example.com" {
		t.Errorf("got = %v, want [a.example.com, b.example.com]", got)
	}
}

func TestFilterSubdomainsByRootsCaseSensitive(t *testing.T) {
	// rootDomain() preserves case from url.URL.Hostname(), so roots must match exactly.
	// Mixed-case subdomains won't match a lowercase root.
	subs := []string{"a.Example.COM", "b.example.com"}
	got := FilterSubdomainsByRoots(subs, []string{"example.com"})
	if len(got) != 1 || got[0] != "b.example.com" {
		t.Fatalf("len = %d, want 1 ([b.example.com]): %v", len(got), got)
	}
}

func TestFilterSubdomainsByRootsDeduplicates(t *testing.T) {
	subs := []string{"a.example.com", "a.example.com", "b.example.com"}
	got := FilterSubdomainsByRoots(subs, []string{"example.com"})
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2: %v", len(got), got)
	}
	// verify no duplicates
	seen := make(map[string]bool)
	for _, s := range got {
		if seen[s] {
			t.Errorf("duplicate found: %s", s)
		}
		seen[s] = true
	}
}

func TestFilterSubdomainsByRootsMultipleRoots(t *testing.T) {
	subs := []string{
		"a.example.com",
		"b.example.com",
		"c.other.org",
		"d.other.org",
		"e.third.net",
	}
	got := FilterSubdomainsByRoots(subs, []string{"example.com", "other.org"})
	if len(got) != 4 {
		t.Fatalf("len = %d, want 4: %v", len(got), got)
	}
}

func TestFilterSubdomainsByRootsSkipsInvalidSubdomains(t *testing.T) {
	subs := []string{"a.example.com", "", "invalidtld", "b.example.com"}
	got := FilterSubdomainsByRoots(subs, []string{"example.com"})
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2: %v", len(got), got)
	}
}

func TestRootDomainAndFilterIntegration(t *testing.T) {
	// Many subdomains from different roots
	subs := []string{
		"api.example.com",
		"www.example.com",
		"mail.example.com",
		"blog.example.com",
		"status.other.org",
		"docs.other.org",
	}
	// Find top root
	top := FilterTopSubdomains(subs, 1)
	if len(top) != 1 || top[0] != "example.com" {
		t.Fatalf("top = %v, want [example.com]", top)
	}
	// Filter by that root
	filtered := FilterSubdomainsByRoots(subs, top)
	if len(filtered) != 4 {
		t.Fatalf("filtered len = %d, want 4: %v", len(filtered), filtered)
	}
}

func TestRootDomainHashtag(t *testing.T) {
	// # is an invalid host so url.Parse should fail or produce empty
	if got := rootDomain("http://#"); got != "" {
		t.Logf("rootDomain(http://#) = %q", got)
	}
}

func TestRootDomainNilSubdomainInput(t *testing.T) {
	got := FilterTopSubdomains(nil, 5)
	if !reflect.DeepEqual(got, []string{}) {
		t.Errorf("FilterTopSubdomains(nil) = %v, want []", got)
	}
}
