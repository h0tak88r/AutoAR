package urls

import (
	"testing"
)

func TestContainsAnyEmptySubs(t *testing.T) {
	if containsAny("anything") {
		t.Error("containsAny() with no subs should be false")
	}
}

func TestContainsAnyMatch(t *testing.T) {
	if !containsAny("hello.php", ".php", ".asp") {
		t.Error("containsAny() should be true when substring matches")
	}
}

func TestContainsAnyNoMatch(t *testing.T) {
	if containsAny("hello.html", ".php", ".asp") {
		t.Error("containsAny() should be false when no substring matches")
	}
}

func TestContainsAnyMultiMatch(t *testing.T) {
	if !containsAny("config.json", ".env", ".git", ".json") {
		t.Error("containsAny() should be true when later substring matches")
	}
}

func TestContainsAnyExactSubstring(t *testing.T) {
	if !containsAny("https://example.com/admin/login", "/admin") {
		t.Error("containsAny() should match path segments")
	}
}

func TestUniqueStringsEmpty(t *testing.T) {
	got := uniqueStrings(nil)
	if len(got) != 0 {
		t.Errorf("uniqueStrings(nil) len = %d, want 0", len(got))
	}
	got = uniqueStrings([]string{})
	if len(got) != 0 {
		t.Errorf("uniqueStrings([]) len = %d, want 0", len(got))
	}
}

func TestUniqueStringsNoDupes(t *testing.T) {
	in := []string{"a", "b", "c"}
	got := uniqueStrings(in)
	if len(got) != 3 {
		t.Fatalf("uniqueStrings() len = %d, want 3", len(got))
	}
	for i, v := range []string{"a", "b", "c"} {
		if got[i] != v {
			t.Errorf("uniqueStrings()[%d] = %q, want %q", i, got[i], v)
		}
	}
}

func TestUniqueStringsDedup(t *testing.T) {
	in := []string{"a", "b", "a", "c", "b"}
	got := uniqueStrings(in)
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("uniqueStrings() len = %d, want %d: %v", len(got), len(want), got)
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("uniqueStrings()[%d] = %q, want %q", i, got[i], v)
		}
	}
}

func TestUniqueStringsWhitespace(t *testing.T) {
	in := []string{" a ", "a", "  b  "}
	got := uniqueStrings(in)
	if len(got) != 2 {
		t.Errorf("uniqueStrings() len = %d, want 2: %v", len(got), got)
	}
}

func TestUniqueStringsEmptyFiltered(t *testing.T) {
	in := []string{"", "a", ""}
	got := uniqueStrings(in)
	if len(got) != 1 || got[0] != "a" {
		t.Errorf("uniqueStrings() = %v, want [a]", got)
	}
}

func TestUniqueStringsPreservesOrder(t *testing.T) {
	in := []string{"z", "a", "m", "a", "z", "b"}
	got := uniqueStrings(in)
	want := []string{"z", "a", "m", "b"}
	if len(got) != len(want) {
		t.Fatalf("uniqueStrings() len = %d, want %d: %v", len(got), len(want), got)
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("uniqueStrings()[%d] = %q, want %q", i, got[i], v)
		}
	}
}

func TestExtractRootDomainSimple(t *testing.T) {
	got := extractRootDomain("example.com")
	if got != "example.com" {
		t.Errorf("extractRootDomain() = %q, want %q", got, "example.com")
	}
}

func TestExtractRootDomainSubdomain(t *testing.T) {
	got := extractRootDomain("www.example.com")
	if got != "example.com" {
		t.Errorf("extractRootDomain() = %q, want %q", got, "example.com")
	}
}

func TestExtractRootDomainDeepSubdomain(t *testing.T) {
	got := extractRootDomain("sub.sub.example.com")
	if got != "example.com" {
		t.Errorf("extractRootDomain() = %q, want %q", got, "example.com")
	}
}

func TestExtractRootDomainWithProtocol(t *testing.T) {
	got := extractRootDomain("https://www.example.com")
	if got != "example.com" {
		t.Errorf("extractRootDomain() = %q, want %q", got, "example.com")
	}
}

func TestExtractRootDomainWithPort(t *testing.T) {
	got := extractRootDomain("example.com:8080")
	if got != "example.com" {
		t.Errorf("extractRootDomain() = %q, want %q", got, "example.com")
	}
}

func TestExtractRootDomainWithPath(t *testing.T) {
	got := extractRootDomain("www.example.com/path/to/page")
	if got != "example.com" {
		t.Errorf("extractRootDomain() = %q, want %q", got, "example.com")
	}
}

func TestExtractRootDomainSinglePart(t *testing.T) {
	got := extractRootDomain("localhost")
	if got != "localhost" {
		t.Errorf("extractRootDomain() = %q, want %q", got, "localhost")
	}
}

func TestExtractRootDomainEmpty(t *testing.T) {
	got := extractRootDomain("")
	if got != "" {
		t.Errorf("extractRootDomain() = %q, want empty", got)
	}
}

func TestFilterInterestingURLsEmpty(t *testing.T) {
	got := FilterInterestingURLs(nil)
	if len(got) != 0 {
		t.Errorf("FilterInterestingURLs(nil) len = %d, want 0", len(got))
	}
	got = FilterInterestingURLs([]string{})
	if len(got) != 0 {
		t.Errorf("FilterInterestingURLs([]) len = %d, want 0", len(got))
	}
}

func TestFilterInterestingURLsLegacyTech(t *testing.T) {
	got := FilterInterestingURLs([]string{"https://example.com/page.php"})
	if len(got) != 1 || got[0] != "https://example.com/page.php" {
		t.Errorf("FilterInterestingURLs() = %v, want [page.php]", got)
	}
}

func TestFilterInterestingURLsAuthParams(t *testing.T) {
	got := FilterInterestingURLs([]string{"https://example.com/api?token=abc123"})
	if len(got) != 1 {
		t.Errorf("FilterInterestingURLs() len = %d, want 1: %v", len(got), got)
	}
}

func TestFilterInterestingURLsAdminPath(t *testing.T) {
	got := FilterInterestingURLs([]string{"https://example.com/wp-admin/panel"})
	if len(got) != 1 {
		t.Errorf("FilterInterestingURLs() len = %d, want 1: %v", len(got), got)
	}
}

func TestFilterInterestingURLsAPIEndpoint(t *testing.T) {
	got := FilterInterestingURLs([]string{"https://api.example.com/v1/users"})
	if len(got) != 1 {
		t.Errorf("FilterInterestingURLs() len = %d, want 1: %v", len(got), got)
	}
}

func TestFilterInterestingURLsSensitiveFile(t *testing.T) {
	got := FilterInterestingURLs([]string{"https://example.com/.env"})
	if len(got) != 1 {
		t.Errorf("FilterInterestingURLs() len = %d, want 1: %v", len(got), got)
	}
}

func TestFilterInterestingURLsRedirectParam(t *testing.T) {
	got := FilterInterestingURLs([]string{"https://example.com/login?redirect=https://evil.com"})
	if len(got) != 1 {
		t.Errorf("FilterInterestingURLs() len = %d, want 1: %v", len(got), got)
	}
}

func TestFilterInterestingURLsDebugPath(t *testing.T) {
	got := FilterInterestingURLs([]string{"https://example.com/debug/info"})
	if len(got) != 1 {
		t.Errorf("FilterInterestingURLs() len = %d, want 1: %v", len(got), got)
	}
}

func TestFilterInterestingURLsBoringURL(t *testing.T) {
	got := FilterInterestingURLs([]string{"https://example.com/about"})
	if len(got) != 0 {
		t.Errorf("FilterInterestingURLs() len = %d, want 0 (boring URL): %v", len(got), got)
	}
}

func TestFilterInterestingURLsDedup(t *testing.T) {
	got := FilterInterestingURLs([]string{
		"https://example.com/.env",
		"https://example.com/.env", // duplicate
		"https://example.com/.git/config",
	})
	if len(got) != 2 {
		t.Errorf("FilterInterestingURLs() len = %d, want 2 (deduped): %v", len(got), got)
	}
}

func TestFilterInterestingURLsCaseInsensitive(t *testing.T) {
	got := FilterInterestingURLs([]string{"https://example.com/ADMIN/PANEL"})
	if len(got) != 1 {
		t.Errorf("FilterInterestingURLs() len = %d, want 1 (case-insensitive): %v", len(got), got)
	}
}
