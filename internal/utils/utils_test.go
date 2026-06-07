package utils

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeTargetSegmentPreservesLegitTargets(t *testing.T) {
	cases := map[string]string{
		"example.com":           "example.com",
		"https://example.com":   "example.com",
		"http://api.example.io": "api.example.io",
		"sub.example.com/":      "sub.example.com",
		"example.com:8080":      "example.com-8080",
		"my-bucket_name":        "my-bucket_name",
	}
	for in, want := range cases {
		if got := SanitizeTargetSegment(in); got != want {
			t.Errorf("SanitizeTargetSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSanitizeTargetSegmentBlocksTraversal is the security regression guard:
// no sanitized segment may contain a path separator or "..", so it can never
// escape its parent dir via filepath.Join.
func TestSanitizeTargetSegmentBlocksTraversal(t *testing.T) {
	evil := []string{
		"../../../../etc/passwd",
		"..\\..\\windows\\system32",
		"../../tmp/x",
		"a/b/c",
		"....//....//x",
		"foo/../../bar",
	}
	base := "/app/new-results"
	for _, in := range evil {
		got := SanitizeTargetSegment(in)
		if strings.ContainsAny(got, `/\`) {
			t.Errorf("SanitizeTargetSegment(%q) = %q still contains a path separator", in, got)
		}
		if strings.Contains(got, "..") {
			t.Errorf("SanitizeTargetSegment(%q) = %q still contains '..'", in, got)
		}
		joined := filepath.Join(base, got)
		if !strings.HasPrefix(joined, base+string(filepath.Separator)) {
			t.Errorf("filepath.Join(%q, %q) = %q escaped the base dir", base, got, joined)
		}
	}
}

func TestSanitizeTargetSegmentEmpty(t *testing.T) {
	if got := SanitizeTargetSegment(""); got != "unknown" {
		t.Errorf("SanitizeTargetSegment(\"\") = %q, want %q", got, "unknown")
	}
	if got := SanitizeTargetSegment("..."); got != "unknown" {
		t.Errorf("SanitizeTargetSegment(\"...\") = %q, want %q", got, "unknown")
	}
}

func TestUniqueStringsEmpty(t *testing.T) {
	got := UniqueStrings(nil)
	if got != nil && len(got) != 0 {
		t.Errorf("UniqueStrings(nil) = %v, want nil or empty", got)
	}
}

func TestUniqueStringsNoDupes(t *testing.T) {
	in := []string{"a", "b", "c"}
	got := UniqueStrings(in)
	if len(got) != 3 {
		t.Errorf("UniqueStrings() len = %d, want 3", len(got))
	}
	for i, v := range []string{"a", "b", "c"} {
		if got[i] != v {
			t.Errorf("UniqueStrings()[%d] = %q, want %q", i, got[i], v)
		}
	}
}

func TestUniqueStringsDeduplicates(t *testing.T) {
	in := []string{"a", "b", "a", "c", "b"}
	got := UniqueStrings(in)
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("UniqueStrings() len = %d, want %d: %v", len(got), len(want), got)
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("UniqueStrings()[%d] = %q, want %q", i, got[i], v)
		}
	}
}

func TestUniqueStringsAllSame(t *testing.T) {
	in := []string{"x", "x", "x", "x"}
	got := UniqueStrings(in)
	if len(got) != 1 || got[0] != "x" {
		t.Errorf("UniqueStrings() = %v, want [x]", got)
	}
}

func TestUniqueStringsWhitespaceFiltering(t *testing.T) {
	in := []string{" a ", "a", "  b  "}
	got := UniqueStrings(in)
	if len(got) != 2 {
		t.Errorf("UniqueStrings() len = %d, want 2: %v", len(got), got)
	}
}

func TestUniqueStringsEmptyStringFiltered(t *testing.T) {
	in := []string{"", "a", ""}
	got := UniqueStrings(in)
	if len(got) != 1 || got[0] != "a" {
		t.Errorf("UniqueStrings() = %v, want [a]", got)
	}
}

func TestUniqueStringsPreservesOrder(t *testing.T) {
	in := []string{"z", "a", "m", "a", "z", "b"}
	got := UniqueStrings(in)
	want := []string{"z", "a", "m", "b"}
	if len(got) != len(want) {
		t.Fatalf("UniqueStrings() len = %d, want %d: %v", len(got), len(want), got)
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("UniqueStrings()[%d] = %q, want %q", i, got[i], v)
		}
	}
}

func TestURLSlugSimple(t *testing.T) {
	got := URLSlug("https://example.com/path/to/page")
	if got != "https:__example.com_path_to_page" {
		t.Errorf("URLSlug() = %q, want %q", got, "https:__example.com_path_to_page")
	}
}

func TestURLSlugNoSlashes(t *testing.T) {
	got := URLSlug("example.com")
	if got != "example.com" {
		t.Errorf("URLSlug() = %q, want %q", got, "example.com")
	}
}

func TestURLSlugEmpty(t *testing.T) {
	got := URLSlug("")
	if got != "" {
		t.Errorf("URLSlug() = %q, want %q", got, "")
	}
}

func TestURLSlugMultipleSlashes(t *testing.T) {
	got := URLSlug("a//b")
	if got != "a__b" {
		t.Errorf("URLSlug() = %q, want %q", got, "a__b")
	}
}
