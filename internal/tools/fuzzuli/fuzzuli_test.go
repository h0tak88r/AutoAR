package fuzzuli

import (
	"testing"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.Workers != 16 {
		t.Errorf("DefaultOptions().Workers = %d, want 16", opts.Workers)
	}
	if opts.MinContentLength != 100 {
		t.Errorf("DefaultOptions().MinContentLength = %d, want 100", opts.MinContentLength)
	}
	if opts.StatusCode != 200 {
		t.Errorf("DefaultOptions().StatusCode = %d, want 200", opts.StatusCode)
	}
	if len(opts.Extensions) == 0 {
		t.Error("DefaultOptions().Extensions should not be empty")
	}
	if len(opts.Paths) != 1 || opts.Paths[0] != "/" {
		t.Errorf("DefaultOptions().Paths = %v, want [/]", opts.Paths)
	}
	if opts.UserAgent == "" {
		t.Error("DefaultOptions().UserAgent should not be empty")
	}
	if opts.Method != MethodRegular {
		t.Errorf("DefaultOptions().Method = %q, want %q", opts.Method, MethodRegular)
	}
}

func TestDefaultOptionsExtensionsIsCopy(t *testing.T) {
	opts := DefaultOptions()
	opts.Extensions[0] = ".modified"
	opts2 := DefaultOptions()
	if opts2.Extensions[0] == ".modified" {
		t.Error("DefaultOptions() should return a copy of defaultExtensions, not the original slice")
	}
}

func TestNormalizeBaseHTTPDefault(t *testing.T) {
	got := normalizeBase("example.com")
	if got != "http://example.com" {
		t.Errorf("normalizeBase() = %q, want %q", got, "http://example.com")
	}
}

func TestNormalizeBaseHTTPSPreserved(t *testing.T) {
	got := normalizeBase("https://example.com")
	if got != "https://example.com" {
		t.Errorf("normalizeBase() = %q, want %q", got, "https://example.com")
	}
}

func TestNormalizeBaseHTTPPreserved(t *testing.T) {
	got := normalizeBase("http://example.com")
	if got != "http://example.com" {
		t.Errorf("normalizeBase() = %q, want %q", got, "http://example.com")
	}
}

func TestNormalizeBaseTrailingSlash(t *testing.T) {
	got := normalizeBase("https://example.com/")
	if got != "https://example.com" {
		t.Errorf("normalizeBase() = %q, want %q", got, "https://example.com")
	}
}

func TestNormalizeBaseEmpty(t *testing.T) {
	got := normalizeBase("")
	if got != "" {
		t.Errorf("normalizeBase() = %q, want empty", got)
	}
}

func TestNormalizeBaseWhitespaceOnly(t *testing.T) {
	got := normalizeBase("  ")
	if got != "" {
		t.Errorf("normalizeBase() = %q, want empty", got)
	}
}

func TestNormalizeBaseWithPort(t *testing.T) {
	got := normalizeBase("example.com:8080")
	if got != "http://example.com:8080" {
		t.Errorf("normalizeBase() = %q, want %q", got, "http://example.com:8080")
	}
}

func TestBuildURLComplete(t *testing.T) {
	got := buildURL("http://example.com", "/", "app", ".zip")
	want := "http://example.com/app.zip"
	if got != want {
		t.Errorf("buildURL() = %q, want %q", got, want)
	}
}

func TestBuildURLPathWithoutLeadingSlash(t *testing.T) {
	got := buildURL("http://example.com", "backup", "app", ".tar.gz")
	want := "http://example.com/backupapp.tar.gz"
	if got != want {
		t.Errorf("buildURL() = %q, want %q", got, want)
	}
}

func TestBuildURLEmptyBase(t *testing.T) {
	if got := buildURL("", "/", "word", ".zip"); got != "" {
		t.Errorf("buildURL() = %q, want empty", got)
	}
}

func TestBuildURLEmptyWord(t *testing.T) {
	if got := buildURL("http://example.com", "/", "", ".zip"); got != "" {
		t.Errorf("buildURL() = %q, want empty", got)
	}
}

func TestBuildURLEmptyExt(t *testing.T) {
	if got := buildURL("http://example.com", "/", "word", ""); got != "" {
		t.Errorf("buildURL() = %q, want empty", got)
	}
}

func TestGenerateWordlistRegular(t *testing.T) {
	words := generateWordlist("example.com", MethodRegular)
	if len(words) == 0 {
		t.Error("generateWordlist(MethodRegular) should return non-empty words")
	}
}

func TestGenerateWordlistWithoutDots(t *testing.T) {
	words := generateWordlist("example.com", MethodWithoutDots)
	if len(words) == 0 {
		t.Error("generateWordlist(MethodWithoutDots) should return non-empty words")
	}
}

func TestGenerateWordlistWithHTTPProtocol(t *testing.T) {
	words := generateWordlist("http://example.com", MethodRegular)
	if len(words) == 0 {
		t.Error("generateWordlist() should strip protocol and return words")
	}
}

func TestGenerateWordlistAll(t *testing.T) {
	words := generateWordlist("test.com", MethodAll)
	if len(words) == 0 {
		t.Error("generateWordlist(MethodAll) should return non-empty words")
	}
}

func TestGenerateWordlistDedup(t *testing.T) {
	words := generateWordlist("a.com", MethodAll)
	seen := make(map[string]bool)
	for _, w := range words {
		if seen[w] {
			t.Errorf("generateWordlist() has duplicate word: %q", w)
		}
		seen[w] = true
	}
}

func TestReverseSliceEmpty(t *testing.T) {
	got := reverseSlice(nil)
	if got != nil {
		t.Errorf("reverseSlice(nil) = %v, want nil", got)
	}
}

func TestReverseSliceSingle(t *testing.T) {
	in := []string{"a"}
	got := reverseSlice(in)
	if len(got) != 1 || got[0] != "a" {
		t.Errorf("reverseSlice([a]) = %v", got)
	}
}

func TestReverseSliceOdd(t *testing.T) {
	in := []string{"a", "b", "c"}
	got := reverseSlice(in)
	want := []string{"c", "b", "a"}
	if len(got) != 3 {
		t.Fatalf("reverseSlice() len = %d, want 3", len(got))
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("reverseSlice()[%d] = %q, want %q", i, got[i], v)
		}
	}
}

func TestReverseSliceEven(t *testing.T) {
	in := []string{"1", "2", "3", "4"}
	got := reverseSlice(in)
	want := []string{"4", "3", "2", "1"}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("reverseSlice()[%d] = %q, want %q", i, got[i], v)
		}
	}
}

func TestContainsTrue(t *testing.T) {
	if !contains([]string{"a", "b", "c"}, "b") {
		t.Error("contains() should be true when element is present")
	}
}

func TestContainsFalse(t *testing.T) {
	if contains([]string{"a", "b", "c"}, "d") {
		t.Error("contains() should be false when element is absent")
	}
}

func TestContainsEmpty(t *testing.T) {
	if contains(nil, "a") {
		t.Error("contains(nil) should be false")
	}
	if contains([]string{}, "a") {
		t.Error("contains([]) should be false")
	}
}

func TestUniqueFuzzuliEmpty(t *testing.T) {
	got := unique(nil)
	if len(got) != 0 {
		t.Errorf("unique(nil) len = %d, want 0", len(got))
	}
}

func TestUniqueFuzzuliNoDupes(t *testing.T) {
	in := []string{"a", "b", "c"}
	got := unique(in)
	if len(got) != 3 {
		t.Fatalf("unique() len = %d, want 3", len(got))
	}
	for i, v := range []string{"a", "b", "c"} {
		if got[i] != v {
			t.Errorf("unique()[%d] = %q, want %q", i, got[i], v)
		}
	}
}

func TestUniqueFuzzuliDedup(t *testing.T) {
	in := []string{"x", "y", "x", "z", "y"}
	got := unique(in)
	want := []string{"x", "y", "z"}
	if len(got) != len(want) {
		t.Fatalf("unique() len = %d, want %d: %v", len(got), len(want), got)
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("unique()[%d] = %q, want %q", i, got[i], v)
		}
	}
}

func TestUniqueFuzzuliEmptyStringFiltered(t *testing.T) {
	in := []string{"", "a", ""}
	got := unique(in)
	if len(got) != 1 || got[0] != "a" {
		t.Errorf("unique() = %v, want [a]", got)
	}
}

func TestUniqueFuzzuliPreservesOrder(t *testing.T) {
	in := []string{"z", "a", "m", "a", "z", "b"}
	got := unique(in)
	want := []string{"z", "a", "m", "b"}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("unique()[%d] = %q, want %q", i, got[i], v)
		}
	}
}
