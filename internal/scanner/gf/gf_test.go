package gf

import (
	"testing"
)

func TestResultFileForPatternSimple(t *testing.T) {
	got := ResultFileForPattern("img-traversal")
	want := "gf-img-traversal-results.txt"
	if got != want {
		t.Errorf("ResultFileForPattern() = %q, want %q", got, want)
	}
}

func TestResultFileForPatternEmpty(t *testing.T) {
	got := ResultFileForPattern("")
	want := "gf--results.txt"
	if got != want {
		t.Errorf("ResultFileForPattern() = %q, want %q", got, want)
	}
}

func TestResultFileForPatternSingleChar(t *testing.T) {
	got := ResultFileForPattern("x")
	want := "gf-x-results.txt"
	if got != want {
		t.Errorf("ResultFileForPattern() = %q, want %q", got, want)
	}
}

func TestNormaliseURLEmpty(t *testing.T) {
	got := normaliseURL("")
	if got != "" {
		t.Errorf("normaliseURL() = %q, want empty", got)
	}
}

func TestNormaliseURLNoQuery(t *testing.T) {
	got := normaliseURL("https://example.com/path")
	want := "https://example.com/path"
	if got != want {
		t.Errorf("normaliseURL() = %q, want %q", got, want)
	}
}

func TestNormaliseURLWithQuery(t *testing.T) {
	got := normaliseURL("https://example.com/search?q=foo&lang=en")
	want := "https://example.com/search?lang=&q="
	if got != want {
		t.Errorf("normaliseURL() = %q, want %q", got, want)
	}
}

func TestNormaliseURLQueryParamsSorted(t *testing.T) {
	got := normaliseURL("https://example.com/api?b=2&a=1&c=3")
	want := "https://example.com/api?a=&b=&c="
	if got != want {
		t.Errorf("normaliseURL() = %q, want %q", got, want)
	}
}

func TestNormaliseURLFragmentRemoved(t *testing.T) {
	got := normaliseURL("https://example.com/page#section")
	want := "https://example.com/page"
	if got != want {
		t.Errorf("normaliseURL() = %q, want %q", got, want)
	}
}

func TestNormaliseURLQueryAndFragment(t *testing.T) {
	got := normaliseURL("https://example.com/path?a=1&b=2#anchor")
	want := "https://example.com/path?a=&b="
	if got != want {
		t.Errorf("normaliseURL() = %q, want %q", got, want)
	}
}

func TestNormaliseURLInvalidURL(t *testing.T) {
	got := normaliseURL("://invalid")
	// returns the original or best effort
	if got == "" {
		t.Error("normaliseURL() should return something for invalid URL")
	}
}

func TestNormaliseURLDuplicateParams(t *testing.T) {
	got := normaliseURL("https://example.com/page?key=1&key=2")
	want := "https://example.com/page?key="
	if got != want {
		t.Errorf("normaliseURL() = %q, want %q", got, want)
	}
}

func TestNormaliseURLWithoutScheme(t *testing.T) {
	got := normaliseURL("example.com/page?q=a")
	want := "example.com/page?q="
	if got != want {
		t.Errorf("normaliseURL() = %q, want %q", got, want)
	}
}
