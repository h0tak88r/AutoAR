package jsfinder

import (
	"testing"
)

func TestNormalizeJSURLEmptyJSURL(t *testing.T) {
	if got := normalizeJSURL("https://example.com", ""); got != "" {
		t.Errorf("normalizeJSURL() = %q, want empty", got)
	}
	if got := normalizeJSURL("https://example.com", "  "); got != "" {
		t.Errorf("normalizeJSURL() = %q, want empty for whitespace-only JS URL", got)
	}
}

func TestNormalizeJSURLEmptyPageURL(t *testing.T) {
	if got := normalizeJSURL("", "script.js"); got != "" {
		t.Errorf("normalizeJSURL() = %q, want empty", got)
	}
	if got := normalizeJSURL("  ", "script.js"); got != "" {
		t.Errorf("normalizeJSURL() = %q, want empty for whitespace-only page URL", got)
	}
}

func TestNormalizeJSURLAbsoluteHTTP(t *testing.T) {
	got := normalizeJSURL("https://example.com", "https://cdn.example.com/app.js")
	if got != "https://cdn.example.com/app.js" {
		t.Errorf("normalizeJSURL() = %q, want %q", got, "https://cdn.example.com/app.js")
	}
}

func TestNormalizeJSURLRootRelative(t *testing.T) {
	got := normalizeJSURL("https://example.com", "/assets/app.js")
	want := "https://example.com/assets/app.js"
	if got != want {
		t.Errorf("normalizeJSURL() = %q, want %q", got, want)
	}
}

func TestNormalizeJSURLProtocolRelative(t *testing.T) {
	got := normalizeJSURL("https://example.com", "//cdn.example.com/app.js")
	want := "https://cdn.example.com/app.js"
	if got != want {
		t.Errorf("normalizeJSURL() = %q, want %q", got, want)
	}
}

func TestNormalizeJSURLNonJSExtension(t *testing.T) {
	got := normalizeJSURL("https://example.com", "api/data.php")
	want := "https://example.com/api/data.php"
	if got != want {
		t.Errorf("normalizeJSURL() = %q, want %q", got, want)
	}
}

func TestNormalizeJSURLJSWithQueryParam(t *testing.T) {
	got := normalizeJSURL("https://example.com", "/bundle.js?v=123")
	want := "https://example.com/bundle.js?v=123"
	if got != want {
		t.Errorf("normalizeJSURL() = %q, want %q", got, want)
	}
}

func TestNormalizeJSURLPageURLNoScheme(t *testing.T) {
	got := normalizeJSURL("example.com", "/app.js")
	want := "https://example.com/app.js"
	if got != want {
		t.Errorf("normalizeJSURL() = %q, want %q", got, want)
	}
}

func TestNormalizeJSURLJSURLIsFullDomain(t *testing.T) {
	got := normalizeJSURL("https://example.com", "other.com/script.js")
	want := "https://other.com/script.js"
	if got != want {
		t.Errorf("normalizeJSURL() = %q, want %q", got, want)
	}
}

func TestNormalizeJSURLJSURLHasNetTLD(t *testing.T) {
	got := normalizeJSURL("https://example.com", "cdn.example.net/app.js")
	want := "https://cdn.example.net/app.js"
	if got != want {
		t.Errorf("normalizeJSURL() = %q, want %q", got, want)
	}
}

func TestNormalizeJSURLJSURLIsDomainWithPath(t *testing.T) {
	got := normalizeJSURL("https://example.com", "cdn.other.com/assets/bundle.js")
	want := "https://cdn.other.com/assets/bundle.js"
	if got != want {
		t.Errorf("normalizeJSURL() = %q, want %q", got, want)
	}
}

func TestNormalizeJSURLRootRelativeWithNetTLD(t *testing.T) {
	got := normalizeJSURL("https://example.net", "/app.js")
	want := "https://example.net/app.js"
	if got != want {
		t.Errorf("normalizeJSURL() = %q, want %q", got, want)
	}
}

func TestNormalizeJSURLRootRelativeWithOrgTLD(t *testing.T) {
	got := normalizeJSURL("https://example.org", "/app.js")
	want := "https://example.org/app.js"
	if got != want {
		t.Errorf("normalizeJSURL() = %q, want %q", got, want)
	}
}
