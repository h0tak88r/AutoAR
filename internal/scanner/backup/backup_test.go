package backup

import (
	"testing"
)

func TestSanitizeDomainForPathStripsHTTP(t *testing.T) {
	got := sanitizeDomainForPath("http://example.com")
	if got != "example.com" {
		t.Errorf("sanitizeDomainForPath() = %q, want %q", got, "example.com")
	}
}

func TestSanitizeDomainForPathStripsHTTPS(t *testing.T) {
	got := sanitizeDomainForPath("https://example.com")
	if got != "example.com" {
		t.Errorf("sanitizeDomainForPath() = %q, want %q", got, "example.com")
	}
}

func TestSanitizeDomainForPathRemovesTrailingSlash(t *testing.T) {
	got := sanitizeDomainForPath("https://example.com/")
	if got != "example.com" {
		t.Errorf("sanitizeDomainForPath() = %q, want %q", got, "example.com")
	}
}

func TestSanitizeDomainForPathReplacesColon(t *testing.T) {
	got := sanitizeDomainForPath("example.com:8080")
	if got != "example.com-8080" {
		t.Errorf("sanitizeDomainForPath() = %q, want %q", got, "example.com-8080")
	}
}

func TestSanitizeDomainForPathComplex(t *testing.T) {
	got := sanitizeDomainForPath("https://example.com:8443/path/")
	if got != "example.com-8443/path" {
		t.Errorf("sanitizeDomainForPath() = %q, want %q", got, "example.com-8443/path")
	}
}

func TestSanitizeDomainForPathPlainDomain(t *testing.T) {
	got := sanitizeDomainForPath("example.com")
	if got != "example.com" {
		t.Errorf("sanitizeDomainForPath() = %q, want %q", got, "example.com")
	}
}

func TestSanitizeDomainForPathWhitespace(t *testing.T) {
	got := sanitizeDomainForPath("  example.com  ")
	if got != "example.com" {
		t.Errorf("sanitizeDomainForPath() = %q, want %q", got, "example.com")
	}
}

func TestSanitizeDomainForPathEmpty(t *testing.T) {
	got := sanitizeDomainForPath("")
	if got != "" {
		t.Errorf("sanitizeDomainForPath() = %q, want %q", got, "")
	}
}

func TestSanitizeDomainForPathTrailingSlashes(t *testing.T) {
	got := sanitizeDomainForPath("https://example.com///")
	if got != "example.com" {
		t.Errorf("sanitizeDomainForPath() = %q, want %q", got, "example.com")
	}
}

func TestMinFirstSmaller(t *testing.T) {
	if got := min(1, 5); got != 1 {
		t.Errorf("min(1, 5) = %d, want 1", got)
	}
}

func TestMinSecondSmaller(t *testing.T) {
	if got := min(5, 1); got != 1 {
		t.Errorf("min(5, 1) = %d, want 1", got)
	}
}

func TestMinEqual(t *testing.T) {
	if got := min(3, 3); got != 3 {
		t.Errorf("min(3, 3) = %d, want 3", got)
	}
}

func TestMinNegative(t *testing.T) {
	if got := min(-5, 2); got != -5 {
		t.Errorf("min(-5, 2) = %d, want -5", got)
	}
}

func TestMinZero(t *testing.T) {
	if got := min(0, 0); got != 0 {
		t.Errorf("min(0, 0) = %d, want 0", got)
	}
}
