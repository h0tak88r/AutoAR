package aem

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestNormalizeURLNoDoubleSlash(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		path    string
		want    string
	}{
		{"no trailing slash base", "https://example.com", "/path", "https://example.com/path"},
		{"trailing slash base no leading slash path", "https://example.com/", "path", "https://example.com/path"},
		{"neither slash", "https://example.com", "path", "https://example.compath"},
		{"both slashes - normal", "https://example.com/", "/path", "https://example.com/path"},
		{"both slashes - backslash path", "https://example.com/", "\\path", "https://example.com\\path"},
		{"trailing slash, empty path", "https://example.com/", "", "https://example.com/"},
		{"no trailing slash, empty path", "https://example.com", "", "https://example.com"},
		{"deep path", "https://example.com/api/v1/", "/users", "https://example.com/api/v1/users"},
		{"root with slash base", "https://example.com/", "/", "https://example.com/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeURL(tt.baseURL, tt.path); got != tt.want {
				t.Errorf("NormalizeURL(%q, %q) = %q, want %q", tt.baseURL, tt.path, got, tt.want)
			}
		})
	}
}

func TestContentTypeSimple(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"text/html; charset=utf-8", "text/html"},
		{"application/json", "application/json"},
		{"TEXT/HTML; Charset=UTF-8", "text/html"},
		{"  text/html  ; charset=utf-8", "text/html"},
		{"application/octet-stream; boundary=something", "application/octet-stream"},
		{"", ""},
		{"no-semicolon", "no-semicolon"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ContentType(tt.input); got != tt.want {
				t.Errorf("ContentType(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestContentTypeSemicolons(t *testing.T) {
	got := ContentType("text/html; charset=utf-8; version=2")
	if got != "text/html" {
		t.Errorf("ContentType() = %q, want text/html", got)
	}
}

func TestBasicAuth(t *testing.T) {
	got := BasicAuth("user", "pass")
	auth := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	want := "Basic " + auth
	if got != want {
		t.Errorf("BasicAuth() = %q, want %q", got, want)
	}
}

func TestBasicAuthEmpty(t *testing.T) {
	got := BasicAuth("", "")
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(":"))
	if got != want {
		t.Errorf("BasicAuth() = %q, want %q", got, want)
	}
}

func TestBasicAuthSpecialChars(t *testing.T) {
	got := BasicAuth("user@name", "p@ss:word")
	// Should not contain raw password
	if strings.Contains(got, "p@ss:word") {
		t.Error("BasicAuth() contains raw password")
	}
	// Verify it decodes correctly
	b64 := strings.TrimPrefix(got, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if string(decoded) != "user@name:p@ss:word" {
		t.Errorf("decoded = %q, want user@name:p@ss:word", string(decoded))
	}
}

func TestRandomStringLength(t *testing.T) {
	for _, length := range []int{0, 1, 5, 10, 100} {
		got := RandomString(length)
		if len(got) != length {
			t.Errorf("RandomString(%d) length = %d, want %d", length, len(got), length)
		}
	}
}

func TestRandomStringContainsOnlyAlphabet(t *testing.T) {
	for _, length := range []int{1, 10, 50} {
		got := RandomString(length)
		for _, c := range got {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
				t.Errorf("RandomString(%d) contains non-alphabet char: %c in %q", length, c, got)
				return
			}
		}
	}
}

func TestRandomStringDeterministicPattern(t *testing.T) {
	// Since RandomString uses i%len(charset), it's cyclic — verify the pattern
	got := RandomString(10)
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for i, c := range got {
		want := rune(charset[i%len(charset)])
		if c != want {
			t.Errorf("RandomString at position %d: got %c, want %c", i, c, want)
		}
	}
}
