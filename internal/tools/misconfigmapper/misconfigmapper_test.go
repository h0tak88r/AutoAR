package misconfigmapper

import (
	"testing"
)

func TestParseRegexSingle(t *testing.T) {
	got := ParseRegex([]string{"example.com"})
	want := `example\.com`
	if got != want {
		t.Errorf("ParseRegex() = %q, want %q", got, want)
	}
}

func TestParseRegexMultiple(t *testing.T) {
	got := ParseRegex([]string{"example.com", "test.org", "api.example.com"})
	want := `example\.com|test\.org|api\.example\.com`
	if got != want {
		t.Errorf("ParseRegex() = %q, want %q", got, want)
	}
}

func TestParseRegexEmpty(t *testing.T) {
	got := ParseRegex([]string{})
	if got != "" {
		t.Errorf("ParseRegex() = %q, want %q", got, "")
	}
}

func TestParseRegexNoDots(t *testing.T) {
	got := ParseRegex([]string{"hello", "world"})
	want := "hello|world"
	if got != want {
		t.Errorf("ParseRegex() = %q, want %q", got, want)
	}
}

func TestParseRegexSpecialChars(t *testing.T) {
	got := ParseRegex([]string{"a.b"})
	want := `a\.b`
	if got != want {
		t.Errorf("ParseRegex() = %q, want %q", got, want)
	}
}
