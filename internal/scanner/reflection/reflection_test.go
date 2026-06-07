package reflection

import (
	"testing"
)

func TestExtractAngleBracketURLsEmpty(t *testing.T) {
	got := extractAngleBracketURLs(nil)
	if len(got) != 0 {
		t.Errorf("extractAngleBracketURLs(nil) len = %d, want 0", len(got))
	}
	got = extractAngleBracketURLs([]xssFinding{})
	if len(got) != 0 {
		t.Errorf("extractAngleBracketURLs([]) len = %d, want 0", len(got))
	}
}

func TestExtractAngleBracketURLsNoAngleBrackets(t *testing.T) {
	findings := []xssFinding{
		{MatchedAt: "https://example.com/page", Unfiltered: []string{"\"", "'"}},
		{MatchedAt: "https://example.com/other", Unfiltered: []string{"<", ">"}},
	}
	got := extractAngleBracketURLs(findings)
	if len(got) != 0 {
		t.Errorf("extractAngleBracketURLs() len = %d, want 0: %v", len(got), got)
	}
}

func TestExtractAngleBracketURLsLeftAngle(t *testing.T) {
	findings := []xssFinding{
		{MatchedAt: "https://example.com/vuln", Unfiltered: []string{"{<}", "\""}},
	}
	got := extractAngleBracketURLs(findings)
	if len(got) != 1 || got[0] != "https://example.com/vuln" {
		t.Errorf("extractAngleBracketURLs() = %v, want [https://example.com/vuln]", got)
	}
}

func TestExtractAngleBracketURLsRightAngle(t *testing.T) {
	findings := []xssFinding{
		{MatchedAt: "https://example.com/vuln", Unfiltered: []string{"{>}", "'"}},
	}
	got := extractAngleBracketURLs(findings)
	if len(got) != 1 || got[0] != "https://example.com/vuln" {
		t.Errorf("extractAngleBracketURLs() = %v, want [https://example.com/vuln]", got)
	}
}

func TestExtractAngleBracketURLsBothAngles(t *testing.T) {
	findings := []xssFinding{
		{MatchedAt: "https://example.com/both", Unfiltered: []string{"{<}", "{>}"}},
	}
	got := extractAngleBracketURLs(findings)
	if len(got) != 1 || got[0] != "https://example.com/both" {
		t.Errorf("extractAngleBracketURLs() = %v, want [https://example.com/both]", got)
	}
}

func TestExtractAngleBracketURLsMixed(t *testing.T) {
	findings := []xssFinding{
		{MatchedAt: "https://example.com/safe", Unfiltered: []string{"\"", "'"}},
		{MatchedAt: "https://example.com/vuln1", Unfiltered: []string{"{<}", "\""}},
		{MatchedAt: "https://example.com/vuln2", Unfiltered: []string{"'", "{>}"}},
		{MatchedAt: "https://example.com/also-safe", Unfiltered: []string{"<", ">"}},
	}
	got := extractAngleBracketURLs(findings)
	if len(got) != 2 {
		t.Fatalf("extractAngleBracketURLs() len = %d, want 2: %v", len(got), got)
	}
	if got[0] != "https://example.com/vuln1" || got[1] != "https://example.com/vuln2" {
		t.Errorf("extractAngleBracketURLs() = %v, want [https://example.com/vuln1, https://example.com/vuln2]", got)
	}
}

func TestExtractAngleBracketURLsDeduplicatesSameURL(t *testing.T) {
	findings := []xssFinding{
		{MatchedAt: "https://example.com/dup", Unfiltered: []string{"{<}"}},
		{MatchedAt: "https://example.com/dup", Unfiltered: []string{"{>}"}},
	}
	got := extractAngleBracketURLs(findings)
	if len(got) != 1 || got[0] != "https://example.com/dup" {
		t.Errorf("extractAngleBracketURLs() = %v, want [https://example.com/dup]", got)
	}
}

func TestExtractAngleBracketURLsEmptyUnfiltered(t *testing.T) {
	findings := []xssFinding{
		{MatchedAt: "https://example.com/page", Unfiltered: []string{}},
	}
	got := extractAngleBracketURLs(findings)
	if len(got) != 0 {
		t.Errorf("extractAngleBracketURLs() len = %d, want 0", len(got))
	}
}
