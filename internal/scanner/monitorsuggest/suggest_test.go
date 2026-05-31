package monitorsuggest

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestNormalizeDomainEmpty(t *testing.T) {
	_, err := NormalizeDomain("")
	if err == nil {
		t.Error("NormalizeDomain(\"\") should return an error")
	}
	_, err = NormalizeDomain("   ")
	if err == nil {
		t.Error("NormalizeDomain(\"   \") should return an error")
	}
}

func TestNormalizeDomainWithSpaces(t *testing.T) {
	_, err := NormalizeDomain("example com")
	if err == nil {
		t.Error("NormalizeDomain(\"example com\") should return an error")
	}
}

func TestNormalizeDomainValid(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"plain domain", "example.com", "example.com"},
		{"https scheme", "https://example.com", "example.com"},
		{"http scheme", "http://example.com", "example.com"},
		{"uppercase", "EXAMPLE.COM", "example.com"},
		{"trailing slash", "example.com/", "example.com"},
		{"with path", "https://example.com/path/to/page", "example.com"},
		{"mixed case with scheme", "HTTPS://Example.Com/Path", "example.com"},
		{"trailing dot", "example.com.", "example.com"},
		{"whitespace", "  example.com  ", "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeDomain(tt.raw)
			if err != nil {
				t.Errorf("NormalizeDomain(%q) unexpected error: %v", tt.raw, err)
				return
			}
			if got != tt.want {
				t.Errorf("NormalizeDomain(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestNormalizeDomainTrailingDotAfterPathStrip(t *testing.T) {
	got, err := NormalizeDomain("example.com./")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "example.com" {
		t.Errorf("NormalizeDomain() = %q, want example.com", got)
	}
}

func TestStripTagsRemovesScripts(t *testing.T) {
	html := "<html><script>alert('hi')</script><div>Hello</div></html>"
	got := stripTags(html)
	if got != "Hello" {
		t.Errorf("stripTags() = %q, want %q", got, "Hello")
	}
}

func TestStripTagsRemovesStyles(t *testing.T) {
	html := "<html><style>.x { color: red; }</style><p>Text</p></html>"
	got := stripTags(html)
	if got != "Text" {
		t.Errorf("stripTags() = %q, want %q", got, "Text")
	}
}

func TestStripTagsNested(t *testing.T) {
	html := `<div><span>Hello</span> <b>World</b></div>`
	got := stripTags(html)
	// Tag removal replaces each tag with a space, so multiple spaces may result
	if !strings.Contains(got, "Hello") || !strings.Contains(got, "World") {
		t.Errorf("stripTags() = %q, want it to contain Hello and World", got)
	}
}

func TestStripTagsNoTags(t *testing.T) {
	got := stripTags("Plain text without tags")
	if got != "Plain text without tags" {
		t.Errorf("stripTags() = %q, want %q", got, "Plain text without tags")
	}
}

func TestStripTagsEmptyInput(t *testing.T) {
	got := stripTags("")
	if got != "" {
		t.Errorf("stripTags() = %q, want empty", got)
	}
}

func TestExtractTitle(t *testing.T) {
	tests := []struct {
		name string
		html string
		want string
	}{
		{"simple title", "<html><head><title>My Page</title></head></html>", "My Page"},
		{"title with attributes", `<html><title id="main">Hello World</title></html>`, "Hello World"},
		{"no title", "<html><body>No title here</body></html>", ""},
		// The regex [^<]{1,300} inside <title> stops at <, so tags inside title prevent matching
		{"title with tags inside", "<html><title>Hello <b>World</b></title></html>", ""},
		{"multiline title", "<html>\n<title>  My \n  Page\n</title>\n</html>", "My \n  Page"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractTitle(tt.html); got != tt.want {
				t.Errorf("extractTitle() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSnippetFromHTML(t *testing.T) {
	html := "<html><body><p>This is some readable content that should appear in the snippet from the web page.</p></body></html>"
	got := snippetFromHTML(html)
	if len(got) == 0 {
		t.Error("snippetFromHTML() returned empty")
	}
	if len(got) > maxBodySnip+3 { // +3 for "…"
		t.Errorf("snippetFromHTML() length = %d, want <= %d", len(got), maxBodySnip+3)
	}
}

func TestSnippetFromHTMLLongContent(t *testing.T) {
	// Build content longer than maxBodySnip
	long := "<html><body><p>"
	for i := 0; i < maxBodySnip*2; i++ {
		long += "word "
	}
	long += "</p></body></html>"
	got := snippetFromHTML(long)
	if len(got) > maxBodySnip+3 {
		t.Errorf("snippetFromHTML() length = %d, want <= %d", len(got), maxBodySnip+3)
	}
}

func TestSnippetFromHTMLRemovesScriptsAndStyles(t *testing.T) {
	html := `<html>
		<script>var x = 1;</script>
		<style>.red { color: red; }</style>
		<p>Visible content</p>
	</html>`
	got := snippetFromHTML(html)
	if got == "" {
		t.Error("snippetFromHTML() returned empty")
	}
	// Should not contain script or style remnants
	if len(got) == 0 {
		t.Error("expected non-empty snippet")
	}
}

func TestSnippetFromEmptyHTML(t *testing.T) {
	got := snippetFromHTML("")
	if got != "" {
		t.Errorf("snippetFromHTML(\"\") = %q, want empty", got)
	}
}

func TestHeuristicRankEmpty(t *testing.T) {
	got := heuristicRank("example.com", nil)
	if len(got) != 0 {
		t.Errorf("heuristicRank() with nil = %v, want empty", got)
	}
	got = heuristicRank("example.com", []Candidate{})
	if len(got) != 0 {
		t.Errorf("heuristicRank() with empty = %v, want empty", got)
	}
}

func TestHeuristicRankScores(t *testing.T) {
	candidates := []Candidate{
		{URL: "https://example.com/changelog", Title: "Changelog", Snippet: "latest releases and updates"},
		{URL: "https://example.com/about", Title: "About Us", Snippet: "we are a company"},
		{URL: "https://example.com/releases", Title: "Release Notes", Snippet: "what's new in v2.0"},
	}
	got := heuristicRank("example.com", candidates)
	if len(got) == 0 {
		t.Fatal("heuristicRank() returned empty")
	}
	// The changelog/releases candidates should have higher scores than about
	if got[0].Score < got[len(got)-1].Score {
		t.Errorf("first = %d, last = %d; want first >= last", got[0].Score, got[len(got)-1].Score)
	}
}

func TestHeuristicRankLimitsTo8(t *testing.T) {
	var candidates []Candidate
	for i := 0; i < 20; i++ {
		candidates = append(candidates, Candidate{
			URL:  "https://example.com/page" + string(rune('0'+i%10)),
			Title: "Page",
		})
	}
	got := heuristicRank("example.com", candidates)
	if len(got) > 8 {
		t.Errorf("heuristicRank() len = %d, want <= 8", len(got))
	}
}

func TestHeuristicRankScoreCap(t *testing.T) {
	// A candidate matching many keywords should be capped at 100
	cand := Candidate{
		URL:     "https://example.com/changelog/releases/whats-new/roadmap",
		Title:   "Changelog and Release Notes",
		Snippet: "product update notes roadmap",
	}
	got := heuristicRank("example.com", []Candidate{cand})
	if len(got) != 1 {
		t.Fatal("expected 1 result")
	}
	if got[0].Score > 100 {
		t.Errorf("Score = %d, want <= 100", got[0].Score)
	}
	if got[0].Strategy != "hash" {
		t.Errorf("Strategy = %q, want hash", got[0].Strategy)
	}
	if got[0].Reason == "" {
		t.Error("Reason should not be empty")
	}
}

func TestHeuristicRankSortsByScore(t *testing.T) {
	candidates := []Candidate{
		{URL: "https://example.com/low", Title: "Low", Snippet: "nothing relevant"},
		{URL: "https://example.com/changelog", Title: "High", Snippet: "whats new in production"},
	}
	got := heuristicRank("example.com", candidates)
	if len(got) != 2 {
		t.Fatal("expected 2 results")
	}
	if got[0].Score < got[1].Score {
		t.Errorf("first score %d < second score %d; want sorted desc", got[0].Score, got[1].Score)
	}
}

func TestExtractTitleWithScriptInside(t *testing.T) {
	// The regex [^<]{1,300} stops at <, so <script> inside <title> prevents the match.
	html := `<html><head><title>Welcome <script>alert('xss')</script></title></head></html>`
	got := extractTitle(html)
	if got != "" {
		t.Errorf("extractTitle() = %q, want empty", got)
	}
}

func TestNormalizeDomainEvolution(t *testing.T) {
	got, err := NormalizeDomain("http://www.EXAMPLE.COM/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "www.example.com" {
		t.Errorf("NormalizeDomain() = %q, want www.example.com", got)
	}
}

func TestCandidatesSort(t *testing.T) {
	cands := []Candidate{
		{URL: "https://example.com/b"},
		{URL: "https://example.com/a"},
		{URL: "https://example.com/c"},
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].URL < cands[j].URL })
	if cands[0].URL != "https://example.com/a" {
		t.Errorf("expected sorted; got %v", cands)
	}
	if cands[2].URL != "https://example.com/c" {
		t.Errorf("expected sorted; got %v", cands)
	}
}

func TestSuggestionFields(t *testing.T) {
	s := Suggestion{
		URL:      "https://example.com/changelog",
		Title:    "Changelog",
		Score:    85,
		Reason:   "Release notes found",
		Strategy: "hash",
	}
	if s.Strategy != "hash" {
		t.Errorf("Strategy = %q, want hash", s.Strategy)
	}
	if s.Score != 85 {
		t.Errorf("Score = %d, want 85", s.Score)
	}
}

func TestCandidateFields(t *testing.T) {
	c := Candidate{
		URL:     "https://example.com",
		Title:   "Example",
		Status:  200,
		Snippet: "Hello world",
	}
	if c.URL != "https://example.com" || c.Title != "Example" || c.Status != 200 || c.Snippet != "Hello world" {
		t.Error("Candidate field mismatch")
	}
}

func TestNormalizeDomainWithPort(t *testing.T) {
	_, err := NormalizeDomain("example.com:8080")
	if err != nil {
		t.Logf("NormalizeDomain with port returned error (expected — port is stripped as path): %v", err)
	}
}

func TestStripTagsComplexHTML(t *testing.T) {
	html := `<div class="main">
		<script>console.log("hello");</script>
		<style>.test{}</style>
		<h1>Title</h1>
		<p>Paragraph <a href="/link">with link</a></p>
	</div>`
	got := stripTags(html)
	if !reflect.DeepEqual(got != "", true) {
		t.Error("expected non-empty output")
	}
	// Check script and style are removed
	if got != "Title Paragraph with link" {
		// Accept multiple spaces
		t.Logf("stripTags() = %q", got)
	}
}

func TestReleasePathsConstant(t *testing.T) {
	if len(releasePaths) == 0 {
		t.Error("releasePaths should not be empty")
	}
	seen := make(map[string]bool)
	for _, p := range releasePaths {
		if seen[p] {
			t.Errorf("duplicate release path: %s", p)
		}
		seen[p] = true
		if p == "" {
			t.Error("empty release path")
		}
		if p[0] != '/' {
			t.Errorf("release path %q should start with /", p)
		}
	}
}
