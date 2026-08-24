package utils

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestScanContentForSecretsFindsMatch(t *testing.T) {
	patterns := map[string][]*regexp.Regexp{
		"GitHub Token":      {regexp.MustCompile(`ghp_[A-Za-z0-9_]{36}`)},
		"Generic API Key":   {regexp.MustCompile(`(?i)api[_-]?key\s*[:=]\s*["'][A-Za-z0-9+/=]{20,}["']`)},
		"AWS Access Key ID": {regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	}

	// GitHub-PAT-shaped fixtures built at runtime so no token literal appears in
	// source (these are fake test inputs, but a literal trips secret scanners).
	ghToken := "ghp_" + strings.Repeat("a1B2", 9)  // 36 chars after the prefix
	ghToken2 := "ghp_" + strings.Repeat("z9Y8", 9) // distinct, also 36 chars

	tests := []struct {
		name           string
		content        string
		source         string
		wantMatchCount int
		wantContains   string
	}{
		{
			name:           "github token found",
			content:        "const token = \"" + ghToken + "\"",
			source:         "config.js",
			wantMatchCount: 1,
			wantContains:   ghToken,
		},
		{
			name:           "api key with quotes",
			content:        `api_key: "abcdefghijAB1234567890+abc="`,
			source:         ".env",
			wantMatchCount: 1,
			wantContains:   "abcdefghijAB1234567890+abc=",
		},
		{
			name:           "AWS key found",
			content:        "AKIA1234567890ABCDEF",
			source:         "",
			wantMatchCount: 1,
			wantContains:   "AKIA1234567890ABCDEF",
		},
		{
			name:           "no secrets",
			content:        "nothing to see here",
			source:         "text.txt",
			wantMatchCount: 0,
		},
		{
			name:           "multiple matches deduplicated",
			content:        "AKIA1234567890ABCDEF and AKIA1234567890ABCDEF again",
			source:         "dup.txt",
			wantMatchCount: 1,
		},
		{
			name:           "source prefix in output",
			content:        ghToken2,
			source:         "leaked.js",
			wantMatchCount: 1,
			wantContains:   "leaked.js",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ScanContentForSecrets(tt.content, tt.source, patterns)
			if len(findings) != tt.wantMatchCount {
				t.Errorf("ScanContentForSecrets() count = %d, want %d: %v", len(findings), tt.wantMatchCount, findings)
			}
			if tt.wantContains != "" && len(findings) > 0 {
				matched := false
				for _, f := range findings {
					if strings.Contains(f, tt.wantContains) {
						matched = true
						break
					}
				}
				if !matched {
					t.Errorf("ScanContentForSecrets() findings = %v, want to contain %q", findings, tt.wantContains)
				}
			}
		})
	}
}

func TestScanContentForSecretsTruncation(t *testing.T) {
	longStr := "AKIA" + strings.Repeat("A", 200)
	patterns := map[string][]*regexp.Regexp{
		"AWS Key": {regexp.MustCompile(`AKIA[A-Z]{16,}`)},
	}
	findings := ScanContentForSecrets(longStr, "", patterns)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if !strings.HasSuffix(findings[0], "...") {
		t.Errorf("long match should be truncated with '...': %s", findings[0])
	}
}

func TestScanContentForSecretsEmptyPatterns(t *testing.T) {
	findings := ScanContentForSecrets("AKIA1234567890ABCDE", "", nil)
	if len(findings) != 0 {
		t.Errorf("ScanContentForSecrets() with nil patterns = %v, want 0 findings", findings)
	}
}

// TestClientSidePatternsFileLoads ensures every regex in the shipped
// client-side-patterns.yaml compiles (LoadPatternFile silently drops
// non-compiling regexes, so a typo would silently kill a detection) and that
// representative patterns fire on realistic JS snippets.
func TestClientSidePatternsFileLoads(t *testing.T) {
	patterns := loadClientSidePatternsForTest(t)
	if len(patterns) == 0 {
		t.Fatal("no client-side patterns loaded — every regex may have failed to compile")
	}
	// Every named pattern must have at least one compiled regex.
	for name, res := range patterns {
		if len(res) == 0 {
			t.Errorf("pattern %q has no compiled regexes", name)
		}
	}

	samples := []struct {
		patternName string
		js          string
	}{
		{"DOM XSS Sink: innerHTML", `el.innerHTML = data;`},
		{"DOM XSS Source: location.hash", `var x = location.hash;`},
		{"Dynamic Code Execution: eval()", `var r = eval(userInput);`},
		{"postMessage: wildcard target origin '*'", `w.postMessage(payload, '*');`},
		{"postMessage: message listener (verify origin check)", `window.addEventListener('message', h);`},
		{"Open Redirect Sink: location.assign/replace", `location.assign(next);`},
		{"Prototype Pollution: __proto__ reference", `obj[key] = v; if (key === '__proto__') return;`},
		{"Sensitive Storage: credential stored via setItem", `localStorage.setItem("auth_token", t);`},
		{"Insecure WebSocket: ws:// endpoint", `const ws = new WebSocket("ws://example.com/s");`},
		{"CORS Hint: credentials included cross-origin", `fetch(u, {credentials: 'include'})`},
	}
	for _, s := range samples {
		t.Run(s.patternName, func(t *testing.T) {
			res, ok := patterns[s.patternName]
			if !ok || len(res) == 0 {
				t.Fatalf("pattern %q not loaded", s.patternName)
			}
			matched := false
			for _, re := range res {
				if re.MatchString(s.js) {
					matched = true
					break
				}
			}
			if !matched {
				t.Errorf("pattern %q did not match sample JS: %s", s.patternName, s.js)
			}
		})
	}
}

func loadClientSidePatternsForTest(t *testing.T) map[string][]*regexp.Regexp {
	t.Helper()
	patterns, err := LoadPatternFile(filepath.Join("..", "..", "regexes"), "client-side-patterns.yaml")
	if err != nil {
		t.Fatalf("LoadPatternFile() error = %v", err)
	}
	return patterns
}
