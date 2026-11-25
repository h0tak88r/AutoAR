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
		{"DOM XSS Sink (bare): innerHTML", `el.innerHTML = data;`},
		{"DOM XSS Flow: URL/referrer/name source into HTML or JS sink", `el.innerHTML = decodeURIComponent(location.hash.slice(1));`},
		{"DOM XSS Flow: URL/referrer/name source into HTML or JS sink", `$("#out").html(location.search.substr(1))`},
		{"DOM XSS Source: location.hash", `var x = location.hash;`},
		{"Dynamic Code Execution: eval()", `var r = eval(userInput);`},
		{"postMessage: wildcard target origin '*'", `w.postMessage(payload, '*');`},
		{"postMessage: message listener (verify origin check)", `window.addEventListener('message', h);`},
		{"Open Redirect Sink: location.assign/replace", `location.assign(next);`},
		{"Prototype Pollution (bare): __proto__ reference", `obj[key] = v; if (key === '__proto__') return;`},
		{"Prototype Pollution: write through __proto__ / constructor.prototype", `target.__proto__[k] = src[k];`},
		{"Prototype Pollution: write through __proto__ / constructor.prototype", `o["__proto__"].isAdmin = true`},
		{"Prototype Pollution: write through __proto__ / constructor.prototype", `x.constructor.prototype.polluted = 1`},
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

// TestClientSideTightPatternsSkipBenignIdioms: the medium-severity flow/write
// patterns must not fire on the common benign idioms the "(bare)" ones catch.
func TestClientSideTightPatternsSkipBenignIdioms(t *testing.T) {
	patterns := loadClientSidePatternsForTest(t)
	benign := map[string][]string{
		"DOM XSS Flow: URL/referrer/name source into HTML or JS sink": {
			`el.innerHTML = "<b>" + i18n.title + "</b>";`,
			`var h = location.hash; render(h);`,
			`if (el.innerHTML == location.hash) {}`,
		},
		"Prototype Pollution: write through __proto__ / constructor.prototype": {
			`if (key === '__proto__' || key === 'constructor') return;`,
			`var p = obj.__proto__;`,
			`Foo.prototype.bar = function () {};`,
			`if (a.constructor.prototype === b) {}`,
		},
	}
	for name, samples := range benign {
		res := patterns[name]
		if len(res) == 0 {
			t.Fatalf("pattern %q not loaded", name)
		}
		for _, js := range samples {
			for _, re := range res {
				if re.MatchString(js) {
					t.Errorf("%q matched benign JS: %s", name, js)
				}
			}
		}
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

func TestMaskSecret(t *testing.T) {
	cases := map[string]string{
		"":                          "",
		"AKIAIOSFODNN7EXAMPLE":      "AKIA…MPLE (20 chars)",
		"  sk_live_0123456789abcd ": "sk_l…abcd (22 chars)",
		"hunter2pass":               "hu… (11 chars)",
		"ab":                        "a… (2 chars)",
	}
	for in, want := range cases {
		if got := MaskSecret(in); got != want {
			t.Errorf("MaskSecret(%q) = %q, want %q", in, got, want)
		}
	}
	full := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	if strings.Contains(MaskSecret(full), "abcdefghij") {
		t.Fatalf("MaskSecret leaked the middle of the secret: %q", MaskSecret(full))
	}
}

// The shipped JS-secret patterns on minified-bundle shapes: real key formats
// still match, the junk they used to flag does not (owners.awaze.com's 4 MB
// Vite bundle produced 48 hits under the old patterns, all false).
func TestShippedSecretPatternsOnBundleShapes(t *testing.T) {
	patterns, err := LoadSecretPatterns(filepath.Join("..", "..", "regexes"))
	if err != nil {
		t.Fatal(err)
	}
	types := func(content string) map[string]string {
		out := map[string]string{}
		for _, f := range ScanContentForSecrets(content, "x.js", patterns) {
			out[f[1:strings.Index(f, "]")]] = f[strings.Index(f, "-> ")+3:]
		}
		return out
	}
	// Key-shaped fixtures are built at runtime so no literal trips scanners.
	sg := "SG." + strings.Repeat("aB3_", 5) + "xy" + "." + strings.Repeat("Qw9-", 10) + "zz1"
	aws := "AKIA" + "IOSFODNN7" + "EXAMPLE"
	site := "6Lc" + strings.Repeat("A1b2", 9) + "x" // 40 chars, like a real key
	b64 := strings.Repeat("Q0RFRkdISUpLTE1OT1BRUlNUVVZXWFla", 3)

	for _, c := range []struct {
		name, content, typ, value string
	}{
		{"sendgrid key", `const k="` + sg + `"`, "sendgrid_api_key", sg},
		{"aws key id", `accessKeyId:"` + aws + `",`, "aws_access_key_id", aws},
		{"recaptcha key, quotes trimmed", `sitekey:"` + site + `"`, "google_captcha", site},
		{"client secret near its keyword", `client_secret: "` + strings.Repeat("ab12", 8) + `"`, "Generic Secret", ""},
	} {
		got := types(c.content)
		v, ok := got[c.typ]
		if !ok {
			t.Errorf("%s: %s not found in %v", c.name, c.typ, got)
			continue
		}
		if c.value != "" && v != c.value {
			t.Errorf("%s: value %q, want %q", c.name, v, c.value)
		}
	}
	for _, c := range []struct{ name, content, typ string }{
		{"SG + any char (old unescaped dot)", "var SGEr" + strings.Repeat("x7Kq", 14) + ";", "sendgrid_api_key"},
		{"AWS-prefixed lowercase identifier", "function ASIAmazingThingHandler_x(){}", "aws_access_key_id"},
		{"AWS prefix inside a base64 run", b64 + "AKIA" + strings.Repeat("Z9", 8) + b64, "aws_access_key_id"},
		{"6L run inside base64 (no quotes)", "data:font/woff2;base64," + b64 + "6Ly9" + strings.Repeat("aB", 18) + b64, "google_captcha"},
		{"'secret' far from a quoted hash in a minified line", `n.secret=!0;` + strings.Repeat("a(b,c);", 40) + `h="` + strings.Repeat("f0e1", 8) + `"`, "Generic Secret"},
	} {
		if v, ok := types(c.content)[c.typ]; ok {
			t.Errorf("%s: false positive %s = %q", c.name, c.typ, v)
		}
	}
}
