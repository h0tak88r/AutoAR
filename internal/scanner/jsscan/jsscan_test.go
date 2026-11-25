package jsscan

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/h0tak88r/AutoAR/internal/utils"
)

// TestMaskSecretInLine: js-secrets-vulnerabilities.json feeds the dashboard/DB/
// R2, so neither the finding line nor the secret field may carry the value.
func TestMaskSecretInLine(t *testing.T) {
	line := "[Stripe Secret] https://t.example/app.js -> sk_live_0123456789abcdefWXYZ"
	target, typ, val := parseSecretLine(line)
	if target != "https://t.example/app.js" || typ != "Stripe Secret" {
		t.Fatalf("parseSecretLine: %q %q", target, typ)
	}
	maskedLine, masked := maskSecretInLine(line, val)
	if strings.Contains(maskedLine, "0123456789abcdef") || strings.Contains(masked, "0123456789abcdef") {
		t.Fatalf("secret leaked: line=%q masked=%q", maskedLine, masked)
	}
	if !strings.HasPrefix(maskedLine, "[Stripe Secret] https://t.example/app.js -> sk_l…WXYZ") {
		t.Fatalf("masked line = %q", maskedLine)
	}
	if l, m := maskSecretInLine("[X] url", ""); l != "[X] url" || m != "" {
		t.Fatalf("empty value: %q %q", l, m)
	}
}

func TestClientSideSeverity(t *testing.T) {
	for typ, want := range map[string]string{
		"DOM XSS Source: location.hash":                                        "info",
		"DOM XSS Sink (bare): innerHTML":                                       "info",
		"Prototype Pollution (bare): __proto__ reference":                      "info",
		"DOM XSS Flow: URL/referrer/name source into HTML or JS sink":          "medium",
		"DOM XSS Sink: document.write":                                         "medium",
		"Prototype Pollution: write through __proto__ / constructor.prototype": "medium",
		"Prototype Pollution: computed write to a built-in prototype":          "medium",
		"Prototype Pollution (bare): computed prototype assignment":            "info",
		"Open Redirect Sink: window.open":                                      "low",
	} {
		if got := clientSideSeverity(typ); got != want {
			t.Errorf("clientSideSeverity(%q) = %q, want %q", typ, got, want)
		}
	}
}

// Computed writes to a class's own prototype are how bundlers define methods
// (owners.awaze.com's bundle had 14, all library code); only a computed write
// to a built-in prototype is a medium lead.
func TestPrototypeAssignmentPatterns(t *testing.T) {
	patterns, err := utils.LoadPatternFile(filepath.Join("..", "..", "..", "regexes"), "client-side-patterns.yaml")
	if err != nil || len(patterns) < 20 {
		t.Fatalf("client-side patterns: %d loaded, %v", len(patterns), err)
	}
	classes := func(js string) map[string]bool {
		out := map[string]bool{}
		for _, f := range utils.ScanContentForSecrets(js, "x.js", patterns) {
			out[f[1:strings.Index(f, "]")]] = true
		}
		return out
	}
	const bare, builtin = "Prototype Pollution (bare): computed prototype assignment", "Prototype Pollution: computed write to a built-in prototype"
	for _, js := range []string{
		`Buffer.prototype["read"+t+"LE"]=function(e){return e}`,
		`ua.prototype[Symbol.iterator]=function*(){}`,
		`n.prototype[` + "`${e}At`" + `]=r`,
	} {
		got := classes(js)
		if !got[bare] || got[builtin] {
			t.Errorf("%s: %v", js, got)
		}
		if clientSideSeverity(bare) != "info" {
			t.Errorf("library method definitions must stay info")
		}
	}
	if got := classes(`for(k in src)Object.prototype[k]=src[k]`); !got[builtin] {
		t.Errorf("computed write to Object.prototype not flagged: %v", got)
	}
	if got := classes(`if(a.prototype[k]==b)c()`); got[bare] || got[builtin] {
		t.Errorf("a comparison is not an assignment: %v", got)
	}
}

func TestSelectJSURLs(t *testing.T) {
	in := []string{
		"https://www.acme.com/wp-includes/js/jquery.min.js?ver=3.7.1",
		"https://www.acme.com/wp-includes/js/jquery.min.js?ver=3.6.0", // same path, other cache buster
		"https://www.acme.com/wp-json/wp/v2/pages",                    // ".js" substring, not a JS file
		"https://www.acme.com/config.json",
		"https://www.acme.com/index.jsp",
		"https://www.acme.com/static/app.MJS",
		"https://www.acme.com/a.js#x",
		"ftp://www.acme.com/b.js",
		"https://www.acme.com/c.js",
	}
	got := selectJSURLs(in, 10)
	want := []string{in[0], in[5], in[6], in[8]}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v", got)
	}
	if got := selectJSURLs(in, 2); len(got) != 2 || got[0] != in[0] {
		t.Fatalf("cap keeps input order (live-page scripts first): %v", got)
	}
}
