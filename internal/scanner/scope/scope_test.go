package scope

import (
	"testing"

	bbscope "github.com/sw33tLie/bbscope/pkg/scope"
)

func TestIsMobileOrAppTargetCategoryMatch(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		category string
		want     bool
	}{
		{"mobile category", "example.com", "mobile", true},
		{"android category", "example.com", "android", true},
		{"ios category", "example.com", "ios", true},
		{"apple category", "example.com", "apple", true},
		{"executable category", "example.com", "executable", true},
		{"source_code category", "example.com", "source_code", true},
		{"smart_contract category", "example.com", "smart_contract", true},
		{"ai_model category", "example.com", "ai_model", true},
		{"hardware category", "example.com", "hardware", true},
		{"google_play_app_id category", "example.com", "google_play_app_id", true},
		{"apple_store_app_id category", "example.com", "apple_store_app_id", true},
		{"other_apk category", "example.com", "other_apk", true},
		{"testflight category", "example.com", "testflight", true},
		{"windows_app_store_app_id category", "example.com", "windows_app_store_app_id", true},
		{"downloadable_executables category", "example.com", "downloadable_executables", true},
		{"code category", "example.com", "code", true},
		{"other category", "example.com", "other", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isMobileOrAppTarget(tt.target, tt.category); got != tt.want {
				t.Errorf("isMobileOrAppTarget(%q, %q) = %v, want %v", tt.target, tt.category, got, tt.want)
			}
		})
	}
}

func TestIsMobileOrAppTargetNotMobile(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		category string
	}{
		{"normal website", "example.com", "web_application"},
		{"subdomain", "api.example.com", "api"},
		{"ip address", "192.168.1.1", "network"},
		{"wildcard domain", "*.example.com", "web_application"},
		{"empty strings", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isMobileOrAppTarget(tt.target, tt.category); got {
				t.Errorf("isMobileOrAppTarget(%q, %q) = true, want false", tt.target, tt.category)
			}
		})
	}
}

// Host keywords are NOT a signal any more (C16): the old substring list
// ("app", "cloud", "ios", "exe", "deb", …) dropped legitimate roots such as
// whatsapp.com or cloudflare.com. Only categories and unambiguous target
// shapes (store listings, file extensions) mark a target as non-web.
func TestIsMobileOrAppTargetKeepsLegitHosts(t *testing.T) {
	for _, target := range []string{
		"whatsapp.com", "cloudflare.com", "debian.org", "my-ios-app.example.com",
		"android.example.com", "aws.example.com", "cloud.example.com", "my-application.com",
		"executable-files.com", "mobile.example.com", "*.appspot-like.example.com",
	} {
		if isMobileOrAppTarget(target, "") {
			t.Errorf("isMobileOrAppTarget(%q, \"\") = true, want false (legit host)", target)
		}
		if isMobileOrAppTarget(target, "URL") {
			t.Errorf("isMobileOrAppTarget(%q, URL) = true, want false (legit host)", target)
		}
	}
}

func TestIsMobileOrAppTargetShapes(t *testing.T) {
	for _, target := range []string{
		"https://play.google.com/store/apps/details?id=com.acme",
		"https://apps.apple.com/us/app/acme/id123",
		"acme-installer.exe", "app-release.apk", "Acme.IPA",
	} {
		if !isMobileOrAppTarget(target, "") {
			t.Errorf("isMobileOrAppTarget(%q) = false, want true", target)
		}
	}
	// Web categories always stay web, whatever their tokens.
	for _, cat := range []string{"web-application", "websites_and_applications", "WILDCARD", "Url", "website", "api", "ip-address"} {
		if isMobileOrAppTarget("acme.com", cat) {
			t.Errorf("category %q must be web", cat)
		}
	}
	for _, cat := range []string{"mobile-application-ios", "application", "SOURCE_CODE", "OTHER", "Device"} {
		if !isMobileOrAppTarget("acme.com", cat) {
			t.Errorf("category %q must be non-web", cat)
		}
	}
}

func TestIsMobileOrAppTargetCaseInsensitive(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		category string
		want     bool
	}{
		{"uppercase category", "example.com", "MOBILE", true},
		{"mixed case category", "example.com", "Android", true},
		{"uppercase store host", "HTTPS://PLAY.GOOGLE.COM/store/apps", "", true},
		{"uppercase legit host", "IOS.example.com", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isMobileOrAppTarget(tt.target, tt.category); got != tt.want {
				t.Errorf("isMobileOrAppTarget(%q, %q) = %v, want %v", tt.target, tt.category, got, tt.want)
			}
		})
	}
}

func TestIsMobileOrAppTargetPartialCategoryMatch(t *testing.T) {
	// "code" is a whole token of "source_code"
	if !isMobileOrAppTarget("example.com", "source_code") {
		t.Error("isMobileOrAppTarget(example.com, source_code) should match via 'code'")
	}
	// "apple"/"app" are whole tokens of "apple_store_app_id"
	if !isMobileOrAppTarget("example.com", "apple_store_app_id") {
		t.Error("isMobileOrAppTarget(example.com, apple_store_app_id) should match via 'apple'")
	}
	// ...but tokens never match inside other words.
	if isMobileOrAppTarget("example.com", "scenarios") {
		t.Error("'scenarios' must not match the 'ios' token")
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in       string
		host     string
		wildcard bool
		path     bool
		ok       bool
	}{
		{"*.Acme.com", "acme.com", true, false, true},
		{"https://api.acme.com:8443/v1/x", "api.acme.com", false, true, true},
		{"https://acme.com/", "acme.com", false, false, true},
		{"api.*.acme.com", "acme.com", true, false, true},
		{"*-dev.acme.com", "acme.com", true, false, true},
		{"acme.*", "", true, false, false},
		{"NO_IN_SCOPE_TABLE", "", false, false, false},
		{"com.acme.android", "com.acme.android", false, false, true},
		{"free text scope", "", false, false, false},
		{`"><svg>.x`, "", false, false, false},
		{"bücher.de", "xn--bcher-kva.de", false, false, true},
	}
	for _, c := range cases {
		pt, ok := ParseTarget(c.in)
		if ok != c.ok || (ok && (pt.Host != c.host || pt.Wildcard != c.wildcard || pt.HasPath != c.path)) {
			t.Errorf("ParseTarget(%q) = %+v,%v; want host=%q wildcard=%v path=%v ok=%v", c.in, pt, ok, c.host, c.wildcard, c.path, c.ok)
		}
	}
	if pt, ok := ParseTarget("10.0.0.0/8"); !ok || !pt.IsIP {
		t.Errorf("CIDR must parse as IP: %+v %v", pt, ok)
	}
}

// C3: specific hosts, SaaS tenants and repo URLs must never be widened into a
// vendor/registrable root; only wildcards and explicitly typed apexes are.
func TestElementRoot(t *testing.T) {
	cases := []struct {
		target, category string
		want             string // "" = no root
	}{
		{"*.acme.com", "WILDCARD", "acme.com"},
		{"*.api.acme.com", "website", "api.acme.com"},
		{"acme.com", "WILDCARD", "acme.com"},
		{"acme.com", "", "acme.com"},
		{"acme.com", "URL", ""}, // the apex host only, not its subdomains
		{"app.acme.com", "URL", ""},
		{"acme.zendesk.com", "URL", ""},
		{"acme.atlassian.net", "", ""},
		{"acme.okta.com", "", ""},
		{"https://github.com/acme/repo", "SOURCE_CODE", ""},
		{"https://github.com/acme/repo", "", ""},
		{"*.zendesk.com", "WILDCARD", ""},
		{"*.acme.herokuapp.com", "WILDCARD", ""},
		{"*.co.uk", "WILDCARD", ""},
		{"*.acme.co.uk", "WILDCARD", "acme.co.uk"},
		{"*.acme.com", "GOOGLE_PLAY_APP_ID", ""},
		{"10.0.0.0/8", "CIDR", ""},
		{"*.whatsapp.com", "WILDCARD", "whatsapp.com"},
	}
	for _, c := range cases {
		got, ok := ElementRoot(bbscope.ScopeElement{Target: c.target, Category: c.category})
		if c.want == "" && ok {
			t.Errorf("ElementRoot(%q,%q) = %q, want no root", c.target, c.category, got)
		}
		if c.want != "" && (!ok || got != c.want) {
			t.Errorf("ElementRoot(%q,%q) = %q,%v, want %q", c.target, c.category, got, ok, c.want)
		}
	}
}

func TestExtractRootDomainsIgnoresOutOfScope(t *testing.T) {
	got, err := ExtractRootDomains([]bbscope.ProgramData{{
		InScope: []bbscope.ScopeElement{
			{Target: "*.acme.com", Category: "WILDCARD"},
			{Target: "*.legacy.acme.com", Category: "WILDCARD"},
			{Target: "app.other.com", Category: "URL"},
		},
		OutOfScope: []bbscope.ScopeElement{
			{Target: "*.legacy.acme.com", Category: "WILDCARD"},
			{Target: "*.evil.com", Category: "WILDCARD"},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "acme.com" {
		t.Fatalf("roots = %v, want [acme.com]", got)
	}
}

func TestCatalogEntries(t *testing.T) {
	pd := bbscope.ProgramData{
		InScope: []bbscope.ScopeElement{
			{Target: "app.acme.com", Category: "URL"},
			{Target: "*.api.acme.com", Category: "WILDCARD"},
			{Target: "status.acme.com", Category: "URL"},
			{Target: "acme.zendesk.com", Category: "URL"},
			{Target: "https://github.com/acme/repo", Category: ""},
			{Target: "*.zendesk.com", Category: "WILDCARD"},
			{Target: "com.acme.app", Category: "GOOGLE_PLAY_APP_ID"},
		},
		OutOfScope: []bbscope.ScopeElement{
			{Target: "status.acme.com", Category: "URL"},
		},
	}
	got := map[string]bool{}
	for _, e := range CatalogEntries(pd) {
		got[e.Domain] = e.InScope
	}
	want := map[string]bool{
		"app.acme.com":     true,
		"*.api.acme.com":   true,
		"status.acme.com":  false, // listed both ways → out-of-scope wins
		"acme.zendesk.com": true,  // the tenant host itself is in scope
	}
	if len(got) != len(want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}
	for d, in := range want {
		if g, ok := got[d]; !ok || g != in {
			t.Errorf("entry %q = %v,%v want in_scope=%v", d, g, ok, in)
		}
	}
}

func TestExtractRawTargetsEmpty(t *testing.T) {
	got := ExtractRawTargets(nil)
	if len(got) != 0 {
		t.Errorf("ExtractRawTargets(nil) len = %d, want 0", len(got))
	}
	got = ExtractRawTargets([]bbscope.ProgramData{})
	if len(got) != 0 {
		t.Errorf("ExtractRawTargets([]) len = %d, want 0", len(got))
	}
}

func TestExtractRawTargetsSingleProgram(t *testing.T) {
	programs := []bbscope.ProgramData{
		{
			Url: "https://example.com",
			InScope: []bbscope.ScopeElement{
				{Target: "example.com", Description: "", Category: "web_application"},
				{Target: "api.example.com", Description: "", Category: "api"},
			},
			OutOfScope: []bbscope.ScopeElement{
				{Target: "admin.example.com", Description: "", Category: ""},
			},
		},
	}
	got := ExtractRawTargets(programs)
	want := map[string]bool{
		"example.com":       true,
		"api.example.com":   true,
		"admin.example.com": true,
	}
	if len(got) != len(want) {
		t.Fatalf("ExtractRawTargets() len = %d, want %d: %v", len(got), len(want), got)
	}
	for _, tgt := range got {
		if !want[tgt] {
			t.Errorf("unexpected target %q in result", tgt)
		}
	}
}

func TestExtractRawTargetsDeduplicatesAcrossPrograms(t *testing.T) {
	programs := []bbscope.ProgramData{
		{
			Url: "https://example.com",
			InScope: []bbscope.ScopeElement{
				{Target: "example.com", Description: "", Category: "web_application"},
			},
		},
		{
			Url: "https://other.com",
			InScope: []bbscope.ScopeElement{
				{Target: "example.com", Description: "", Category: "web_application"},
				{Target: "other.com", Description: "", Category: "api"},
			},
		},
	}
	got := ExtractRawTargets(programs)
	if len(got) != 2 {
		t.Fatalf("ExtractRawTargets() len = %d, want 2 (deduplicated): %v", len(got), got)
	}
}

func TestExtractRawTargetsSkipsEmptyTargets(t *testing.T) {
	programs := []bbscope.ProgramData{
		{
			Url: "https://example.com",
			InScope: []bbscope.ScopeElement{
				{Target: "", Description: "", Category: ""},
				{Target: "example.com", Description: "", Category: "web_application"},
				{Target: "  ", Description: "", Category: ""},
			},
			OutOfScope: []bbscope.ScopeElement{
				{Target: "", Description: "", Category: ""},
			},
		},
	}
	got := ExtractRawTargets(programs)
	if len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("ExtractRawTargets() = %v, want [example.com]", got)
	}
}

func TestExtractRawTargetsTrimsWhitespace(t *testing.T) {
	programs := []bbscope.ProgramData{
		{
			Url: "https://example.com",
			InScope: []bbscope.ScopeElement{
				{Target: "  example.com  ", Description: "", Category: ""},
			},
		},
	}
	got := ExtractRawTargets(programs)
	if len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("ExtractRawTargets() = %v, want [example.com]", got)
	}
}

func TestExtractRawTargetsOnlyOutOfScope(t *testing.T) {
	programs := []bbscope.ProgramData{
		{
			Url:        "https://example.com",
			InScope:    []bbscope.ScopeElement{},
			OutOfScope: []bbscope.ScopeElement{
				{Target: "out.example.com", Description: "", Category: ""},
			},
		},
	}
	got := ExtractRawTargets(programs)
	if len(got) != 1 || got[0] != "out.example.com" {
		t.Fatalf("ExtractRawTargets() = %v, want [out.example.com]", got)
	}
}

func TestExtractRawTargetsMultiplePrograms(t *testing.T) {
	programs := []bbscope.ProgramData{
		{
			Url: "https://hackerone.com/program1",
			InScope: []bbscope.ScopeElement{
				{Target: "*.example.com", Description: "wildcard", Category: "web_application"},
				{Target: "api.example.com", Description: "api", Category: "api"},
			},
		},
		{
			Url: "https://hackerone.com/program2",
			InScope: []bbscope.ScopeElement{
				{Target: "other.com", Description: "", Category: "web_application"},
			},
			OutOfScope: []bbscope.ScopeElement{
				{Target: "staging.other.com", Description: "", Category: ""},
			},
		},
	}
	got := ExtractRawTargets(programs)
	if len(got) != 4 {
		t.Fatalf("ExtractRawTargets() len = %d, want 4: %v", len(got), got)
	}
}
