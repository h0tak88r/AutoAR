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

func TestIsMobileOrAppTargetKeywordMatch(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		category string
		want     bool
	}{
		{"ios keyword in target", "my-ios-app.example.com", "", true},
		{"android keyword in target", "android.example.com", "", true},
		{"apple keyword in target", "apple-pay.example.com", "", true},
		{"aws keyword in target", "aws.example.com", "", true},
		{"azure keyword in target", "azure.example.com", "", true},
		{"gcp keyword in target", "gcp.example.com", "", true},
		{"cloud keyword in target", "cloud.example.com", "", true},
		{"s3 keyword in target", "s3.example.com", "", true},
		{"ec2 keyword in target", "ec2.example.com", "", true},
		{"lambda keyword in target", "lambda.example.com", "", true},
		{"playstore keyword in target", "playstore.example.com", "", true},
		{"testflight keyword in target", "testflight.example.com", "", true},
		{"mobile keyword in target", "mobile.example.com", "", true},
		{"app keyword in target", "my-app.example.com", "", true},
		{"binary keyword in target", "binary.example.com", "", true},
		{"smart_contract keyword in target", "smart_contract.example.com", "", true},
		{"source_code keyword in target", "source_code.example.com", "", true},
		{"hardware keyword in target", "hardware.example.com", "", true},
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

func TestIsMobileOrAppTargetCaseInsensitive(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		category string
		want     bool
	}{
		{"uppercase category", "example.com", "MOBILE", true},
		{"mixed case category", "example.com", "Android", true},
		{"uppercase target", "IOS.example.com", "", true},
		{"mixed case target", "PlayStore.example.com", "", true},
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
	// "code" is in the category list, so "source_code" should match
	if !isMobileOrAppTarget("example.com", "source_code") {
		t.Error("isMobileOrAppTarget(example.com, source_code) should match via 'code'")
	}
	// "apple" is in the category list, so "apple_store_app_id" should match
	if !isMobileOrAppTarget("example.com", "apple_store_app_id") {
		t.Error("isMobileOrAppTarget(example.com, apple_store_app_id) should match via 'apple'")
	}
}

func TestIsMobileOrAppTargetPartialKeywordMatch(t *testing.T) {
	// "app" is in keywords, so "application" should match
	if !isMobileOrAppTarget("my-application.com", "") {
		t.Error("isMobileOrAppTarget(my-application.com, '') should match via 'app' keyword")
	}
	// "exe" is in keywords, so "executable" should match
	if !isMobileOrAppTarget("executable-files.com", "") {
		t.Error("isMobileOrAppTarget(executable-files.com, '') should match via 'exe' keyword")
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
