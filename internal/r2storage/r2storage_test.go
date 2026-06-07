package r2storage

import (
	"os"
	"testing"
)

func TestGetContentTypeKnownExtensions(t *testing.T) {
	tests := []struct {
		filePath string
		want     string
	}{
		{"data.json", "application/json"},
		{"log.txt", "text/plain"},
		{"app.log", "text/plain"},
		{"page.html", "text/html"},
		{"config.xml", "application/xml"},
		{"app.ipa", "application/octet-stream"},
		{"archive.zip", "application/zip"},
		{"backup.tar", "application/x-tar"},
		{"archive.gz", "application/gzip"},
		{"data.db", "application/x-sqlite3"},
		{"query.sql", "application/sql"},
		{"report.pdf", "application/pdf"},
		{"icon.png", "image/png"},
		{"photo.jpg", "image/jpeg"},
		{"photo.jpeg", "image/jpeg"},
		{"UPPERCASE.PNG", "image/png"},
		{"MixedCase.JpG", "image/jpeg"},
	}

	for _, tt := range tests {
		t.Run(tt.filePath, func(t *testing.T) {
			got := getContentType(tt.filePath)
			if got != tt.want {
				t.Errorf("getContentType(%q) = %q, want %q", tt.filePath, got, tt.want)
			}
		})
	}
}

func TestGetContentTypeUnknownExtension(t *testing.T) {
	got := getContentType("file.unknown")
	if got != "application/octet-stream" {
		t.Errorf("getContentType() = %q, want %q", got, "application/octet-stream")
	}
}

func TestGetContentTypeNoExtension(t *testing.T) {
	got := getContentType("Makefile")
	if got != "application/octet-stream" {
		t.Errorf("getContentType() = %q, want %q", got, "application/octet-stream")
	}
}

func TestGetFileSizeLimit(t *testing.T) {
	got := GetFileSizeLimit()
	want := int64(25 * 1024 * 1024)
	if got != want {
		t.Errorf("GetFileSizeLimit() = %d, want %d", got, want)
	}
}

func TestShouldUseR2NotEnabled(t *testing.T) {
	oldEnabled := isEnabled
	isEnabled = false
	defer func() { isEnabled = oldEnabled }()

	if ShouldUseR2("somefile.txt") {
		t.Error("ShouldUseR2() should return false when R2 is not enabled")
	}
}

func TestShouldUseR2FileDoesNotExist(t *testing.T) {
	oldEnabled := isEnabled
	isEnabled = true
	defer func() { isEnabled = oldEnabled }()

	if ShouldUseR2("/nonexistent/file.txt") {
		t.Error("ShouldUseR2() should return false for non-existent file")
	}
}

func TestShouldUseR2SmallFile(t *testing.T) {
	oldEnabled := isEnabled
	isEnabled = true
	defer func() { isEnabled = oldEnabled }()

	tmpFile, err := os.CreateTemp("", "r2test_small_*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString("small content"); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	if ShouldUseR2(tmpFile.Name()) {
		t.Error("ShouldUseR2() should return false for small file")
	}
}

func TestExtractObjectKeyFromPublicURLEmpty(t *testing.T) {
	got := ExtractObjectKeyFromPublicURL("")
	if got != "" {
		t.Errorf("ExtractObjectKeyFromPublicURL(\"\") = %q, want \"\"", got)
	}

	got = ExtractObjectKeyFromPublicURL("   ")
	if got != "" {
		t.Errorf("ExtractObjectKeyFromPublicURL(\"   \") = %q, want \"\"", got)
	}
}

func TestExtractObjectKeyFromPublicURLInvalid(t *testing.T) {
	got := ExtractObjectKeyFromPublicURL("not-a%valid%url%%")
	if got != "" {
		t.Errorf("ExtractObjectKeyFromPublicURL() with invalid URL = %q, want \"\"", got)
	}
}

func TestExtractObjectKeyFromPublicURLSimple(t *testing.T) {
	got := ExtractObjectKeyFromPublicURL("https://example.com/path/to/file.zip")
	if got != "path/to/file.zip" {
		t.Errorf("ExtractObjectKeyFromPublicURL() = %q, want %q", got, "path/to/file.zip")
	}
}

func TestExtractObjectKeyFromPublicURLNoPath(t *testing.T) {
	got := ExtractObjectKeyFromPublicURL("https://example.com")
	if got != "" {
		t.Errorf("ExtractObjectKeyFromPublicURL() = %q, want \"\"", got)
	}
}

func TestExtractObjectKeyFromPublicURLWithR2Base(t *testing.T) {
	oldCfg := r2Config
	r2Config = &R2Config{
		PublicURL: "https://cdn.example.com/r2/",
	}
	defer func() { r2Config = oldCfg }()

	got := ExtractObjectKeyFromPublicURL("https://cdn.example.com/r2/results/domain.zip")
	if got != "results/domain.zip" {
		t.Errorf("ExtractObjectKeyFromPublicURL() = %q, want %q", got, "results/domain.zip")
	}
}

func TestExtractObjectKeyFromPublicURLDifferentHost(t *testing.T) {
	oldCfg := r2Config
	r2Config = &R2Config{
		PublicURL: "https://r2.example.com/bucket/",
	}
	defer func() { r2Config = oldCfg }()

	got := ExtractObjectKeyFromPublicURL("https://other.example.com/results/file.zip")
	if got != "results/file.zip" {
		t.Errorf("ExtractObjectKeyFromPublicURL() = %q, want %q", got, "results/file.zip")
	}
}

func TestExtractObjectKeyFromPublicURLTrailingSlash(t *testing.T) {
	got := ExtractObjectKeyFromPublicURL("https://example.com//path//to/file.zip")
	if got != "path//to/file.zip" {
		t.Errorf("ExtractObjectKeyFromPublicURL() = %q, want %q", got, "path//to/file.zip")
	}
}

func TestPublicURLForKeyNotEnabled(t *testing.T) {
	oldCfg := r2Config
	r2Config = nil
	defer func() { r2Config = oldCfg }()

	got := PublicURLForKey("results/file.zip")
	if got != "" {
		t.Errorf("PublicURLForKey() = %q, want \"\" when not configured", got)
	}
}

func TestPublicURLForKeyDisabled(t *testing.T) {
	oldCfg := r2Config
	r2Config = &R2Config{Enabled: false}
	defer func() { r2Config = oldCfg }()

	got := PublicURLForKey("results/file.zip")
	if got != "" {
		t.Errorf("PublicURLForKey() = %q, want \"\" when disabled", got)
	}
}

func TestPublicURLForKeyEmptyPublicURL(t *testing.T) {
	oldCfg := r2Config
	r2Config = &R2Config{Enabled: true, PublicURL: ""}
	defer func() { r2Config = oldCfg }()

	got := PublicURLForKey("results/file.zip")
	if got != "" {
		t.Errorf("PublicURLForKey() = %q, want \"\" when PublicURL empty", got)
	}
}

func TestPublicURLForKeyValid(t *testing.T) {
	oldCfg := r2Config
	r2Config = &R2Config{Enabled: true, PublicURL: "https://cdn.example.com/r2"}
	defer func() { r2Config = oldCfg }()

	got := PublicURLForKey("results/file.zip")
	want := "https://cdn.example.com/r2/results/file.zip"
	if got != want {
		t.Errorf("PublicURLForKey() = %q, want %q", got, want)
	}
}

func TestPublicURLForKeyTrailingSlashPublicURL(t *testing.T) {
	oldCfg := r2Config
	r2Config = &R2Config{Enabled: true, PublicURL: "https://cdn.example.com/r2/"}
	defer func() { r2Config = oldCfg }()

	got := PublicURLForKey("results/file.zip")
	want := "https://cdn.example.com/r2/results/file.zip"
	if got != want {
		t.Errorf("PublicURLForKey() = %q, want %q", got, want)
	}
}

func TestPublicURLForKeyLeadingSlash(t *testing.T) {
	oldCfg := r2Config
	r2Config = &R2Config{Enabled: true, PublicURL: "https://cdn.example.com"}
	defer func() { r2Config = oldCfg }()

	got := PublicURLForKey("/results/file.zip")
	want := "https://cdn.example.com/results/file.zip"
	if got != want {
		t.Errorf("PublicURLForKey() = %q, want %q", got, want)
	}
}

func TestPublicURLForKeyEmptyKey(t *testing.T) {
	oldCfg := r2Config
	r2Config = &R2Config{Enabled: true, PublicURL: "https://cdn.example.com"}
	defer func() { r2Config = oldCfg }()

	got := PublicURLForKey("")
	if got != "" {
		t.Errorf("PublicURLForKey(\"\") = %q, want \"\"", got)
	}
}

func TestLoadConfigDisabled(t *testing.T) {
	os.Setenv("USE_R2_STORAGE", "false")
	defer os.Unsetenv("USE_R2_STORAGE")

	cfg := LoadConfig()
	if cfg.Enabled {
		t.Error("LoadConfig() should return disabled config when USE_R2_STORAGE is false")
	}
}

func TestLoadConfigMissingRequiredFields(t *testing.T) {
	os.Setenv("USE_R2_STORAGE", "true")
	os.Setenv("R2_BUCKET_NAME", "test-bucket")
	os.Unsetenv("R2_ACCESS_KEY_ID")
	os.Unsetenv("R2_SECRET_KEY")
	defer func() {
		os.Unsetenv("USE_R2_STORAGE")
		os.Unsetenv("R2_BUCKET_NAME")
	}()

	cfg := LoadConfig()
	if cfg.Enabled {
		t.Error("LoadConfig() should disable when required fields are missing")
	}
}

func TestR2CtxBgReturnsBackgroundContext(t *testing.T) {
	ctx := r2ctxBg()
	if ctx == nil {
		t.Fatal("r2ctxBg() should return a non-nil context")
	}
}
