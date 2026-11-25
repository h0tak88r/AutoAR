package nuclei

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	nucleiSDK "github.com/projectdiscovery/nuclei/v3/lib"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func TestSanitizeNucleiTarget(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		want   string
		wantOK bool
	}{
		{"plain host", "example.com", "example.com", true},
		{"subdomain", "sub.example.com", "sub.example.com", true},
		{"host with port", "example.com:8080", "example.com:8080", true},
		{"https url", "https://example.com", "https://example.com", true},
		{"http url with path", "http://example.com/a/b", "http://example.com/a/b", true},
		{"trims surrounding whitespace", "  example.com\t", "example.com", true},
		{"empty", "", "", false},
		{"only whitespace", "   ", "", false},
		{"internal space", "exa mple.com", "", false},
		{"angle brackets", "e<b>x.com", "", false},
		{"double quote", `ex"ample.com`, "", false},
		{"single quote", "ex'ample.com", "", false},
		{"backtick", "ex`ample.com", "", false},
		{"non-http scheme", "ftp://example.com", "", false},
		{"scheme without host", "http://", "", false},
		{"printf placeholder", "http://ex%sample.com", "", false},
		{"trailing percent", "example.com%", "", false},
		{"underscore is not a host", "not_a_host", "", false},
		{"html-escaped bracket is rejected after unescape", "example.com&lt;script", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := sanitizeNucleiTarget(tc.in)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("sanitizeNucleiTarget(%q) = (%q, %v), want (%q, %v)",
					tc.in, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestReadTargetLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	content := strings.Join([]string{
		"example.com",
		"example.com",     // duplicate -> deduped
		"https://foo.com", // valid URL
		"bad target",      // contains a space -> skipped
		"<script>",        // angle brackets -> skipped
		"example.com:443", // host:port -> valid
		"",                // blank line -> skipped
		"sub.example.com",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := readTargetLines(path)
	if err != nil {
		t.Fatalf("readTargetLines error: %v", err)
	}
	want := []string{"example.com", "https://foo.com", "example.com:443", "sub.example.com"}
	if len(got) != len(want) {
		t.Fatalf("readTargetLines returned %d targets %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("target[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

func TestReadTargetLinesMissingFile(t *testing.T) {
	if _, err := readTargetLines(filepath.Join(t.TempDir(), "does-not-exist.txt")); err == nil {
		t.Fatal("expected an error reading a missing target file, got nil")
	}
}

func TestCountLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "count.txt")
	// Two blank lines (one interior, one trailing) must not be counted.
	if err := os.WriteFile(path, []byte("a\nb\n\nc\n"), 0644); err != nil {
		t.Fatal(err)
	}
	n, err := countLines(path)
	if err != nil {
		t.Fatalf("countLines error: %v", err)
	}
	if n != 3 {
		t.Errorf("countLines = %d, want 3", n)
	}
}

func TestCountLinesEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	n, err := countLines(path)
	if err != nil {
		t.Fatalf("countLines error: %v", err)
	}
	if n != 0 {
		t.Errorf("countLines(empty) = %d, want 0", n)
	}
}

func TestCountLinesMissingFile(t *testing.T) {
	if _, err := countLines(filepath.Join(t.TempDir(), "does-not-exist.txt")); err == nil {
		t.Fatal("expected an error counting lines in a missing file, got nil")
	}
}

func TestScanRequestHeadersDefault(t *testing.T) {
	t.Setenv("AUTOAR_SCAN_USER_AGENT", "") // force the default branch

	got := scanRequestHeaders()
	if len(got) != 1 {
		t.Fatalf("scanRequestHeaders() = %#v, want exactly one header", got)
	}
	if !strings.HasPrefix(got[0], "User-Agent: ") {
		t.Errorf("header %q is missing the 'User-Agent: ' prefix", got[0])
	}
	// The default must look like a real browser, not nuclei's self-identifying UA
	// (commodity WAFs reject the latter, producing silent false negatives).
	if !strings.Contains(got[0], "Mozilla/5.0") || !strings.Contains(got[0], "Chrome/") {
		t.Errorf("default User-Agent %q does not look like a browser", got[0])
	}
	if strings.Contains(strings.ToLower(got[0]), "nuclei") {
		t.Errorf("default User-Agent %q must not identify as nuclei", got[0])
	}
}

func TestScanRequestHeadersOverride(t *testing.T) {
	const custom = "MyScanner/1.2 (contact@example.com)"
	t.Setenv("AUTOAR_SCAN_USER_AGENT", custom)

	got := scanRequestHeaders()
	want := "User-Agent: " + custom
	if len(got) != 1 || got[0] != want {
		t.Fatalf("scanRequestHeaders() = %#v, want [%q]", got, want)
	}
}

func TestExtractDomainFromURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://example.com/path", "example.com"},
		{"http://example.com", "example.com"},
		{"https://sub.example.com:8443/a/b", "sub.example.com:8443"},
		{"http://example.com/", "example.com"},
		{"example.com", "example.com"},
		{"example.com/foo", "example.com"},
	}
	for _, tc := range cases {
		if got := extractDomainFromURL(tc.in); got != tc.want {
			t.Errorf("extractDomainFromURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDirExists(t *testing.T) {
	dir := t.TempDir()
	if !dirExists(dir) {
		t.Errorf("dirExists(%q) = false, want true", dir)
	}

	file := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if dirExists(file) {
		t.Errorf("dirExists(%q) = true, want false (it is a regular file)", file)
	}
	if dirExists(filepath.Join(dir, "missing")) {
		t.Errorf("dirExists(missing path) = true, want false")
	}
}

func TestMaxHelper(t *testing.T) {
	cases := []struct{ a, b, want int }{
		{3, 7, 7},
		{7, 3, 7},
		{4, 4, 4},
		{-1, -5, -1},
	}
	for _, tc := range cases {
		if got := max(tc.a, tc.b); got != tc.want {
			t.Errorf("max(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestBuildEngineReleasesInitLockOnPanic(t *testing.T) {
	orig := newNucleiEngine
	t.Cleanup(func() { newNucleiEngine = orig })
	newNucleiEngine = func(context.Context, ...nucleiSDK.NucleiSDKOptions) (*nucleiSDK.NucleiEngine, error) {
		panic("sdk constructor blew up")
	}
	func() {
		defer func() { _ = recover() }()
		_, _ = buildEngine(context.Background(), "x")
	}()
	if !nucleiEngineInitMu.TryLock() {
		t.Fatal("nucleiEngineInitMu still held after a constructor panic — every later nuclei run would hang")
	}
	nucleiEngineInitMu.Unlock()
}

func TestBuildEngineFailsWhenNothingCompiles(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a real nuclei engine")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("id: broken\nthis is: [not a template\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := buildEngine(context.Background(), dir,
		nucleiSDK.DisableUpdateCheck(),
		nucleiSDK.WithVerbosity(nucleiSDK.VerbosityOptions{Silent: true}),
		nucleiSDK.WithTemplatesOrWorkflows(nucleiSDK.TemplateSources{Templates: []string{dir}}),
		nucleiSDK.WithSandboxOptions(false, true),
	)
	if err == nil {
		engine.Close()
		t.Fatal("want an error for a template dir that compiles to zero templates")
	}
	if !nucleiEngineInitMu.TryLock() {
		t.Fatal("init lock held after a failed build")
	}
	nucleiEngineInitMu.Unlock()
}

// TestRunGlobalTemplateSandboxBlocksLocalNetwork runs a trivial template
// against a loopback server: unsandboxed it matches, sandboxed (auto-run
// mode) the engine must refuse the local address.
func TestRunGlobalTemplateSandboxBlocksLocalNetwork(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a real nuclei engine")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("autoar-sandbox-marker"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	tpl := filepath.Join(dir, "marker.yaml")
	if err := os.WriteFile(tpl, []byte(`id: autoar-sandbox-test
info:
  name: sandbox test
  author: autoar
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "autoar-sandbox-marker"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	targets := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(targets, []byte(srv.URL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(sandbox bool) int {
		var hits int
		var mu sync.Mutex
		out := filepath.Join(dir, fmt.Sprintf("out-%v.json", sandbox))
		err := RunGlobalTemplateWithOptions(context.Background(), targets, tpl, out, 5, RunOptions{Sandbox: sandbox},
			func(*nucleiOutput.ResultEvent) { mu.Lock(); hits++; mu.Unlock() })
		if err != nil {
			t.Fatalf("RunGlobalTemplateWithOptions(sandbox=%v): %v", sandbox, err)
		}
		return hits
	}
	if got := run(false); got != 1 {
		t.Fatalf("unsandboxed run: %d hits, want 1 (template/target wiring broken)", got)
	}
	if got := run(true); got != 0 {
		t.Fatalf("sandboxed run reached a loopback target (%d hits) — local network not restricted", got)
	}
}
