package subdomains

import (
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// providerEnvVars is every environment variable generateSubfinderConfigFromEnv
// inspects. Tests blank all of them first so the generated config depends only
// on what each test sets — never on the developer's real environment.
var providerEnvVars = []string{
	"GITHUB_TOKEN", "SECURITYTRAILS_API_KEY", "VIRUSTOTAL_API_KEY",
	"WORDPRESS_API_KEY", "BEVIGIL_API_KEY", "BINARYEDGE_API_KEY",
	"URLSCAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET",
	"CERTSPOTTER_API_KEY", "CHAOS_API_KEY", "FOFA_EMAIL", "FOFA_KEY",
	"FULLHUNT_API_KEY", "INTELX_API_KEY", "PASSIVETOTAL_USERNAME",
	"PASSIVETOTAL_API_KEY", "QUAKE_USERNAME", "QUAKE_PASSWORD",
	"THREATBOOK_API_KEY", "WHOISXMLAPI_API_KEY", "ZOOMEYE_USERNAME",
	"ZOOMEYE_PASSWORD", "ZOOMEYEAPI_API_KEY", "SHODAN_API_KEYS",
	"SHODAN_API_KEY",
}

// isolateAPIKeys makes generateSubfinderConfigFromEnv deterministic and
// hermetic. apikeys.All is DB-first with an env fallback; pointing DB_TYPE at an
// unsupported driver forces db.Init to error, so the env fallback is always
// taken regardless of any DB the host machine happens to have configured. Every
// provider variable is then blanked so only the test's own Setenv calls matter.
func isolateAPIKeys(t *testing.T) {
	t.Helper()
	t.Setenv("DB_TYPE", "none-for-tests")
	for _, k := range providerEnvVars {
		t.Setenv(k, "")
	}
}

// generateAndParse runs the generator, asserts a file was produced, parses it
// with gopkg.in/yaml.v3 (proving the emitted YAML is valid), and returns both
// the raw text and the decoded top-level map.
func generateAndParse(t *testing.T) (string, map[string]interface{}) {
	t.Helper()
	path, err := generateSubfinderConfigFromEnv()
	if err != nil {
		t.Fatalf("generateSubfinderConfigFromEnv() error = %v", err)
	}
	if path == "" {
		t.Fatalf("generateSubfinderConfigFromEnv() returned empty path, want a config file")
	}
	t.Cleanup(func() { _ = os.Remove(path) })

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading generated config %s: %v", path, err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("generated config is not valid YAML: %v\n---\n%s", err, data)
	}
	return string(data), parsed
}

// A paired provider (zoomeye = [username, password]) whose password carries a
// double-quote AND a backslash must survive into a clean, parseable YAML list.
// This is the regression guard for the %q escaping fix: a naive plain-%s writer
// would emit ["user", "p"a\ss"] and corrupt the whole file.
func TestGenerateSubfinderConfig_EscapesPairedProviderValue(t *testing.T) {
	isolateAPIKeys(t)
	const user = "zoom_user"
	const pass = `p"a\ss` // embedded " and \, no surrounding quotes/whitespace
	t.Setenv("ZOOMEYE_USERNAME", user)
	t.Setenv("ZOOMEYE_PASSWORD", pass)

	content, parsed := generateAndParse(t)

	list, ok := parsed["zoomeye"].([]interface{})
	if !ok {
		t.Fatalf("zoomeye is not a YAML list: %#v", parsed["zoomeye"])
	}
	if len(list) != 2 {
		t.Fatalf("zoomeye list len = %d, want 2 (%#v)", len(list), list)
	}
	if list[0] != user {
		t.Errorf("zoomeye[0] = %q, want %q", list[0], user)
	}
	if list[1] != pass {
		t.Errorf("zoomeye[1] round-trip = %q, want %q (quote/backslash mangled)", list[1], pass)
	}
	// The raw line must Go-quote the value: " -> \" and \ -> \\.
	if !strings.Contains(content, `"p\"a\\ss"`) {
		t.Errorf("raw YAML is not correctly escaped; got:\n%s", content)
	}
}

// The single-value provider loop must escape values the same way. A GitHub token
// containing a quote and backslash must round-trip as a one-element list.
func TestGenerateSubfinderConfig_EscapesSingleProviderValue(t *testing.T) {
	isolateAPIKeys(t)
	const token = `gh"tok\en` // embedded " and \, no surrounding quotes/whitespace
	t.Setenv("GITHUB_TOKEN", token)

	content, parsed := generateAndParse(t)

	list, ok := parsed["github"].([]interface{})
	if !ok {
		t.Fatalf("github is not a YAML list: %#v", parsed["github"])
	}
	if len(list) != 1 || list[0] != token {
		t.Fatalf("github = %#v, want single-element list [%q]", list, token)
	}
	if !strings.Contains(content, `"gh\"tok\\en"`) {
		t.Errorf("raw YAML is not correctly escaped; got:\n%s", content)
	}
}

// A comma-separated multi-key value must expand into a multi-item YAML list —
// both via the generic single-value loop (virustotal) and the dedicated shodan
// branch.
func TestGenerateSubfinderConfig_MultiKeyBecomesList(t *testing.T) {
	isolateAPIKeys(t)
	t.Setenv("VIRUSTOTAL_API_KEY", "vt1,vt2,vt3")
	t.Setenv("SHODAN_API_KEYS", "s1,s2")

	_, parsed := generateAndParse(t)

	vt, ok := parsed["virustotal"].([]interface{})
	if !ok || len(vt) != 3 {
		t.Fatalf("virustotal = %#v, want a 3-item list", parsed["virustotal"])
	}
	for i, want := range []string{"vt1", "vt2", "vt3"} {
		if vt[i] != want {
			t.Errorf("virustotal[%d] = %v, want %q", i, vt[i], want)
		}
	}

	sh, ok := parsed["shodan"].([]interface{})
	if !ok || len(sh) != 2 {
		t.Fatalf("shodan = %#v, want a 2-item list", parsed["shodan"])
	}
	for i, want := range []string{"s1", "s2"} {
		if sh[i] != want {
			t.Errorf("shodan[%d] = %v, want %q", i, sh[i], want)
		}
	}
}

// With no provider keys configured at all, the generator writes no file and
// returns an empty path so subfinder falls back to its default providers.
func TestGenerateSubfinderConfig_NoProvidersReturnsEmpty(t *testing.T) {
	isolateAPIKeys(t)

	path, err := generateSubfinderConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "" {
		t.Errorf("expected empty path with no providers configured, got %q", path)
	}
}

// A paired provider needs BOTH halves; supplying only one must not emit the
// provider (and, with nothing else configured, yields an empty path).
func TestGenerateSubfinderConfig_PairedProviderNeedsBothValues(t *testing.T) {
	isolateAPIKeys(t)
	t.Setenv("QUAKE_USERNAME", "solo") // password intentionally left blank

	path, err := generateSubfinderConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "" {
		t.Errorf("expected empty path when only half of a paired provider is set, got %q", path)
	}
}

// passiveSourceClient must carry a non-zero timeout; without it a stalled read
// from a passive source wedges getSubdomainsFromAPIs' wg.Wait() forever.
func TestPassiveSourceClientHasTimeout(t *testing.T) {
	if passiveSourceClient == nil {
		t.Fatal("passiveSourceClient is nil")
	}
	if passiveSourceClient.Timeout <= 0 {
		t.Fatalf("passiveSourceClient.Timeout = %v, want > 0", passiveSourceClient.Timeout)
	}
	if want := 30 * time.Second; passiveSourceClient.Timeout != want {
		t.Errorf("passiveSourceClient.Timeout = %v, want %v", passiveSourceClient.Timeout, want)
	}
}
