package githubscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReconScanFileCategories(t *testing.T) {
	into := map[string]map[string]bool{}
	for cat := range reconCategories {
		into[cat] = map[string]bool{}
	}
	content := `
const API = "https://internal-api.acme.com/v2/users";
const adminPath = "/admin/panel";
const db = "postgres://svc:hunter2@10.0.4.12:5432/prod";
const bucket = "acme-prod-backups.s3.eu-west-1.amazonaws.com";
if (DEBUG = true) { console.log(process.env.STRIPE_SECRET_KEY); }
// TODO: remove this hardcoded api_key before production
fetch("https://auth.acme.com/oauth/authorize?client_id=x");
contact: admin@acme.com
//# sourceMappingURL=app.min.js.map
host: k8s-worker.internal.acme.internal
`
	reconScanFile("src/app.js", content, into)

	if len(into["endpoints"]) == 0 {
		t.Error("endpoints category empty — URL regex failed")
	}
	foundDB, foundS3, foundEnv, foundTODO, foundOAuth, foundMap, foundIntHost := false, false, false, false, false, false, false
	for k := range into["infra"] {
		if strings.Contains(k, "postgres://") {
			foundDB = true
		}
		if strings.Contains(k, ".internal") {
			foundIntHost = true
		}
	}
	for k := range into["cloud"] {
		if strings.Contains(k, "acme-prod-backups") {
			foundS3 = true
		}
	}
	for k := range into["debug-admin"] {
		if strings.Contains(k, "STRIPE_SECRET_KEY") || strings.Contains(k, "DEBUG") {
			foundEnv = true
		}
	}
	for k := range into["comments"] {
		if strings.Contains(k, "api_key") {
			foundTODO = true
		}
	}
	for k := range into["auth"] {
		if strings.Contains(k, "oauth/authorize") {
			foundOAuth = true
		}
	}
	for k := range into["sourcemaps"] {
		if strings.Contains(k, "sourceMappingURL") {
			foundMap = true
		}
	}
	for k, want := range map[string]bool{"postgres": foundDB, "s3": foundS3, "env/debug": foundEnv, "todo": foundTODO, "oauth": foundOAuth, "sourcemap": foundMap, "internal host": foundIntHost} {
		if !want {
			t.Errorf("expected %s finding, got none (category contents: infra=%v cloud=%v debug=%v comments=%v auth=%v maps=%v infra=%v)",
				k, into["endpoints"], into["cloud"], into["debug-admin"], into["comments"], into["auth"], into["sourcemaps"], into["infra"])
		}
	}
	// emails category
	if len(into["emails"]) == 0 {
		t.Error("emails category empty")
	}
}

func TestReconScanFileSkipsBinary(t *testing.T) {
	into := map[string]map[string]bool{}
	for cat := range reconCategories {
		into[cat] = map[string]bool{}
	}
	bin := string([]byte{0x00, 0x01, 0x02}) + "https://should-not-appear.example.com/api"
	reconScanFile("blob.bin", bin, into)
	for k := range into["endpoints"] {
		if strings.Contains(k, "should-not-appear") {
			t.Fatal("binary file was scanned")
		}
	}
}

func TestReconScanWritesDigest(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "README.md"), []byte("See https://api.acme-test.internal/v1 for docs"), 0o644)
	n, digest, err := ReconScan(dir, dir)
	if err != nil {
		t.Fatalf("ReconScan: %v", err)
	}
	data, _ := os.ReadFile(digest)
	if !strings.Contains(string(data), "Repo recon digest") {
		t.Error("digest missing header")
	}
	if _, err := os.Stat(filepath.Join(dir, "recon.json")); err != nil {
		t.Error("recon.json not written")
	}
	_ = n
}
