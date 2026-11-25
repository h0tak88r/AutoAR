package githubscan

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestReconScanSkipsSymlinks: a hostile repo can commit symlinks (a.js ->
// /proc/self/environ, package.json -> /app/.env). Walk's Lstat sizes let them
// pass the size check; the read must not follow them.
func TestReconScanSkipsSymlinks(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "server.env")
	if err := os.WriteFile(secret, []byte("DB=postgres://admin:SERVERLEAK@10.0.0.9/prod\nhttps://leak.example.org/SERVERLEAK\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	for _, name := range []string{"a.js", "package.json", "go.mod"} {
		if err := os.Symlink(secret, filepath.Join(repo, name)); err != nil {
			t.Skipf("symlinks unsupported: %v", err)
		}
	}
	if err := os.Symlink("/dev/zero", filepath.Join(repo, "zero.js")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "ok.js"), []byte(`fetch("https://api.repo-own.example.net/v1")`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	_, digest, err := ReconScan(repo, out)
	if err != nil {
		t.Fatalf("ReconScan: %v", err)
	}
	md, _ := os.ReadFile(digest)
	js, _ := os.ReadFile(filepath.Join(out, "recon.json"))
	for _, b := range [][]byte{md, js} {
		if strings.Contains(string(b), "SERVERLEAK") {
			t.Fatalf("symlink target content surfaced in recon output:\n%s", b)
		}
	}
	if !strings.Contains(string(md), "api.repo-own.example.net") {
		t.Fatalf("regular file not scanned:\n%s", md)
	}
}

func TestReadRegularFile(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(reg, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, err := readRegularFile(reg, 4); err != nil || string(b) != "0123" {
		t.Fatalf("regular file: %q %v", b, err)
	}
	link := filepath.Join(dir, "l.txt")
	if err := os.Symlink(reg, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if _, err := readRegularFile(link, 4); err == nil {
		t.Fatal("symlink was followed")
	}
	if _, err := readRegularFile(dir, 4); err == nil {
		t.Fatal("directory accepted")
	}
}

// TestSanitizeTruffleHogLine: the plaintext secret (Raw/RawV2) must never be
// persisted; detector, location, Verified and a redacted form stay.
func TestSanitizeTruffleHogLine(t *testing.T) {
	line := `{"DetectorName":"AWS","Verified":true,"Raw":"AKIAIOSFODNN7EXAMPLE","RawV2":"AKIAIOSFODNN7EXAMPLEwJalrXUtnFEMI","Redacted":"","SourceMetadata":{"Data":{"Git":{"file":"a.py","line":3}}}}`
	clean, ok := sanitizeTruffleHogLine(line)
	if !ok {
		t.Fatal("valid line rejected")
	}
	if strings.Contains(clean, "IOSFODNN7") || strings.Contains(clean, `"Raw"`) || strings.Contains(clean, `"RawV2"`) {
		t.Fatalf("plaintext secret persisted: %s", clean)
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(clean), &m); err != nil {
		t.Fatal(err)
	}
	if m["DetectorName"] != "AWS" || m["Verified"] != true || m["SourceMetadata"] == nil {
		t.Fatalf("metadata lost: %v", m)
	}
	if red, _ := m["Redacted"].(string); !strings.HasPrefix(red, "AKIA…") {
		t.Fatalf("Redacted = %q, want masked stand-in", red)
	}

	// An existing Redacted is kept as-is.
	clean, _ = sanitizeTruffleHogLine(`{"Raw":"ghp_secretsecretsecret","Redacted":"ghp_****"}`)
	if !strings.Contains(clean, `"Redacted":"ghp_****"`) || strings.Contains(clean, "secretsecret") {
		t.Fatalf("existing Redacted handling: %s", clean)
	}
	if _, ok := sanitizeTruffleHogLine(`{not json`); ok {
		t.Fatal("unparseable line accepted")
	}
}

func TestReconIndexDir(t *testing.T) {
	root := filepath.Join("res", "github", "repos")
	cases := map[string]string{
		"owner/repo":  filepath.Join(root, "owner", "repo"),
		" acme/api ":  filepath.Join(root, "acme", "api"),
		"../../etc":   "",
		"owner/../..": "",
		"":            "",
	}
	for in, want := range cases {
		if got := reconIndexDir("res", in); got != want {
			t.Errorf("reconIndexDir(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPublishReconCopiesOnlyRecon(t *testing.T) {
	from := t.TempDir()
	for _, n := range []string{"recon.md", "recon.json", "secrets.json", "trufflehog.log"} {
		if err := os.WriteFile(filepath.Join(from, n), []byte(n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	idx := filepath.Join(t.TempDir(), "owner", "repo")
	publishRecon(from, idx)
	for _, n := range []string{"recon.md", "recon.json"} {
		if b, err := os.ReadFile(filepath.Join(idx, n)); err != nil || string(b) != n {
			t.Errorf("%s not published: %q %v", n, b, err)
		}
	}
	for _, n := range []string{"secrets.json", "trufflehog.log"} {
		if _, err := os.Stat(filepath.Join(idx, n)); err == nil {
			t.Errorf("%s must not be published to the index dir", n)
		}
	}
}

// TestShallowCloneRefusesNonHTTPS: only the https transport may be used — a
// submitted file:// URL must not clone the server's own repositories.
func TestShallowCloneRefusesNonHTTPS(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	src := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = src
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git %v: %v %s", args, err, out)
		}
	}
	run("init", "-q")
	if err := os.WriteFile(filepath.Join(src, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "f.txt")
	run("commit", "-q", "-m", "x")

	dest := filepath.Join(t.TempDir(), "source")
	if err := shallowClone("file://"+src, dest); err == nil {
		t.Fatal("file:// clone succeeded; want protocol refusal")
	} else if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("clone failed for another reason (want transport refusal): %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "f.txt")); err == nil {
		t.Fatal("file:// clone checked out content")
	}
}
