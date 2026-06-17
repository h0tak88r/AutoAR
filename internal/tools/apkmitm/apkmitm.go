// Package apkmitm is a Go reimplementation of niklashigi/apk-mitm's default
// patching: it prepares an Android APK for HTTPS interception by making the app
// trust user-installed CAs and dropping Network-Security-Config-based certificate
// pinning, then rebuilds and re-signs the APK with a debug key.
//
// It mirrors what apk-mitm does for a single .apk:
//  1. Decode with apktool.
//  2. Network security config: write a config whose base-config AND
//     debug-overrides trust the system + user certificate stores and permit
//     cleartext. If the app already ships a config, overwrite the file it points
//     at (so its <pin-set>/domain rules no longer apply); otherwise create one
//     and reference it from the manifest.
//  3. Manifest: set android:debuggable="true" (+ android:networkSecurityConfig
//     when we added a new config).
//  4. Rebuild with apktool.
//  5. Zipalign + re-sign with a debug key (uber-apk-signer).
//
// Like apk-mitm, this defeats Network-Security-Config-based pinning but NOT
// programmatic pinning (e.g. OkHttp CertificatePinner, custom TrustManagers) —
// those still require Frida/objection at runtime.
//
// The external tools (apktool, uber-apk-signer, a JRE) are only needed to run
// Patch(); they are bundled in the project's Docker image.
package apkmitm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// networkSecurityConfig trusts the system AND user certificate stores in both
// base-config and debug-overrides (the latter is what makes a debuggable build
// honour a user-added Burp/mitmproxy CA even past NSC pinning) and permits
// cleartext for testing — matching apk-mitm's effective config.
const networkSecurityConfig = `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
`

// nscResourceName is the res/xml resource we create when the app has none.
const nscResourceName = "nsc_mitm"

// Tool paths — overridable via env so the package isn't hard-wired to Docker.
func apktoolBin() string {
	if v := strings.TrimSpace(os.Getenv("APKTOOL_BIN")); v != "" {
		return v
	}
	return "apktool"
}

func javaBin() string {
	if v := strings.TrimSpace(os.Getenv("JAVA_BIN")); v != "" {
		return v
	}
	return "java"
}

func uberSignerJar() string {
	if v := strings.TrimSpace(os.Getenv("UBER_APK_SIGNER_JAR")); v != "" {
		return v
	}
	return "/usr/local/bin/uber-apk-signer.jar"
}

// CheckTools verifies the external dependencies are available, returning a clear
// error (so the API can respond 503 with guidance) when they are not.
func CheckTools() error {
	if _, err := exec.LookPath(apktoolBin()); err != nil {
		return fmt.Errorf("apktool not found (set APKTOOL_BIN or run inside the Docker image)")
	}
	if _, err := exec.LookPath(javaBin()); err != nil {
		return fmt.Errorf("java not found (a JRE is required to run uber-apk-signer)")
	}
	if _, err := os.Stat(uberSignerJar()); err != nil {
		return fmt.Errorf("uber-apk-signer.jar not found at %s (set UBER_APK_SIGNER_JAR)", uberSignerJar())
	}
	return nil
}

// Patch runs the full MITM-prep pipeline on inputAPK using workDir for scratch
// space, and returns the path to the patched, re-signed APK (inside workDir).
// The caller owns workDir and should remove it when done.
func Patch(inputAPK, workDir string) (string, error) {
	if err := CheckTools(); err != nil {
		return "", err
	}

	decodeDir := filepath.Join(workDir, "decoded")
	builtAPK := filepath.Join(workDir, "built.apk")
	signDir := filepath.Join(workDir, "signed")
	manifestPath := filepath.Join(decodeDir, "AndroidManifest.xml")

	// 1) Decode.
	if out, err := run(apktoolBin(), "d", "-f", "-o", decodeDir, inputAPK); err != nil {
		return "", fmt.Errorf("apktool decode failed: %v\n%s", err, out)
	}

	// 2) Network security config + manifest.
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", fmt.Errorf("read manifest: %w", err)
	}
	newRef, err := applyNetworkSecurityConfig(decodeDir, string(manifest))
	if err != nil {
		return "", fmt.Errorf("write network security config: %w", err)
	}
	if err := patchManifest(manifestPath, newRef); err != nil {
		return "", fmt.Errorf("patch manifest: %w", err)
	}

	// 3) Rebuild.
	if out, err := run(apktoolBin(), "b", "-o", builtAPK, decodeDir); err != nil {
		return "", fmt.Errorf("apktool build failed: %v\n%s", err, out)
	}

	// 4) Zipalign + sign with a debug key.
	if err := os.MkdirAll(signDir, 0o755); err != nil {
		return "", fmt.Errorf("create sign dir: %w", err)
	}
	if out, err := run(javaBin(), "-jar", uberSignerJar(), "--apks", builtAPK, "--out", signDir, "--allowResign", "--overwrite"); err != nil {
		return "", fmt.Errorf("uber-apk-signer failed: %v\n%s", err, out)
	}

	// 5) Locate the signed APK.
	return findSignedAPK(signDir)
}

var reNSCAttr = regexp.MustCompile(`android:networkSecurityConfig="@xml/([^"]+)"`)

// applyNetworkSecurityConfig writes the MITM network security config into the
// decoded tree. If the manifest already references a config, that file is
// overwritten (dropping its pin-sets/domain rules); otherwise nsc_mitm.xml is
// created. It returns the resource name the manifest must be pointed at, or ""
// when the manifest already points at the file we just wrote.
func applyNetworkSecurityConfig(decodeDir, manifest string) (string, error) {
	xmlDir := filepath.Join(decodeDir, "res", "xml")
	if err := os.MkdirAll(xmlDir, 0o755); err != nil {
		return "", err
	}
	if m := reNSCAttr.FindStringSubmatch(manifest); m != nil {
		// App already ships a config — overwrite the file it points at.
		return "", os.WriteFile(filepath.Join(xmlDir, m[1]+".xml"), []byte(networkSecurityConfig), 0o644)
	}
	if err := os.WriteFile(filepath.Join(xmlDir, nscResourceName+".xml"), []byte(networkSecurityConfig), 0o644); err != nil {
		return "", err
	}
	return nscResourceName, nil
}

var (
	reAppTag      = regexp.MustCompile(`(?s)<application\b([^>]*)>`)
	reExistingNSC = regexp.MustCompile(`\s+android:networkSecurityConfig="[^"]*"`)
	reExistingDbg = regexp.MustCompile(`\s+android:debuggable="[^"]*"`)
)

// patchManifest sets android:debuggable="true" on <application>, and (when
// addNSCRef is non-empty) points android:networkSecurityConfig at our config.
// apktool decodes AndroidManifest.xml to plain text XML, so a targeted edit of
// the opening <application ...> tag is the least-destructive approach.
func patchManifest(manifestPath, addNSCRef string) error {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	s := string(data)
	loc := reAppTag.FindStringSubmatchIndex(s)
	if loc == nil {
		return fmt.Errorf("no <application> element found")
	}
	attrs := s[loc[2]:loc[3]]
	attrs = reExistingDbg.ReplaceAllString(attrs, "")
	attrs += ` android:debuggable="true"`
	if addNSCRef != "" {
		attrs = reExistingNSC.ReplaceAllString(attrs, "")
		attrs += fmt.Sprintf(` android:networkSecurityConfig="@xml/%s"`, addNSCRef)
	}
	patched := s[:loc[2]] + attrs + s[loc[3]:]
	return os.WriteFile(manifestPath, []byte(patched), 0o644)
}

// findSignedAPK returns the single signed .apk uber-apk-signer wrote to dir.
func findSignedAPK(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(name), ".apk") {
			return filepath.Join(dir, name), nil
		}
	}
	return "", fmt.Errorf("no signed APK produced in %s", dir)
}

// run executes a command and returns its combined output (for error context).
func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
