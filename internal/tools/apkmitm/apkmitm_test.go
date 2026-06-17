package apkmitm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNSCConfigContents(t *testing.T) {
	c := networkSecurityConfig
	for _, want := range []string{
		`<base-config cleartextTrafficPermitted="true">`,
		`<debug-overrides>`,
		`<certificates src="user" />`,
		`<certificates src="system" />`,
	} {
		if !strings.Contains(c, want) {
			t.Errorf("network security config missing %q:\n%s", want, c)
		}
	}
}

func TestApplyNSCNoExisting(t *testing.T) {
	dir := t.TempDir()
	manifest := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:label="X"></application>
</manifest>`
	ref, err := applyNetworkSecurityConfig(dir, manifest)
	if err != nil {
		t.Fatalf("applyNetworkSecurityConfig: %v", err)
	}
	if ref != "nsc_mitm" {
		t.Fatalf("expected ref nsc_mitm, got %q", ref)
	}
	data, err := os.ReadFile(filepath.Join(dir, "res", "xml", "nsc_mitm.xml"))
	if err != nil {
		t.Fatalf("nsc_mitm.xml not written: %v", err)
	}
	if !strings.Contains(string(data), "<debug-overrides>") {
		t.Errorf("written config missing debug-overrides")
	}
}

func TestApplyNSCOverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	// App ships its own config with a pin-set the app points at.
	existing := filepath.Join(dir, "res", "xml", "my_conf.xml")
	_ = os.MkdirAll(filepath.Dir(existing), 0o755)
	_ = os.WriteFile(existing, []byte(`<network-security-config><domain-config><pin-set><pin>AAAA</pin></pin-set></domain-config></network-security-config>`), 0o644)

	manifest := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:networkSecurityConfig="@xml/my_conf"></application>
</manifest>`
	ref, err := applyNetworkSecurityConfig(dir, manifest)
	if err != nil {
		t.Fatalf("applyNetworkSecurityConfig: %v", err)
	}
	if ref != "" {
		t.Fatalf("expected empty ref (manifest already points at the file), got %q", ref)
	}
	data, _ := os.ReadFile(existing)
	s := string(data)
	if strings.Contains(s, "pin-set") {
		t.Errorf("existing config's pin-set should be gone after overwrite:\n%s", s)
	}
	if !strings.Contains(s, `<certificates src="user" />`) {
		t.Errorf("overwritten config should trust user CAs:\n%s", s)
	}
}

func TestPatchManifestAddsRefAndDebuggable(t *testing.T) {
	dir := t.TempDir()
	mf := filepath.Join(dir, "AndroidManifest.xml")
	src := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:label="Demo" android:icon="@mipmap/ic">
        <activity android:name=".Main"/>
    </application>
</manifest>`
	_ = os.WriteFile(mf, []byte(src), 0o644)
	if err := patchManifest(mf, "nsc_mitm"); err != nil {
		t.Fatalf("patchManifest: %v", err)
	}
	got, _ := os.ReadFile(mf)
	s := string(got)
	if !strings.Contains(s, `android:networkSecurityConfig="@xml/nsc_mitm"`) {
		t.Errorf("missing networkSecurityConfig:\n%s", s)
	}
	if !strings.Contains(s, `android:debuggable="true"`) {
		t.Errorf("missing debuggable:\n%s", s)
	}
	if !strings.Contains(s, `android:label="Demo"`) || !strings.Contains(s, ".Main") {
		t.Errorf("patch clobbered the manifest:\n%s", s)
	}
}

func TestPatchManifestPreservesExistingRef(t *testing.T) {
	dir := t.TempDir()
	mf := filepath.Join(dir, "AndroidManifest.xml")
	// App already references a config; we overwrote that FILE, so the manifest
	// pointer must be left intact (addNSCRef="") and only debuggable flipped.
	src := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:networkSecurityConfig="@xml/my_conf" android:debuggable="false" android:label="X"></application>
</manifest>`
	_ = os.WriteFile(mf, []byte(src), 0o644)
	if err := patchManifest(mf, ""); err != nil {
		t.Fatalf("patchManifest: %v", err)
	}
	got, _ := os.ReadFile(mf)
	s := string(got)
	if !strings.Contains(s, `android:networkSecurityConfig="@xml/my_conf"`) {
		t.Errorf("existing config reference should be preserved:\n%s", s)
	}
	if strings.Contains(s, `android:debuggable="false"`) || !strings.Contains(s, `android:debuggable="true"`) {
		t.Errorf("debuggable should be flipped to true:\n%s", s)
	}
	if strings.Count(s, "android:debuggable=") != 1 {
		t.Errorf("expected exactly one debuggable attr:\n%s", s)
	}
}

func TestPatchManifestNoApplication(t *testing.T) {
	dir := t.TempDir()
	mf := filepath.Join(dir, "AndroidManifest.xml")
	_ = os.WriteFile(mf, []byte(`<manifest></manifest>`), 0o644)
	if err := patchManifest(mf, "nsc_mitm"); err == nil {
		t.Error("expected error when no <application> element exists")
	}
}

func TestFindSignedAPK(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "app-aligned-debugSigned.apk"), []byte("x"), 0o644)
	got, err := findSignedAPK(dir)
	if err != nil {
		t.Fatalf("findSignedAPK: %v", err)
	}
	if filepath.Base(got) != "app-aligned-debugSigned.apk" {
		t.Errorf("got %s", got)
	}
	if _, err := findSignedAPK(t.TempDir()); err == nil {
		t.Error("expected error for empty dir")
	}
}
