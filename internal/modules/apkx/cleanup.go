package apkx

// cleanup.go — Post-scan upload and cleanup.
//
// After a successful APK scan this does exactly three things:
//  1. Upload results.json       → r2: new-results/apkx/<pkg>/results.json
//  2. Upload AndroidManifest.xml → r2: new-results/apkx/<pkg>/AndroidManifest.xml
//  3. Upload mitm-patched.apk  → r2: new-results/apkx/<pkg>/<file>.apk  (if present)
//
// Then removes from the local server:
//  - The jadx decompile temp dir
//  - The scan output directory (with results.json, html report, etc.)
//  - The downloaded APK file / tmpDir
//
// The HTML report is intentionally NOT uploaded — the dashboard reads the
// structured results.json and AndroidManifest.xml directly instead.

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/h0tak88r/AutoAR/internal/modules/r2storage"
)

// UploadArtifactsAndCleanup uploads the three key scan artifacts to R2, then
// deletes all local decompile/APK data.
//
// Parameters:
//   - result      : scan result (ReportDir, LogFile, MITMPatchedAPK)
//   - packageName : e.g. "com.example.app"
//   - version     : e.g. "5.1.0"
//   - downloadDir : temp directory where the original APK was downloaded (may be empty)
//   - jadxCacheDir: path to ~/.apkx/cache/<hash> used during decompilation (may be empty)
//
// Returns the R2 prefix used for all uploads, or an error.
func UploadArtifactsAndCleanup(
	result *Result,
	packageName, version string,
	downloadDir string,
	jadxCacheDir string,
) (r2Prefix string, err error) {
	if !r2storage.IsEnabled() {
		log.Printf("[CLEANUP] R2 not enabled — skipping upload, keeping local files")
		return "", nil
	}
	if result == nil || result.ReportDir == "" {
		return "", fmt.Errorf("invalid result: ReportDir is empty")
	}

	// ── Build the R2 prefix ────────────────────────────────────────────────────
	// Use new-results/apkx/<pkg>/ to be consistent with other scan types
	// (domain scans → new-results/<target>/, apkx → new-results/apkx/<pkg>/).
	safePkg := strings.NewReplacer(".", "_", "-", "_", " ", "_").Replace(packageName)
	r2Prefix = "new-results/apkx/" + safePkg

	uploadOK := true

	// ── 1. results.json ───────────────────────────────────────────────────────
	resultsJSON := filepath.Join(result.ReportDir, "results.json")
	if _, statErr := os.Stat(resultsJSON); statErr == nil {
		r2Key := r2Prefix + "/results.json"
		if _, uploadErr := r2storage.UploadFile(resultsJSON, r2Key, true); uploadErr != nil {
			log.Printf("[CLEANUP] ⚠  Failed to upload results.json: %v", uploadErr)
			uploadOK = false
		} else {
			log.Printf("[CLEANUP] ✓ Uploaded results.json → %s", r2Key)
		}
	} else {
		log.Printf("[CLEANUP] ⚠  results.json not found at %s", resultsJSON)
		uploadOK = false
	}

	// ── 2. AndroidManifest.xml ────────────────────────────────────────────────
	manifestCandidates := []string{
		filepath.Join(result.ReportDir, "AndroidManifest.xml"),
		filepath.Join(result.ReportDir, "resources", "AndroidManifest.xml"),
	}
	for _, mp := range manifestCandidates {
		if _, statErr := os.Stat(mp); statErr == nil {
			r2Key := r2Prefix + "/AndroidManifest.xml"
			if _, uploadErr := r2storage.UploadFile(mp, r2Key, true); uploadErr != nil {
				log.Printf("[CLEANUP] ⚠  Failed to upload AndroidManifest.xml: %v", uploadErr)
			} else {
				log.Printf("[CLEANUP] ✓ Uploaded AndroidManifest.xml → %s", r2Key)
			}
			break
		}
	}

	// ── 3. MITM-patched APK ───────────────────────────────────────────────────
	if mitmPath := strings.TrimSpace(result.MITMPatchedAPK); mitmPath != "" {
		if _, statErr := os.Stat(mitmPath); statErr == nil {
			r2Key := r2Prefix + "/" + filepath.Base(mitmPath)
			if _, uploadErr := r2storage.UploadFile(mitmPath, r2Key, true); uploadErr != nil {
				log.Printf("[CLEANUP] ⚠  Failed to upload MITM APK: %v", uploadErr)
			} else {
				log.Printf("[CLEANUP] ✓ Uploaded MITM APK → %s", r2Key)
				// Store the R2 key in cache_info.json so dashboard can link it.
				writeCacheInfo(r2Prefix, packageName, version, r2Key)
			}
		}
	}

	if !uploadOK {
		return r2Prefix, fmt.Errorf("one or more required artifacts failed to upload")
	}

	// ── 4. Remove local data — only after successful upload ───────────────────
	removeAll := func(path, label string) {
		if path == "" {
			return
		}
		if err := os.RemoveAll(path); err != nil {
			log.Printf("[CLEANUP] ⚠  Failed to remove %s (%s): %v", label, path, err)
		} else {
			log.Printf("[CLEANUP] 🗑  Removed %s: %s", label, path)
		}
	}

	removeAll(result.ReportDir, "scan output dir")
	removeAll(jadxCacheDir, "jadx decompile cache")
	removeAll(downloadDir, "downloaded APK dir")

	log.Printf("[CLEANUP] ✓ Local cleanup complete. Artifacts at r2:%s", r2Prefix)
	return r2Prefix, nil
}

// writeCacheInfo writes a minimal cache_info.json to R2 so the dashboard
// can discover the MITM APK download link without reading the full manifest.
func writeCacheInfo(r2Prefix, packageName, version, mitmR2Key string) {
	data := fmt.Sprintf(
		`{"package_name":%q,"version":%q,"mitm_r2_key":%q}`,
		packageName, version, mitmR2Key,
	)
	tmp, err := os.CreateTemp("", "cache-info-*.json")
	if err != nil {
		return
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(data); err != nil {
		tmp.Close()
		return
	}
	tmp.Close()
	r2Key := r2Prefix + "/cache_info.json"
	if _, err := r2storage.UploadFile(tmp.Name(), r2Key, true); err != nil {
		log.Printf("[CLEANUP] ⚠  Failed to upload cache_info.json: %v", err)
	} else {
		log.Printf("[CLEANUP] ✓ Uploaded cache_info.json → %s", r2Key)
	}
}
