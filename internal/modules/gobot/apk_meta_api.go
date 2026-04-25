package gobot

// GET /api/scans/:id/results/apk-meta
//
// Returns parsed metadata from the AndroidManifest.xml and cache_info.json
// for an APK scan, without any row limits or scraping of findings data.
//
// Response:
//   {
//     "package_name":   "com.example.app",
//     "version":        "5.1.0",
//     "version_code":   "510",
//     "min_sdk":        "21",
//     "target_sdk":     "34",
//     "task_hijacking_risk": "possible" | "unlikely" | "unknown"
//   }
//
// task_hijacking_risk logic (minSdk):
//   ≤ 28  → "possible"   (Android 9 and earlier — stealBackStack not enforced)
//   29–30 → "mitigated"  (Android 10/11 — partial fix)
//   ≥ 31  → "unlikely"   (Android 12+ — stealBackStack=false by default)

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/modules/db"
)

// APKMeta holds parsed APK metadata.
type APKMeta struct {
	PackageName       string `json:"package_name"`
	Version           string `json:"version"`
	VersionCode       string `json:"version_code,omitempty"`
	MinSDK            string `json:"min_sdk"`
	TargetSDK         string `json:"target_sdk"`
	TaskHijackingRisk string `json:"task_hijacking_risk"` // "possible", "mitigated", "unlikely", "unknown"
	Source            string `json:"source,omitempty"`    // "manifest", "cache_info", "scan_target"
}

func apiScanAPKMeta(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()

	scanID := strings.TrimSpace(c.Param("id"))
	if scanID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan id required"})
		return
	}

	scan, err := db.GetScan(scanID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	meta := &APKMeta{}

	// ── 1. Try AndroidManifest.xml (richest source) ───────────────────────────
	if raw, _, err := loadFileContent(scanID, "AndroidManifest.xml"); err == nil && len(raw) > 0 {
		parseManifestInto(string(raw), meta)
		meta.Source = "manifest"
	}

	// ── 2. Fill gaps from cache_info.json ────────────────────────────────────
	if raw, _, err := loadFileContent(scanID, "cache_info.json"); err == nil && len(raw) > 0 {
		var ci struct {
			PackageName string `json:"package_name"`
			Version     string `json:"version"`
			VersionCode string `json:"version_code"`
		}
		if json.Unmarshal(raw, &ci) == nil {
			if meta.PackageName == "" && ci.PackageName != "" {
				meta.PackageName = ci.PackageName
				if meta.Source == "" {
					meta.Source = "cache_info"
				}
			}
			if meta.Version == "" && ci.Version != "" {
				meta.Version = ci.Version
			}
			if meta.VersionCode == "" && ci.VersionCode != "" {
				meta.VersionCode = ci.VersionCode
			}
		}
	}

	// ── 3. Final fallback: use scan target as package name ────────────────────
	if meta.PackageName == "" {
		tgt := strings.TrimSpace(scan.Target)
		if tgt != "" {
			meta.PackageName = tgt
			if meta.Source == "" {
				meta.Source = "scan_target"
			}
		}
	}

	// ── 4. Compute task hijacking risk from minSdk ────────────────────────────
	meta.TaskHijackingRisk = taskHijackingRisk(meta.MinSDK)

	c.JSON(http.StatusOK, meta)
}

// parseManifestInto fills meta fields by scanning the manifest XML text with
// simple regexes (same approach as reporter.ExtractPackageInfo / ExtractMinSdkVersion).
func parseManifestInto(content string, m *APKMeta) {
	tryRE := func(pattern, text string) string {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return ""
		}
		if matches := re.FindStringSubmatch(text); len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
		return ""
	}

	if v := tryRE(`package\s*=\s*["']([^"']+)["']`, content); v != "" {
		m.PackageName = v
	}
	if v := tryRE(`android:versionName\s*=\s*["']([^"']+)["']`, content); v != "" {
		m.Version = v
	}
	if m.Version == "" {
		if v := tryRE(`android:versionName\s*=\s*(\S+)`, content); v != "" {
			m.Version = strings.Trim(v, `"'`)
		}
	}
	if v := tryRE(`android:versionCode\s*=\s*["']?(\d+)["']?`, content); v != "" {
		m.VersionCode = v
		if m.Version == "" {
			m.Version = "v" + v
		}
	}
	// minSdkVersion — may be in <uses-sdk> or <manifest>
	for _, pat := range []string{
		`android:minSdkVersion\s*=\s*["'](\d+)["']`,
		`android:minSdkVersion\s*=\s*(\d+)`,
		`minSdkVersion\s*=\s*["']?(\d+)["']?`,
	} {
		if v := tryRE(pat, content); v != "" {
			m.MinSDK = v
			break
		}
	}
	// targetSdkVersion
	for _, pat := range []string{
		`android:targetSdkVersion\s*=\s*["'](\d+)["']`,
		`android:targetSdkVersion\s*=\s*(\d+)`,
		`targetSdkVersion\s*=\s*["']?(\d+)["']?`,
	} {
		if v := tryRE(pat, content); v != "" {
			m.TargetSDK = v
			break
		}
	}
}

// taskHijackingRisk returns a risk label based on minSdkVersion.
//
// Task hijacking via stealBackStack was effectively patched in Android 12 (API 31).
//   - API ≤ 28 (Android 9):  widely exploitable
//   - API 29–30 (Android 10/11): partial fix (FLAG_ACTIVITY_TASK_ON_HOME)
//   - API ≥ 31 (Android 12+): stealBackStack=false default
func taskHijackingRisk(minSDK string) string {
	n, err := strconv.Atoi(strings.TrimSpace(minSDK))
	if err != nil || n <= 0 {
		return "unknown"
	}
	switch {
	case n <= 28:
		return "possible"
	case n <= 30:
		return "mitigated"
	default:
		return "unlikely"
	}
}
