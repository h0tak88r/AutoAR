package gobot

// GET /api/scans/:id/results/apk-meta
//
// Returns parsed metadata from the AndroidManifest.xml and cache_info.json
// for an APK scan.
//
// task_hijacking_risk logic (minSdk):
//   ≤ 28  → "possible"   (Android 9 and earlier)
//   29–30 → "mitigated"  (Android 10/11)
//   ≥ 31  → "unlikely"   (Android 12+)

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/modules/db"
	"github.com/h0tak88r/AutoAR/internal/tools/apkx/analyzer"
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

	// ── 1. Try AndroidManifest.xml via XML parser ─────────────────────────────
	if raw, _, err := loadFileContent(scanID, "AndroidManifest.xml"); err == nil && len(raw) > 0 {
		// Write raw bytes to a temp file so ParseManifestXML can read it.
		// (ParseManifestXML accepts a path; we avoid a copy by writing to /tmp)
		if tmpPath, tmpErr := writeTemp("autoar-manifest-*.xml", raw); tmpErr == nil {
			if pm, xmlErr := analyzer.ParseManifestXML(tmpPath); xmlErr == nil {
				if pm.PackageName != "" {
					meta.PackageName = pm.PackageName
				}
				if pm.VersionName != "" {
					meta.Version = pm.VersionName
				}
				if pm.VersionCode != "" {
					meta.VersionCode = pm.VersionCode
					if meta.Version == "" {
						meta.Version = "v" + pm.VersionCode
					}
				}
				meta.MinSDK = pm.MinSdkVersion
				meta.TargetSDK = pm.TargetSdkVersion
				meta.Source = "manifest"
			}
			os.Remove(tmpPath)
		}
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

// writeTemp writes data to a temporary file and returns its path.
func writeTemp(pattern string, data []byte) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
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
