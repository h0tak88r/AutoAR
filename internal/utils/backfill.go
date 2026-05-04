package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// BackfillFindingsCounts runs in the background after startup and retroactively
// populates the files_uploaded counter for completed scans that were created
// before the automatic counting logic existed (files_uploaded == 0).
//
// It reads each scan's local result directory, counts findings in every
// non-recon JSON file using the same blocklist as WriteJSONToScanDir, and
// updates the DB record once per scan.
func BackfillFindingsCounts() {
	if err := db.Init(); err != nil {
		return
	}

	scans, err := db.ListRecentScans(500)
	if err != nil || len(scans) == 0 {
		return
	}

	updated := 0
	for _, scan := range scans {
		if scan == nil {
			continue
		}
		// Only backfill completed scans that have no count yet.
		if scan.FilesUploaded > 0 || scan.Status != "completed" {
			continue
		}

		scanDir := GetScanResultsDir(scan.ScanID)
		if _, statErr := os.Stat(scanDir); statErr != nil {
			continue // no local results directory — skip
		}

		total := countFindingsInDir(scanDir)
		if total > 0 {
			if dbErr := db.UpdateScanStats(scan.ScanID, total, scan.ErrorCount); dbErr == nil {
				updated++
			}
		}
	}

	if updated > 0 {
		GetLogger().Infof("[backfill] Updated findings counts for %d completed scans", updated)
	}
}

// countFindingsInDir walks a scan result directory and returns the total
// number of real findings across all non-recon JSON files.
func countFindingsInDir(dir string) int {
	total := 0
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".json") {
			return nil
		}
		if isReconOrPipelineFile(info.Name()) {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil || len(raw) <= 10 {
			return nil
		}
		total += countFindingsInJSON(raw)
		return nil
	})
	return total
}

// isReconOrPipelineFile returns true for known recon/pipeline input files
// that should never be counted as vulnerability findings.
// Mirrors the blocklist in WriteJSONToScanDir.
func isReconOrPipelineFile(fileName string) bool {
	n := strings.ToLower(fileName)
	return strings.Contains(n, "no-findings") ||
		strings.Contains(n, "no_findings") ||
		strings.Contains(n, "js-url") ||
		strings.Contains(n, "all-url") ||
		strings.Contains(n, "all-subs") ||
		strings.Contains(n, "live-subs") ||
		strings.Contains(n, "live-hosts") ||
		strings.Contains(n, "livehosts") ||
		strings.Contains(n, "subdomains") ||
		strings.Contains(n, "enumerated-subs") ||
		strings.Contains(n, "tech-detect") ||
		strings.Contains(n, "cname-records") ||
		strings.Contains(n, "cnames") ||
		strings.Contains(n, "httpx") ||
		strings.Contains(n, "wayback") ||
		strings.Contains(n, "gospider") ||
		strings.Contains(n, "interesting-urls") ||
		strings.Contains(n, "nuclei-summary") ||
		strings.Contains(n, "scan-manifest") ||
		strings.Contains(n, "dns-takeover-vulnerabilities")
}

// countFindingsInJSON parses a raw JSON blob and returns the number of
// real finding entries, filtering out "no findings" sentinel objects.
func countFindingsInJSON(raw []byte) int {
	var parsed interface{}
	if json.Unmarshal(raw, &parsed) != nil {
		return 0
	}
	switch v := parsed.(type) {
	case []interface{}:
		count := 0
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				if f, _ := m["finding"].(string); strings.Contains(strings.ToLower(f), "no finding") {
					continue
				}
			}
			count++
		}
		return count
	case map[string]interface{}:
		for _, key := range []string{"findings", "results", "items", "vulnerabilities", "matches"} {
			if arr, ok := v[key].([]interface{}); ok {
				return len(arr)
			}
		}
	}
	return 0
}
