package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/internal/modules/db"
	"github.com/h0tak88r/AutoAR/internal/modules/r2storage"
)

// GetScanResultsDir returns the local directory for a scan's results: <resultsDir>/{scanID}/
// Uses the same base directory as the rest of the app (AUTOAR_RESULTS_DIR or new-results).
func GetScanResultsDir(scanID string) string {
	return filepath.Join(GetResultsDir(), scanID)
}

// toScanR2Key converts a local file path to an R2 object key, preserving directory structure.
// Produces keys like: new-results/<scanID>/<fileName>
// Falls back to stripping leading slash if "new-results/" prefix not found.
func toScanR2Key(localPath string) string {
	if idx := strings.Index(localPath, "new-results/"); idx >= 0 {
		return localPath[idx:]
	}
	return strings.TrimPrefix(localPath, "/")
}

// WriteJSONToScanDir writes structured JSON data to a scan's local results directory,
// uploads to R2 under the correct path (new-results/<scanID>/<fileName>), and indexes
// the artifact in the DB so the dashboard can find it.
func WriteJSONToScanDir(scanID, fileName string, data interface{}) error {
	scanDir := GetScanResultsDir(scanID)
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		return fmt.Errorf("create scan dir: %w", err)
	}

	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}

	filePath := filepath.Join(scanDir, fileName)
	if err := os.WriteFile(filePath, raw, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	artifact := &db.ScanArtifact{
		ScanID:      strings.TrimSpace(scanID),
		FileName:    fileName,
		LocalPath:   filePath,
		SizeBytes:   int64(len(raw)),
		LineCount:   countNonEmptyLines(raw),
		ContentType: "application/json",
		CreatedAt:   time.Now().UTC(),
	}

	// Upload to R2 under the correct domain-scoped path
	if r2storage.IsEnabled() {
		artifact.R2Key = toScanR2Key(filePath)
		artifact.PublicURL = r2storage.UploadResultFileAndLog(filePath, artifact.R2Key)
		log.Printf("[JSON] Uploaded %s → R2:%s", fileName, artifact.R2Key)
	}

	// Index in DB so dashboard /results/summary can find it
	if artifact.ScanID != "" {
		if err := db.AppendScanArtifact(artifact); err != nil {
			log.Printf("[JSON] failed to index artifact %s for scan %s: %v", fileName, scanID, err)
		}
	}

	log.Printf("[JSON] Wrote %s (%d bytes) for scan %s", fileName, len(raw), scanID)
	return nil
}

// WriteTextToScanDir writes raw text/bytes to a scan's local results directory and uploads to R2.
func WriteTextToScanDir(scanID, fileName string, content []byte) error {
	scanDir := GetScanResultsDir(scanID)
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		return fmt.Errorf("create scan dir: %w", err)
	}

	filePath := filepath.Join(scanDir, fileName)
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	artifact := &db.ScanArtifact{
		ScanID:      strings.TrimSpace(scanID),
		FileName:    fileName,
		LocalPath:   filePath,
		SizeBytes:   int64(len(content)),
		LineCount:   countNonEmptyLines(content),
		ContentType: "application/json",
		CreatedAt:   time.Now().UTC(),
	}

	if len(content) > 0 && r2storage.IsEnabled() {
		artifact.R2Key = toScanR2Key(filePath)
		artifact.PublicURL = r2storage.UploadResultFileAndLog(filePath, artifact.R2Key)
		log.Printf("[JSON] Uploaded %s → R2:%s", fileName, artifact.R2Key)
	}

	if artifact.ScanID != "" {
		if err := db.AppendScanArtifact(artifact); err != nil {
			log.Printf("[JSON] failed to index artifact %s for scan %s: %v", fileName, scanID, err)
		}
	}

	log.Printf("[JSON] Wrote %s (%d bytes) for scan %s", fileName, len(content), scanID)
	return nil
}

// LinesToJSON converts a slice of text lines into a JSON scan result payload.
// The output structure: {scan_id, target, scan_type, generated, items: [...], count}
func LinesToJSON(scanID, target, scanType string, lines []string) map[string]interface{} {
	items := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			items = append(items, l)
		}
	}
	return map[string]interface{}{
		"scan_id":   scanID,
		"target":    target,
		"scan_type": scanType,
		"generated": time.Now().UTC().Format(time.RFC3339),
		"items":     items,
		"count":     len(items),
	}
}

// WriteLinesAsJSON is a convenience: wraps lines in JSON and writes to the scan dir.
func WriteLinesAsJSON(scanID, target, scanType, fileName string, lines []string) error {
	payload := LinesToJSON(scanID, target, scanType, lines)
	return WriteJSONToScanDir(scanID, fileName, payload)
}
