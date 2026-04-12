package gobot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/modules/db"
	"github.com/h0tak88r/AutoAR/internal/modules/r2storage"
)

const scanResultMaxBody = 12 * 1024 * 1024 // align with r2storage.MaxGetObjectBytes safety margin for JSON expansion

// GET /api/scans/:id — single scan record
func apiGetScan(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan id required"})
		return
	}
	rec, err := db.GetScan(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"scan": rec})
}

type fileEntry struct {
	FileName   string `json:"file_name"`
	R2Key      string `json:"r2_key"`
	SizeBytes  int64  `json:"size_bytes"`
	Source     string `json:"source"` // local | r2 | indexed
	IsJSON     bool   `json:"is_json"`
	CreatedAt  string `json:"created_at,omitempty"`
	PublicURL  string `json:"public_url,omitempty"`
	LocalPath  string `json:"local_path,omitempty"`
	LineCount  int    `json:"line_count,omitempty"`
}

func parseScanResultsPagination(c *gin.Context) (page, perPage int) {
	page, _ = strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ = strconv.Atoi(c.DefaultQuery("per_page", "20"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 20
	}
	if perPage > 100 {
		perPage = 100
	}
	return page, perPage
}

func paginateFileEntries(entries []fileEntry, page, perPage int) (pageItems []fileEntry, total int) {
	total = len(entries)
	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}
	return entries[start:end], total
}

// loadR2CacheFileSet lists filenames in the scan’s R2 cache dir once (avoids N stat calls).
func loadR2CacheFileSet(scanID string) map[string]struct{} {
	cacheDir := filepath.Join(getResultsDir(), ".scan-r2-cache", scanID)
	out := make(map[string]struct{})
	ents, err := os.ReadDir(cacheDir)
	if err != nil {
		return out
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		out[e.Name()] = struct{}{}
	}
	return out
}

// scanResultFileHiddenFromUI drops transient or duplicate-looking artifacts from the scan results table.
func scanResultFileHiddenFromUI(fileName string) bool {
	n := strings.ToLower(strings.TrimSpace(fileName))
	switch n {
	case "temp-url.txt":
		// Nuclei (and similar) transient URL list — not a user-facing result
		return true
	default:
		return false
	}
}

// scanFileEntryBetter returns true if a should replace b when both share the same display name.
func scanFileEntryBetter(a, b fileEntry) bool {
	if a.SizeBytes != b.SizeBytes {
		return a.SizeBytes > b.SizeBytes
	}
	if a.LineCount != b.LineCount {
		return a.LineCount > b.LineCount
	}
	if a.Source != b.Source {
		return a.Source == "local" && b.Source != "local"
	}
	return false
}

// dedupeScanFileEntriesByName keeps one row per basename (e.g. urls/js-urls vs vulnerabilities/js/js-urls).
func dedupeScanFileEntriesByName(entries []fileEntry) []fileEntry {
	best := make(map[string]fileEntry, len(entries))
	order := make([]string, 0, len(entries))
	for _, e := range entries {
		if scanResultFileHiddenFromUI(e.FileName) {
			continue
		}
		k := strings.ToLower(e.FileName)
		prev, ok := best[k]
		if !ok {
			best[k] = e
			order = append(order, k)
			continue
		}
		if scanFileEntryBetter(e, prev) {
			best[k] = e
		}
	}
	out := make([]fileEntry, 0, len(best))
	for _, k := range order {
		out = append(out, best[k])
	}
	return out
}

// fileEntriesFromArtifacts builds the sorted file list with source hints (JSON files first).
func fileEntriesFromArtifacts(scanID string, arts []*db.ScanArtifact) []fileEntry {
	resultsDir := getResultsDir()
	cacheFiles := loadR2CacheFileSet(scanID)
	entries := make([]fileEntry, 0, len(arts))
	for _, a := range arts {
		if a == nil || a.R2Key == "" {
			continue
		}
		fn := a.FileName
		if fn == "" {
			fn = filepath.Base(a.R2Key)
		}
		if scanResultFileHiddenFromUI(fn) {
			continue
		}
		src := "indexed"
		if _, ok := resolveLocalPathForR2Key(resultsDir, a); ok {
			src = "local"
		} else if _, ok := cacheFiles[cacheNameForKey(a.R2Key)]; ok {
			src = "local"
		} else if a.PublicURL != "" || r2storage.IsEnabled() {
			src = "r2"
		}
		isJSON := strings.EqualFold(filepath.Ext(fn), ".json")
		entries = append(entries, fileEntry{
			FileName:  fn,
			R2Key:     a.R2Key,
			SizeBytes: a.SizeBytes,
			Source:    src,
			IsJSON:    isJSON,
			CreatedAt: a.CreatedAt.UTC().Format(time.RFC3339),
			PublicURL: a.PublicURL,
			LocalPath: a.LocalPath,
			LineCount: a.LineCount,
		})
	}
	entries = dedupeScanFileEntriesByName(entries)
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].IsJSON != entries[j].IsJSON {
			return entries[i].IsJSON
		}
		return strings.ToLower(entries[i].FileName) < strings.ToLower(entries[j].FileName)
	})
	return entries
}

// GET /api/scans/:id/results/summary — scan row + file list in one round-trip (preferred for UI).
func apiScanResultsSummary(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()
	scanID := strings.TrimSpace(c.Param("id"))
	if scanID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan id required"})
		return
	}
	page, perPage := parseScanResultsPagination(c)

	rec, err := db.GetScan(scanID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	arts, err := db.ListScanArtifacts(scanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	entries := fileEntriesFromArtifacts(scanID, arts)
	pageItems, total := paginateFileEntries(entries, page, perPage)

	st := strings.ToLower(strings.TrimSpace(rec.Status))
	switch st {
	case "completed", "done", "failed", "cancelled", "error":
		c.Header("Cache-Control", "private, max-age=60")
	}

	c.JSON(http.StatusOK, gin.H{
		"scan":       rec,
		"scan_id":    scanID,
		"page":       page,
		"per_page":   perPage,
		"total":      total,
		"files":      pageItems,
		"json_first": true,
	})
}

// GET /api/scans/:id/results/files — paginated artifact list only (JSON files first).
func apiScanResultFiles(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()
	scanID := strings.TrimSpace(c.Param("id"))
	if scanID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan id required"})
		return
	}
	if _, err := db.GetScan(scanID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	page, perPage := parseScanResultsPagination(c)

	arts, err := db.ListScanArtifacts(scanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	entries := fileEntriesFromArtifacts(scanID, arts)
	pageItems, total := paginateFileEntries(entries, page, perPage)

	c.JSON(http.StatusOK, gin.H{
		"scan_id":    scanID,
		"page":       page,
		"per_page":   perPage,
		"total":      total,
		"files":      pageItems,
		"json_first": true,
	})
}

func cacheNameForKey(r2Key string) string {
	sum := sha256.Sum256([]byte(r2Key))
	h := hex.EncodeToString(sum[:8])
	base := filepath.Base(r2Key)
	if base == "" || base == "." {
		base = "object"
	}
	return h + "_" + base
}

// resolveLocalPathForR2Key returns a readable local path for an artifact when it still exists on disk.
func resolveLocalPathForR2Key(resultsDir string, a *db.ScanArtifact) (string, bool) {
	if a.LocalPath != "" {
		if fi, err := os.Stat(a.LocalPath); err == nil && !fi.IsDir() && fi.Size() > 0 {
			return a.LocalPath, true
		}
	}
	key := strings.TrimPrefix(strings.TrimSpace(a.R2Key), "/")
	if key == "" {
		return "", false
	}
	parent := filepath.Dir(resultsDir)
	candidates := []string{
		filepath.Join(resultsDir, strings.TrimPrefix(key, "new-results/")),
		filepath.Join(parent, key),
		filepath.Join(resultsDir, key),
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Size() > 0 {
			return p, true
		}
	}
	return "", false
}

func writeScanR2Cache(scanID, r2Key string, data []byte) {
	if len(data) == 0 {
		return
	}
	dir := filepath.Join(getResultsDir(), ".scan-r2-cache", scanID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("[scan-cache] mkdir: %v", err)
		return
	}
	path := filepath.Join(dir, cacheNameForKey(r2Key))
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Printf("[scan-cache] write: %v", err)
	}
}

func loadArtifactBytes(scanID string, art *db.ScanArtifact) ([]byte, string, error) {
	resultsDir := getResultsDir()
	if lp, ok := resolveLocalPathForR2Key(resultsDir, art); ok {
		data, err := os.ReadFile(lp)
		if err == nil && len(data) > 0 {
			return data, "local", nil
		}
	}
	cachePath := filepath.Join(resultsDir, ".scan-r2-cache", scanID, cacheNameForKey(art.R2Key))
	if data, err := os.ReadFile(cachePath); err == nil && len(data) > 0 {
		return data, "cache", nil
	}
	if !r2storage.IsEnabled() {
		return nil, "", fmt.Errorf("file not on disk and R2 is disabled")
	}
	data, err := r2storage.GetObjectBytes(art.R2Key)
	if err != nil {
		return nil, "", err
	}
	writeScanR2Cache(scanID, art.R2Key, data)
	return data, "r2", nil
}

// GET /api/scans/:id/results/file — body preview with pagination (JSON arrays / text lines).
func apiScanResultFileContent(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()
	scanID := strings.TrimSpace(c.Param("id"))
	r2Key := strings.TrimSpace(c.Query("r2_key"))
	if scanID == "" || r2Key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan id and r2_key are required"})
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "100"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 100
	}
	if perPage > 500 {
		perPage = 500
	}

	if _, err := db.GetScan(scanID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	arts, err := db.ListScanArtifacts(scanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var art *db.ScanArtifact
	for _, a := range arts {
		if a != nil && a.R2Key == r2Key {
			art = a
			break
		}
	}
	if art == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "artifact does not belong to this scan"})
		return
	}

	raw, source, err := loadArtifactBytes(scanID, art)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if len(raw) > scanResultMaxBody {
		c.JSON(http.StatusOK, gin.H{
			"format":      "too_large",
			"error":       "file too large for inline preview",
			"max_bytes":   scanResultMaxBody,
			"size_bytes":  len(raw),
			"public_url":  art.PublicURL,
			"source_used": source,
		})
		return
	}

	isJSONExt := strings.EqualFold(filepath.Ext(art.FileName), ".json") ||
		strings.EqualFold(filepath.Ext(filepath.Base(art.R2Key)), ".json")
	if !isJSONExt && len(raw) > 0 && json.Valid(raw) && (raw[0] == '{' || raw[0] == '[') {
		isJSONExt = true
	}

	if isJSONExt {
		resp := buildJSONPreview(raw, page, perPage)
		resp["file_name"] = art.FileName
		resp["r2_key"] = art.R2Key
		resp["size_bytes"] = len(raw)
		resp["source_used"] = source
		resp["public_url"] = art.PublicURL
		c.JSON(http.StatusOK, resp)
		return
	}

	// Text / line pagination
	lines := strings.Split(string(raw), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	total := len(lines)
	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}
	slice := lines[start:end]
	if !utf8.ValidString(string(raw)) {
		c.JSON(http.StatusOK, gin.H{
			"format":      "binary",
			"error":       "not valid utf-8 text; use download URL",
			"public_url":  art.PublicURL,
			"size_bytes":  len(raw),
			"source_used": source,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"format":      "text",
		"file_name":   art.FileName,
		"r2_key":      art.R2Key,
		"size_bytes":  len(raw),
		"source_used": source,
		"public_url":  art.PublicURL,
		"page":        page,
		"per_page":    perPage,
		"total_lines": total,
		"lines":       slice,
	})
}

func buildJSONPreview(raw []byte, page, perPage int) gin.H {
	var top interface{}
	if err := json.Unmarshal(raw, &top); err != nil {
		return gin.H{
			"format": "json",
			"error":  "invalid JSON: " + err.Error(),
		}
	}

	switch v := top.(type) {
	case []interface{}:
		total := len(v)
		start := (page - 1) * perPage
		if start > total {
			start = total
		}
		end := start + perPage
		if end > total {
			end = total
		}
		return gin.H{
			"format":       "json-array",
			"page":         page,
			"per_page":     perPage,
			"total_items":  total,
			"items":        v[start:end],
			"prefer_json":  true,
		}
	case map[string]interface{}:
		// Prefer a nested array field (common in tool outputs).
		for _, key := range []string{"results", "findings", "matches", "issues", "vulnerabilities", "data", "items"} {
			if arr, ok := v[key].([]interface{}); ok && len(arr) > 0 {
				total := len(arr)
				start := (page - 1) * perPage
				if start > total {
					start = total
				}
				end := start + perPage
				if end > total {
					end = total
				}
				return gin.H{
					"format":          "json-array",
					"array_field":     key,
					"page":            page,
					"per_page":        perPage,
					"total_items":     total,
					"items":           arr[start:end],
					"object_preview":  trimObjectForPreview(v, key),
					"prefer_json":     true,
				}
			}
		}
		return gin.H{
			"format":      "json-object",
			"page":        1,
			"per_page":    1,
			"data":        v,
			"prefer_json": true,
		}
	default:
		return gin.H{
			"format":      "json",
			"page":        page,
			"raw_preview": truncateStr(string(raw), 8000),
			"prefer_json": true,
		}
	}
}

func trimObjectForPreview(m map[string]interface{}, omitKey string) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		if k == omitKey {
			if arr, ok := v.([]interface{}); ok {
				out[k] = fmt.Sprintf("[%d items — use pagination]", len(arr))
				continue
			}
		}
		out[k] = v
	}
	return out
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
