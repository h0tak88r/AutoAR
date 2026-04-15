package gobot

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/modules/db"
	"github.com/h0tak88r/AutoAR/internal/modules/r2storage"
)

const scanResultMaxBody = 12 * 1024 * 1024

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
	FileName  string `json:"file_name"`
	LocalPath string `json:"local_path"`
	SizeBytes int64  `json:"size_bytes"`
	IsJSON    bool   `json:"is_json"`
	LineCount int    `json:"line_count,omitempty"`
	Module    string `json:"module,omitempty"`
	Category  string `json:"category,omitempty"`
	Source    string `json:"source,omitempty"` // "local", "db", "r2"
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

func inferModuleFromFileName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch {
	case strings.Contains(n, "nuclei"):
		return "nuclei"
	case strings.Contains(n, "sub") && strings.Contains(n, "domain"):
		return "subdomain-enum"
	case strings.Contains(n, "live-subs"), strings.Contains(n, "httpx"), strings.Contains(n, "live-host"):
		return "httpx"
	case strings.Contains(n, "js-url") || strings.Contains(n, "jsurl"):
		return "js-analysis"
	case strings.Contains(n, "js-secret") || strings.Contains(n, "js-exposure") || strings.Contains(n, "secret"):
		return "js-analysis"
	case strings.HasPrefix(n, "gf-") || strings.Contains(n, "gf-"):
		return "gf-patterns"
	case strings.Contains(n, "misconfig"):
		return "misconfig"
	case strings.Contains(n, "zeroday") || strings.Contains(n, "cve"):
		return "zerodays"
	case strings.Contains(n, "ffuf") || strings.Contains(n, "fuzz"):
		return "ffuf-fuzzing"
	case strings.Contains(n, "bucket") || strings.Contains(n, "s3-"):
		return "s3-scan"
	case strings.Contains(n, "aws-") || strings.Contains(n, "azure-") || strings.Contains(n, "gcp-") ||
		strings.Contains(n, "dns") || strings.Contains(n, "takeover") || strings.Contains(n, "dnsreap") ||
		strings.Contains(n, "cloudflare") || strings.Contains(n, "dangling"):
		return "dns-takeover"
	case strings.Contains(n, "tech"):
		return "tech-detect"
	case strings.Contains(n, "port") || strings.Contains(n, "nmap") || strings.Contains(n, "masscan"):
		return "port-scan"
	case strings.Contains(n, "github") || strings.Contains(n, "repo"):
		return "github-scan"
	case strings.Contains(n, "backup") || strings.Contains(n, "fuzzuli"):
		return "backup-detection"
	case strings.Contains(n, "reflection") || strings.Contains(n, "kxss") || strings.Contains(n, "dalfox") || strings.Contains(n, "xss"):
		return "xss-detection"
	case strings.Contains(n, "confusion") || strings.Contains(n, "depconf"):
		return "dependency-confusion"
	default:
		return "autoar"
	}
}

func inferCategoryFromFileName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	// Vulnerability outputs
	if strings.Contains(n, "nuclei") || strings.HasPrefix(n, "gf-") || strings.Contains(n, "gf-") ||
		strings.Contains(n, "misconfig") || strings.Contains(n, "zeroday") ||
		strings.Contains(n, "dalfox") || strings.Contains(n, "sqlmap") || strings.Contains(n, "vuln") ||
		strings.Contains(n, "xss") || strings.Contains(n, "kxss") || strings.Contains(n, "reflection") ||
		strings.Contains(n, "secret") || strings.Contains(n, "exposure") || strings.Contains(n, "js-secret") ||
		strings.Contains(n, "aws-") || strings.Contains(n, "azure-") || strings.Contains(n, "gcp-") ||
		strings.Contains(n, "takeover") || strings.Contains(n, "dangling") || strings.Contains(n, "dnsreap") ||
		strings.Contains(n, "confusion") || strings.Contains(n, "depconf") || strings.Contains(n, "backup") {
		return "vulnerability"
	}
	// Recon outputs
	if strings.Contains(n, "subs") || strings.Contains(n, "url") || strings.Contains(n, "tech") ||
		strings.Contains(n, "port") || strings.Contains(n, "bucket") || strings.Contains(n, "cname") ||
		strings.Contains(n, "live") || strings.Contains(n, "nmap") || strings.Contains(n, "masscan") {
		return "recon"
	}
	if strings.HasSuffix(n, ".log") {
		return "log"
	}
	return "output"
}

// getScanResultsDir returns the local directory for a scan's results
func getScanResultsDir(scanID string) string {
	return filepath.Join(getResultsDir(), scanID)
}

// listLocalFiles returns all files in a scan's local directory, falling back
// to DB-indexed artifacts when the local directory is empty (e.g. after cleanup).
func listLocalFiles(scanID string) ([]fileEntry, error) {
	scanDir := getScanResultsDir(scanID)
	localEntries := []fileEntry{}

	if _, err := os.Stat(scanDir); err == nil {
		// Walk local directory
		walkErr := filepath.Walk(scanDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			isJSON := strings.HasSuffix(strings.ToLower(info.Name()), ".json")
			lineCount := 0
			if isJSON {
				if data, readErr := os.ReadFile(path); readErr == nil {
					lineCount = strings.Count(string(data), "\n")
				}
			}
			localEntries = append(localEntries, fileEntry{
				FileName:  info.Name(),
				LocalPath: path,
				SizeBytes: info.Size(),
				IsJSON:    isJSON,
				LineCount: lineCount,
				Module:    inferModuleFromFileName(info.Name()),
				Category:  inferCategoryFromFileName(info.Name()),
			})
			return nil
		})
		if walkErr != nil {
			log.Printf("[scan-results] walk %s: %v", scanDir, walkErr)
		}
	}

	if len(localEntries) > 0 {
		return localEntries, nil
	}

	// Local dir is empty or missing — fall back to DB-indexed artifacts.
	artifacts, err := db.ListScanArtifacts(scanID)
	if err != nil || len(artifacts) == 0 {
		return localEntries, nil // Return empty list, not an error
	}

	seen := make(map[string]struct{}, len(artifacts))
	for _, a := range artifacts {
		if a == nil {
			continue
		}
		base := filepath.Base(a.FileName)
		if _, dup := seen[base]; dup {
			continue
		}
		seen[base] = struct{}{}

		isJSON := strings.HasSuffix(strings.ToLower(base), ".json")
		src := "r2"
		if a.LocalPath != "" {
			src = "local"
		}
		_ = src
		localEntries = append(localEntries, fileEntry{
			FileName:  base,
			LocalPath: a.LocalPath,
			SizeBytes: a.SizeBytes,
			IsJSON:    isJSON,
			LineCount: a.LineCount,
			Module:    firstNonEmpty(a.Module, inferModuleFromFileName(base)),
			Category:  firstNonEmpty(a.Category, inferCategoryFromFileName(base)),
			Source:    "db",
		})
	}
	return localEntries, nil
}


// writeLocalFile writes content to a local file for a scan
func writeLocalFile(scanID, fileName string, data []byte) (string, error) {
	scanDir := getScanResultsDir(scanID)
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create scan directory: %w", err)
	}

	filePath := filepath.Join(scanDir, fileName)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write file: %w", err)
	}

	// Upload to R2 after local storage
	if r2storage.IsEnabled() {
		publicURL, err := r2storage.UploadFile(filePath, fileName, false)
		if err != nil {
			log.Printf("[R2] Failed to upload %s: %v", fileName, err)
		} else {
			log.Printf("[R2] Uploaded %s to %s", fileName, publicURL)
		}
	}

	return filePath, nil
}

// writeJSONToFile writes structured JSON data to a file
// This is called by modules to output JSON results
func writeJSONToFile(scanID, fileName string, jsonData interface{}) error {
	data, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	_, err = writeLocalFile(scanID, fileName, data)
	return err
}

// loadFileContent loads content from local file first, then R2
func loadFileContent(scanID, fileName string) ([]byte, string, error) {
	scanDir := getScanResultsDir(scanID)
	filePath := filepath.Join(scanDir, fileName)

	// Try local file first — return even if empty (0 bytes = no results found)
	if data, err := os.ReadFile(filePath); err == nil {
		return data, "local", nil
	}

	// Not available locally. Try R2 using the indexed artifact R2 key.
	if !r2storage.IsEnabled() {
		return nil, "", fmt.Errorf("file not found: %s", fileName)
	}

	// Look up the correct R2 key from the scan_artifacts table (most reliable).
	r2Key := ""
	if artifacts, err := db.ListScanArtifacts(scanID); err == nil {
		base := filepath.Base(fileName)
		for _, a := range artifacts {
			if a == nil {
				continue
			}
			if filepath.Base(a.FileName) == base || a.FileName == fileName {
				if a.R2Key != "" {
					r2Key = a.R2Key
					break
				}
				// Derive key from public URL if R2Key wasn't stored
				if a.PublicURL != "" {
					if k := r2storage.ExtractObjectKeyFromPublicURL(a.PublicURL); k != "" {
						r2Key = k
						break
					}
				}
			}
		}
	}

	// Fall back to bare filename if no artifact record found
	if r2Key == "" {
		r2Key = fileName
	}

	data, err := r2storage.GetObjectBytes(r2Key)
	if err != nil {
		// Also try bare filename as final fallback if a structured key was tried
		if r2Key != fileName {
			if data2, err2 := r2storage.GetObjectBytes(fileName); err2 == nil {
				return data2, "r2", nil
			}
		}
		return nil, "", fmt.Errorf("file not found: %s (tried local and R2)", fileName)
	}

	return data, "r2", nil
}


// GET /api/scans/:id/results/summary — scan metadata + local file list
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

	entries, err := listLocalFiles(scanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to list files: %v", err)})
		return
	}

	// Sort: JSON files first, then alphabetically
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsJSON != entries[j].IsJSON {
			return entries[i].IsJSON
		}
		return strings.Compare(entries[i].FileName, entries[j].FileName) < 0
	})

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

// GET /api/scans/:id/results/files — paginated local file list only
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

	entries, err := listLocalFiles(scanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to list files: %v", err)})
		return
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsJSON != entries[j].IsJSON {
			return entries[i].IsJSON
		}
		return strings.Compare(entries[i].FileName, entries[j].FileName) < 0
	})

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

// GET /api/scans/:id/results/file — load from local file or R2
func apiScanResultFileContent(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()
	scanID := strings.TrimSpace(c.Param("id"))
	fileName := strings.TrimSpace(c.Query("file_name"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "100"))

	if scanID == "" || fileName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan id and file_name are required"})
		return
	}
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 100
	}
	if perPage > 500 {
		perPage = 500
	}

	// Verify scan exists
	if _, err := db.GetScan(scanID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	raw, source, err := loadFileContent(scanID, fileName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	// Empty file — return a clean empty response rather than trying to parse nothing
	if len(raw) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"format":      "empty",
			"file_name":   fileName,
			"size_bytes":  0,
			"source_used": source,
			"lines":       []string{},
			"total":       0,
		})
		return
	}
	if len(raw) > scanResultMaxBody {

		c.JSON(http.StatusOK, gin.H{
			"format":      "too_large",
			"error":       "file too large for inline preview",
			"max_bytes":   scanResultMaxBody,
			"size_bytes":  len(raw),
		})
		return
	}

	isJSONExt := strings.HasSuffix(strings.ToLower(fileName), ".json")
	if !isJSONExt && len(raw) > 0 && json.Valid(raw) && (raw[0] == '{' || raw[0] == '[') {
		isJSONExt = true
	}

	if isJSONExt {
		resp := buildJSONPreview(raw, page, perPage)
		resp["file_name"] = fileName
		resp["size_bytes"] = len(raw)
		resp["source_used"] = source
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
			"size_bytes":  len(raw),
			"source_used": source,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"format":      "text",
		"file_name":   fileName,
		"size_bytes":  len(raw),
		"source_used": source,
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
			"format":      "json-array",
			"page":        page,
			"per_page":    perPage,
			"total_items": total,
			"items":       v[start:end],
			"prefer_json": true,
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
					"format":         "json-array",
					"array_field":    key,
					"page":           page,
					"per_page":       perPage,
					"total_items":    total,
					"items":          arr[start:end],
					"object_preview": trimObjectForPreview(v, key),
					"prefer_json":    true,
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

type parsedFinding struct {
	File     string `json:"file"`
	Module   string `json:"module"`
	Category string `json:"category"`
	Source   string `json:"source"`
	Kind     string `json:"kind,omitempty"` // recon dataset: subdomains, urls, js_urls, tech, ffuf, buckets, other
	Severity string `json:"severity"`
	Target   string `json:"target"`
	Finding  string `json:"finding"`
}

// inferReconKind maps artifact filenames to a stable dataset key for unified recon tables.
func inferReconKind(fileName string) string {
	b := strings.ToLower(filepath.Base(strings.TrimSpace(fileName)))
	if b == "" {
		return "other"
	}
	switch {
	// Log files
	case strings.HasSuffix(b, ".log"):
		return "logs"
	// JS URLs
	case strings.Contains(b, "js-url") || strings.Contains(b, "jsurl"):
		return "js_urls"
	// JS secrets / exposures → vuln
	case strings.Contains(b, "js-secret") || strings.Contains(b, "js-exposure") || strings.Contains(b, "secret") || strings.Contains(b, "exposure"):
		return "vuln"
	// Subdomains
	case strings.Contains(b, "all-subs") || strings.Contains(b, "live-subs") || strings.HasSuffix(b, "subs.txt") ||
		strings.Contains(b, "subdomain") || strings.Contains(b, "httpx") || strings.Contains(b, "live-host"):
		return "subdomains"
	// URLs / cnames
	case strings.Contains(b, "all-url") || strings.Contains(b, "interesting-url") || strings.Contains(b, "cname") ||
		(strings.HasSuffix(b, "urls.txt") && !strings.Contains(b, "js")):
		return "urls"
	// Tech detection
	case strings.Contains(b, "tech-detect") || strings.Contains(b, "technologies") || strings.Contains(b, "wappalyzer"):
		return "tech"
	// FFUF
	case strings.Contains(b, "ffuf") || strings.Contains(b, "fuzz"):
		return "ffuf"
	// Buckets / S3
	case strings.Contains(b, "bucket") || strings.Contains(b, "s3-"):
		return "buckets"
	// Nuclei / Vulnerabilities
	case strings.Contains(b, "nuclei") || strings.HasPrefix(b, "gf-") || strings.Contains(b, "gf-") ||
		strings.Contains(b, "misconfig") || strings.Contains(b, "zeroday") ||
		strings.Contains(b, "dalfox") || strings.Contains(b, "kxss") || strings.Contains(b, "xss") ||
		strings.Contains(b, "reflection") || strings.Contains(b, "confusion") || strings.Contains(b, "depconf"):
		return "vuln"
	// DNS / cloud takeover
	case strings.Contains(b, "dns") || strings.Contains(b, "takeover") || strings.Contains(b, "dnsreap") ||
		strings.Contains(b, "aws-") || strings.Contains(b, "azure-") || strings.Contains(b, "gcp-") ||
		strings.Contains(b, "cloudflare") || strings.Contains(b, "dangling"):
		return "dns"
	// Backup
	case strings.Contains(b, "backup") || strings.Contains(b, "fuzzuli"):
		return "backup"
	// Ports
	case strings.Contains(b, "port") || strings.Contains(b, "nmap") || strings.Contains(b, "masscan"):
		return "ports"
	default:
		return "other"
	}
}

// isHostOrIP returns true for bare hostnames / IPs / host:port that are
// NOT full URLs (those are handled separately by the http prefix check).
func isHostOrIP(s string) bool {
	// Strip optional port
	host := s
	if idx := strings.LastIndexByte(s, ':'); idx > 0 {
		// Make sure it is not an IPv6 address
		if !strings.Contains(s[:idx], ":") {
			host = s[:idx]
		}
	}
	// IP address (v4)
	parts := strings.Split(host, ".")
	if len(parts) == 4 {
		allDigits := true
		for _, p := range parts {
			if len(p) == 0 || len(p) > 3 {
				allDigits = false
				break
			}
			for _, c := range p {
				if c < '0' || c > '9' {
					allDigits = false
					break
				}
			}
		}
		if allDigits {
			return true
		}
	}
	// Hostname: must contain a dot and consist of valid label chars
	if !strings.Contains(host, ".") {
		return false
	}
	for _, c := range host {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return len(host) > 3
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func parseFindingFromObject(v map[string]interface{}, fallback string) parsedFinding {
	template := firstNonEmpty(
		fmt.Sprint(v["template-id"]),
		fmt.Sprint(v["template_id"]),
		fmt.Sprint(v["template"]),
		fmt.Sprint(v["id"]),
		fmt.Sprint(v["name"]),
		fmt.Sprint(v["title"]),
		fmt.Sprint(v["issue"]),
	)
	target := firstNonEmpty(
		fmt.Sprint(v["matched-at"]),
		fmt.Sprint(v["matched_at"]),
		fmt.Sprint(v["url"]),
		fmt.Sprint(v["host"]),
		fmt.Sprint(v["domain"]),
		fmt.Sprint(v["target"]),
	)
	sev := firstNonEmpty(
		fmt.Sprint(v["severity"]),
		fmt.Sprint(v["level"]),
	)
	if info, ok := v["info"].(map[string]interface{}); ok {
		if s := firstNonEmpty(fmt.Sprint(info["severity"])); s != "" {
			sev = s
		}
		if template == "" {
			template = firstNonEmpty(fmt.Sprint(info["name"]), fmt.Sprint(info["description"]))
		}
	}
	if template == "" {
		template = fallback
	}
	if target == "" {
		target = "—"
	}
	if sev == "" {
		sev = "—"
	}
	if template == "" {
		template = "—"
	}
	return parsedFinding{
		Severity: sev,
		Target:   target,
		Finding:  template,
	}
}

// isNoiseFinding returns true for rows that are debug/summary text and should
// not appear in the dashboard findings table.
func isNoiseFinding(finding, target string) bool {
	f := strings.TrimSpace(finding)
	t := strings.TrimSpace(target)
	if f == "" && t == "" {
		return true
	}
	if f == "<nil>" || f == "nil" || f == "—" {
		return true
	}
	// Nuclei summary file lines
	noisePrefixes := []string{
		"Nuclei Scan Summary",
		"No vulnerabilities found",
		"Target:",
		"Mode:",
		"Found ",
		"- nuclei-",
		"Tools Used:",
		"Scan Date:",
		"=== ",
		"Skipping unreachable target",
	}
	for _, p := range noisePrefixes {
		if strings.HasPrefix(f, p) {
			return true
		}
	}
	// Bare ISO timestamp (e.g. "2026-04-15 03:20:01")
	if len(f) >= 19 && f[4] == '-' && f[7] == '-' && f[10] == ' ' && f[13] == ':' {
		return true
	}
	return false
}

func parseArtifactFindings(raw []byte, module, category string, maxRows int) []parsedFinding {
	if maxRows < 1 {
		maxRows = 1
	}
	out := make([]parsedFinding, 0, minInt(maxRows, 64))
	appendRow := func(r parsedFinding) {
		if len(out) >= maxRows {
			return
		}
		if isNoiseFinding(r.Finding, r.Target) {
			return
		}
		if strings.TrimSpace(r.Target) == "" {
			r.Target = "—"
		}
		if strings.TrimSpace(r.Severity) == "" {
			r.Severity = "—"
		}
		if strings.TrimSpace(r.Finding) == "" {
			r.Finding = "—"
		}
		out = append(out, r)
	}

	// Try JSON first.
	var top interface{}
	if json.Unmarshal(raw, &top) == nil {
		var walk func(interface{})
		walk = func(x interface{}) {
			if len(out) >= maxRows {
				return
			}
			switch t := x.(type) {
			case map[string]interface{}:
				// Prefer known array fields for result objects.
				for _, key := range []string{"results", "findings", "matches", "issues", "vulnerabilities", "data", "items"} {
					if arr, ok := t[key].([]interface{}); ok && len(arr) > 0 {
						for _, it := range arr {
							walk(it)
							if len(out) >= maxRows {
								return
							}
						}
						return
					}
				}
				appendRow(parseFindingFromObject(t, module))
			case []interface{}:
				for _, it := range t {
					walk(it)
					if len(out) >= maxRows {
						return
					}
				}
			default:
				s := strings.TrimSpace(fmt.Sprint(t))
				if s != "" {
					appendRow(parsedFinding{Finding: s, Target: "—", Severity: "—"})
				}
			}
		}
		walk(top)
		if len(out) > 0 {
			return out
		}
	}

	// Text fallback — smart line classification.
	lines := strings.Split(string(raw), "\n")
	for _, ln := range lines {
		if len(out) >= maxRows {
			break
		}
		line := strings.TrimSpace(ln)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Try JSONL (each line is a JSON object)
		if strings.HasPrefix(line, "{") {
			var obj map[string]interface{}
			if json.Unmarshal([]byte(line), &obj) == nil {
				appendRow(parseFindingFromObject(obj, module))
				continue
			}
		}
		// Nuclei/tool bracket-style: [template-id] [proto] [severity] url
		// Example: [graphql-get] [http] [info] https://example.com/graphql
		// Example: [http-missing-security-headers:cross-origin-embedder-policy] [http] [info] https://example.com
		if strings.HasPrefix(line, "[") {
			templateID, severity, target := parseNucleiTextLine(line)
			if templateID != "" {
				appendRow(parsedFinding{Finding: templateID, Target: target, Severity: severity})
				continue
			}
		}
		// HTTP/HTTPS URL → Target column
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			appendRow(parsedFinding{Finding: module, Target: line, Severity: "—"})
			continue
		}
		// Hostname or IP (with optional port) → Target column
		if isHostOrIP(line) {
			appendRow(parsedFinding{Finding: module, Target: line, Severity: "—"})
			continue
		}
		// Everything else is a plain-text finding
		appendRow(parsedFinding{Finding: line, Target: "—", Severity: "—"})
	}
	return out
}

// parseNucleiTextLine parses the nuclei text output format:
//
//	[template-id] [proto] [severity] url [extra...]
//
// Returns templateID, severity, target URL.
func parseNucleiTextLine(line string) (templateID, severity, target string) {
	// Extract all bracket groups first
	type bracket struct{ content string }
	var brackets []string
	remainder := line
	for strings.HasPrefix(remainder, "[") {
		end := strings.Index(remainder, "]")
		if end < 0 {
			break
		}
		brackets = append(brackets, remainder[1:end])
		remainder = strings.TrimSpace(remainder[end+1:])
	}
	if len(brackets) < 2 {
		return "", "", ""
	}
	// brackets[0] = template-id  (may contain colon for sub-checks)
	// brackets[1] = protocol      (http, dns, tcp, …)
	// brackets[2] = severity      (if present)
	templateID = brackets[0]
	if len(brackets) >= 3 {
		severity = strings.ToLower(brackets[2])
	} else {
		severity = "info"
	}
	// The remainder after all brackets is the target URL/host
	target = strings.TrimSpace(remainder)
	if target == "" {
		target = "—"
	}
	return templateID, severity, target
}

// GET /api/scans/:id/results/parsed — flattened parsed findings for dashboard tables.
func apiScanParsedResults(c *gin.Context) {
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

	section := strings.ToLower(strings.TrimSpace(c.DefaultQuery("section", "all")))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "1200"))
	if limit < 1 {
		limit = 1200
	}
	if limit > 5000 {
		limit = 5000
	}


	// Use local files instead of artifact DB
	entries, err := listLocalFiles(scanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to list files: %v", err)})
		return
	}

	rows := make([]parsedFinding, 0, minInt(limit, 256))
	appendRows := func(ps []parsedFinding, e fileEntry) {
		kind := inferReconKind(e.FileName) // always attach kind for unified table tabs
		for _, r := range ps {
			if len(rows) >= limit {
				return
			}
			r.File = e.FileName
			r.Module = e.Module
			r.Category = e.Category
			r.Kind = kind
			rows = append(rows, r)
		}
	}

	for _, e := range entries {
		if len(rows) >= limit {
			break
		}
		if section == "vulnerability" && e.Category != "vulnerability" {
			continue
		}
		if section == "recon" && e.Category != "recon" {
			continue
		}
		// Read from local file
		raw, _, loadErr := loadFileContent(scanID, e.FileName)
		if loadErr != nil || len(raw) == 0 {
			continue
		}
		if len(raw) > scanResultMaxBody {
			continue
		}
		ps := parseArtifactFindings(raw, e.Module, e.Category, 250)
		appendRows(ps, e)
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id": scanID,
		"section": section,
		"total":   len(rows),
		"rows":    rows,
		"limit":   limit,
	})
}
