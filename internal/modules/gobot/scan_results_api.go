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
	case strings.Contains(n, "cf1016") || strings.Contains(n, "cf-1016") || strings.Contains(n, "cloudflare-1016"):
		return "cf1016"
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
	case strings.Contains(n, "aem"):
		return "aem-scan"
	case strings.Contains(n, "github") || strings.Contains(n, "repo"):
		return "github-scan"
	case strings.Contains(n, "backup") || strings.Contains(n, "fuzzuli"):
		return "backup-detection"
	case strings.Contains(n, "reflection") || strings.Contains(n, "kxss") || strings.Contains(n, "dalfox") || strings.Contains(n, "xss"):
		return "xss-detection"
	case strings.Contains(n, "confusion") || strings.Contains(n, "depconf"):
		return "dependency-confusion"
	case strings.Contains(n, "js-url") || strings.Contains(n, "js_url"):
		return "JS-Enum"
	case n == "urls.txt" || n == "all-urls.txt" || strings.Contains(n, "wayback"):
		return "url-enum"
	default:
		return "autoar"
	}
}

func inferCategoryFromFileName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	// Vulnerability outputs
	if strings.Contains(n, "nuclei") || strings.HasPrefix(n, "gf-") || strings.Contains(n, "gf-") ||
		strings.Contains(n, "cf1016") || strings.Contains(n, "cf-1016") ||
		strings.Contains(n, "misconfig") || strings.Contains(n, "zeroday") ||
		strings.Contains(n, "dalfox") || strings.Contains(n, "sqlmap") || strings.Contains(n, "vuln") ||
		strings.Contains(n, "xss") || strings.Contains(n, "kxss") || strings.Contains(n, "reflection") ||
		strings.Contains(n, "secret") || strings.Contains(n, "exposure") || strings.Contains(n, "js-secret") ||
		strings.Contains(n, "aws-") || strings.Contains(n, "azure-") || strings.Contains(n, "gcp-") ||
		strings.Contains(n, "takeover") || strings.Contains(n, "dangling") || strings.Contains(n, "dnsreap") ||
		strings.Contains(n, "confusion") || strings.Contains(n, "depconf") || strings.Contains(n, "backup") ||
		strings.Contains(n, "aem") {
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
	// CF1016 dangling — must be checked before generic cloudflare/dangling catch below
	case strings.Contains(b, "cf1016") || strings.Contains(b, "cf-1016"):
		return "dns"
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


func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v != "" && v != "<nil>" && v != "\u003cnil\u003e" {
			return v
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
	// CF1016 structured finding: {target, subdomain, cloudflare_ips, http_status, type, severity, description}
	if cfType, ok := v["cloudflare_ips"]; ok && cfType != nil {
		subdomain := strings.TrimSpace(fmt.Sprint(v["target"]))
		if subdomain == "" {
			subdomain = strings.TrimSpace(fmt.Sprint(v["subdomain"]))
		}
		ipsRaw, _ := v["cloudflare_ips"].([]interface{})
		ipStrs := make([]string, 0, len(ipsRaw))
		for _, ip := range ipsRaw {
			if s := strings.TrimSpace(fmt.Sprint(ip)); s != "" {
				ipStrs = append(ipStrs, s)
			}
		}
		status := fmt.Sprint(v["http_status"])
		findingLabel := "Dangling Record (CF-1016)"
		if len(ipStrs) > 0 {
			findingLabel += " — IPs: " + strings.Join(ipStrs, ", ")
		}
		if status != "" && status != "<nil>" && status != "0" {
			findingLabel += " [HTTP " + status + "]"
		}
		sev := strings.TrimSpace(fmt.Sprint(v["severity"]))
		if sev == "" || sev == "<nil>" {
			sev = "high"
		}
		return parsedFinding{
			Severity: sev,
			Target:   subdomain,
			Finding:  findingLabel,
		}
	}

	// DNS takeover structured finding: {target, type, status, details, subdomains}
	// Written by utils.WriteDNSTakeoverJSON
	if dnsType, ok := v["type"].(string); ok && v["target"] != nil {
		target := strings.TrimSpace(fmt.Sprint(v["target"]))
		status := strings.TrimSpace(fmt.Sprint(v["status"]))
		details := strings.TrimSpace(fmt.Sprint(v["details"]))
		if target != "" && target != "<nil>" {
			// Map type to a user-friendly finding label
			typeLabel := map[string]string{
				"dangling-ip":       "Dangling IP",
				"azure-takeover":    "Azure Takeover",
				"aws-takeover":      "AWS Takeover",
				"ns-takeover":       "NS Takeover",
				"cloudflare-tunnel": "Cloudflare Tunnel Error",
				"dns-takeover":      "DNS Takeover",
				"dns-candidate":     "DNS Candidate",
			}[strings.ToLower(dnsType)]
			if typeLabel == "" {
				typeLabel = dnsType
			}
			if status != "" && status != "<nil>" {
				typeLabel += " [" + status + "]"
			}
			sev := "—"
			if strings.Contains(strings.ToLower(dnsType), "vulnerable") || strings.Contains(strings.ToLower(dnsType), "takeover") {
				sev = "medium"
			}
			_ = details
			return parsedFinding{
				Severity: sev,
				Target:   target,
				Finding:  typeLabel,
			}
		}
	}

	// JS Secrets
	if secType, ok := v["type"].(string); ok && v["secret"] != nil && v["file"] != nil {
		return parsedFinding{
			Severity: firstNonEmpty(fmt.Sprint(v["severity"]), "high"),
			Target:   firstNonEmpty(fmt.Sprint(v["file"])),
			Finding:  fmt.Sprintf("[%s]: %s", secType, v["secret"]),
		}
	}

	// S3 Buckets
	if bucketStatus, ok := v["status"].(string); ok && (v["bucket"] != nil || v["target"] != nil) && v["type"] == nil {
		targetField := firstNonEmpty(fmt.Sprint(v["target"]), fmt.Sprint(v["bucket"]))
		isVuln, _ := v["vulnerable"].(bool)
		findType := "s3-enum"
		if isVuln {
			findType = "s3-scan-" + strings.ToLower(bucketStatus)
		}
		return parsedFinding{
			Severity: firstNonEmpty(fmt.Sprint(v["severity"]), "info"),
			Target:   targetField,
			Finding:  findType,
		}
	}

	// Port Scanner
	if port, ok := v["port"]; ok && v["host"] != nil {
		svc := firstNonEmpty(fmt.Sprint(v["service"]))
		return parsedFinding{
			Severity: firstNonEmpty(fmt.Sprint(v["severity"]), "info"),
			Target:   firstNonEmpty(fmt.Sprint(v["host"])),
			Finding:  fmt.Sprintf("Open Port %v (%s)", port, svc),
		}
	}

	template := firstNonEmpty(
		fmt.Sprint(v["finding"]),
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
				// ZeroDays summary-only guard: TotalVulnerable==0 with no findings -> skip.
				if tv, hasTV := t["TotalVulnerable"]; hasTV {
					if n, ok := tv.(float64); ok && n == 0 {
						return
					}
				}
				// Prefer known array fields for result objects.
				// React2ShellVulns / MongoDBVulns are the ZeroDays module array keys.
				for _, key := range []string{"findings", "React2ShellVulns", "MongoDBVulns", "results", "matches", "issues", "vulnerabilities", "data", "items"} {
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
			case string:
				fT := "URL-Enum"
				if module == "JS-Enum" {
					fT = "JS-Enum"
				} else if module == "url-enum" {
					fT = "URL-Enum"
				} else {
					fT = module
				}
				appendRow(parsedFinding{
					Target:   t,
					Finding:  fT,
					Severity: "info",
				})
			default:
			}
		}
		walk(top)
		if len(out) > 0 {
			return out
		}
	} else {
		// Fallback line-by-line parser for text files (e.g., js-urls.txt, urls.txt)
		lines := strings.Split(string(raw), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fT := "URL-Enum"
			if module == "JS-Enum" {
				fT = "JS-Enum"
			} else if module == "url-enum" {
				fT = "URL-Enum"
			} else {
				fT = module
			}
			appendRow(parsedFinding{
				Target:   line,
				Finding:  fT,
				Severity: "info",
			})
		}
	}
	
	return out
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

	// Build set of all indexed file basenames so we can detect when both a raw .txt
	// and its structured JSON replacement are present (old scans indexed both).
	// In that case, skip the raw file to avoid duplicate / un-parsed rows.
	presentFiles := map[string]bool{}
	for _, e := range entries {
		presentFiles[strings.ToLower(e.FileName)] = true
	}
	// rawToJSON maps a raw shadowed filename to the JSON that supersedes it.
	// Also maps pipeline input files (subdomains/URLs) to a sentinel "" to mark
	// them as "always skip" — the sentinel is never present so they are dropped.
	rawToJSON := map[string]string{
		"misconfig-scan-results.txt":    "misconfig-vulnerabilities.json",
		"ffuf-results.txt":              "ffuf-results.json",
		"ffuf-webhook-messages.txt":     "ffuf-results.json",
		"kxss-results.txt":              "xss-reflection-vulnerabilities.json",
		"exposure-findings.txt":         "exposure-vulnerabilities.json",
		// URL corpus files — never findings, always skip (uncommented to SHOW in URL tab)
		// "urls.json":                      "__pipeline_input__",
		// "js-urls.json":                   "__pipeline_input__",
		// Subdomain / port list envelopes — raw line lists, not structured findings
		// "subdomains.json":                "__pipeline_input__",
		// "ports.json":                     "__pipeline_input__",
		// Live hosts — served by /assets, never by /parsed findings
		"livehosts.json":                 "__pipeline_input__",
		// CNAME recon — served by DNS section, not findings
		"cname-records.json":             "__pipeline_input__",
		// Pipeline input files — never findings, always skip
		// "all-subs.txt":                  "__pipeline_input__",
		// "live-subs.txt":                 "__pipeline_input__",
		"live-hosts.txt":                "__pipeline_input__",
		// "all-urls.txt":                  "__pipeline_input__",
		// "subdomains.txt":                "__pipeline_input__",
		// "enumerated-subs.txt":           "__pipeline_input__",
		"nuclei-summary.txt":            "__pipeline_input__",
		// DNS raw intermediate files
		"dangling-ip.txt":               "dns-takeover-vulnerabilities.json",
		"ns-takeover-raw.txt":           "dns-takeover-vulnerabilities.json",
		"ns-servers-vuln.txt":           "dns-takeover-vulnerabilities.json",
		"azure-takeover.txt":            "dns-takeover-vulnerabilities.json",
		"aws-takeover.txt":              "dns-takeover-vulnerabilities.json",
		"gcp-takeover.txt":              "dns-takeover-vulnerabilities.json",
		"cloudflare-tunnel-errors.txt":  "dns-takeover-vulnerabilities.json",
		"cname-takeover-raw.txt":        "dns-takeover-vulnerabilities.json",
		"cname-takeover-vulnerable.txt": "dns-takeover-vulnerabilities.json",
		// CF1016 text report is superseded by the structured JSON twin
		"cf1016-dangling.txt":           "cf1016-dangling.json",
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
		// Skip raw files that are superseded by their structured JSON equivalent
		// (handles existing scans indexed before the shouldSkipArtifact fix).
		// Files mapped to "__pipeline_input__" are always skipped (they are tool
		// inputs like all-subs.txt, never dashboard findings).
		if jsonReplacement, isRaw := rawToJSON[strings.ToLower(e.FileName)]; isRaw {
			if jsonReplacement == "__pipeline_input__" {
				continue
			}
			if presentFiles[strings.ToLower(jsonReplacement)] {
				continue
			}
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
