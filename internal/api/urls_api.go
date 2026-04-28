package api

// GET /api/scans/:id/results/urls
//
// Dedicated, paginated endpoint that serves ALL collected URLs for a scan —
// bypassing the 250-per-file and 1200-total-row limits of /results/parsed.
//
// Source priority (all deduplicated into one list):
//
//  1. Scan-scoped JSON envelopes (new-results/<scanID>/):
//     urls.json, js-urls.json, interesting-urls.json
//     Written by utils.WriteLinesAsJSON during the scan.
//
//  2. Domain-scoped plain-text files (new-results/<domain>/urls/):
//     all-urls.txt   ← 300+ wayback/commoncrawl/alienvault/urlscan/VT URLs
//     js-urls.txt, interesting-urls.txt
//     Written by the urls.go module directly to the domain directory.
//     These are NOT in the scan dir — they live at the domain level.
//
//  3. Scan-scoped plain-text fallbacks (older scans before JSON was added).
//
//  R2 fallback is attempted for both scan-scoped and domain-scoped files
//  when local files are absent.
//
// Query params:
//   page    int    (default 1)
//   limit   int    (default 500, max 5000)
//   q       string — substring filter on URL
//   type    "all" | "js" | "interesting"  (default "all")

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/r2storage"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// URLEntry is one discovered URL with metadata.
type URLEntry struct {
	URL           string `json:"url"`
	IsJS          bool   `json:"is_js,omitempty"`
	IsInteresting bool   `json:"is_interesting,omitempty"`
}

func apiScanURLs(c *gin.Context) {
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

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "500"))
	q := strings.ToLower(strings.TrimSpace(c.Query("q")))
	typeFilter := strings.ToLower(strings.TrimSpace(c.DefaultQuery("type", "all")))

	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 500
	}
	if limit > 5000 {
		limit = 5000
	}

	allURLs := collectAllURLEntries(scanID)

	filtered := make([]URLEntry, 0, len(allURLs))
	for _, e := range allURLs {
		switch typeFilter {
		case "js":
			if !e.IsJS {
				continue
			}
		case "interesting":
			if !e.IsInteresting {
				continue
			}
		}
		if q != "" && !strings.Contains(strings.ToLower(e.URL), q) {
			continue
		}
		filtered = append(filtered, e)
	}

	total := len(filtered)
	start := (page - 1) * limit
	if start >= total {
		start = 0
	}
	end := start + limit
	if end > total {
		end = total
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id": scanID,
		"total":   total,
		"page":    page,
		"limit":   limit,
		"type":    typeFilter,
		"urls":    filtered[start:end],
	})
}

// collectAllURLEntries reads every URL-producing file for a scan and returns a
// deduplicated list tagged with is_js and is_interesting flags.
func collectAllURLEntries(scanID string) []URLEntry {
	seen := map[string]int{}
	result := []URLEntry{}

	add := func(rawURL string, isJS, isInteresting bool) {
		u := strings.TrimSpace(rawURL)
		if u == "" || u == "#" {
			return
		}
		if idx, exists := seen[u]; exists {
			if isJS {
				result[idx].IsJS = true
			}
			if isInteresting {
				result[idx].IsInteresting = true
			}
			return
		}
		seen[u] = len(result)
		result = append(result, URLEntry{URL: u, IsJS: isJS, IsInteresting: isInteresting})
	}

	// parseAndAdd handles JSON array, JSON envelope, or plain text.
	parseAndAdd := func(raw []byte, isJS, isInteresting bool) {
		if len(raw) == 0 {
			return
		}
		var arr []string
		if json.Unmarshal(raw, &arr) == nil {
			for _, u := range arr {
				add(u, isJS, isInteresting)
			}
			return
		}
		var wrapper map[string]interface{}
		if json.Unmarshal(raw, &wrapper) == nil {
			for _, key := range []string{"items", "urls", "url_list"} {
				if list, ok := wrapper[key].([]interface{}); ok {
					for _, v := range list {
						if s, ok := v.(string); ok {
							add(s, isJS, isInteresting)
						}
					}
					return
				}
			}
			return
		}
		// Plain text fallback.
		sc := bufio.NewScanner(bytes.NewReader(raw))
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			add(line, isJS, isInteresting)
		}
	}

	// readScanFile reads from the scan directory or R2 via the artifact index.
	readScanFile := func(fileName string, isJS, isInteresting bool) {
		raw, _, err := loadFileContent(scanID, fileName)
		if err != nil || len(raw) == 0 {
			return
		}
		parseAndAdd(raw, isJS, isInteresting)
	}

	// readDomainFile reads directly from the domain-level URL directory.
	// The urls.go module writes its output to new-results/<domain>/urls/<file>
	// rather than to the scan directory, so we need to look there.
	readDomainFile := func(domain, fileName string, isJS, isInteresting bool) {
		if domain == "" {
			return
		}
		domainDir, err := utils.DomainDirInit(domain)
		if err != nil {
			return
		}
		localPath := filepath.Join(domainDir, "urls", fileName)
		if raw, err := os.ReadFile(localPath); err == nil && len(raw) > 0 {
			parseAndAdd(raw, isJS, isInteresting)
			return
		}
		// Fall back to R2 using the domain-level object key.
		if r2storage.IsEnabled() {
			r2Key := "new-results/" + domain + "/urls/" + fileName
			if raw, err := r2storage.GetObjectBytes(r2Key); err == nil && len(raw) > 0 {
				parseAndAdd(raw, isJS, isInteresting)
			}
		}
	}

	// Resolve the domain from the scan record.
	// For subdomain_run the target IS the subdomain (e.g. panorapresse.ouest-france.fr)
	// which is also used as the dirDomain in urls.go (skipSubdomainEnum=true path).
	var domain string
	if scan, err := db.GetScan(scanID); err == nil && scan.Target != "" {
		domain = extractURLScanDomain(scan.Target)
	}

	// ── 1. Scan-scoped JSON envelopes (written by WriteLinesAsJSON) ───────────
	readScanFile("urls.json", false, false)
	readScanFile("js-urls.json", true, false)
	readScanFile("interesting-urls.json", false, true)

	// ── 2. Domain-scoped plain-text files (the authoritative full corpus) ─────
	readDomainFile(domain, "all-urls.txt", false, false)
	readDomainFile(domain, "js-urls.txt", true, false)
	readDomainFile(domain, "interesting-urls.txt", false, true)

	// ── 3. Scan-scoped plain-text fallbacks (pre-JSON older scans) ────────────
	readScanFile("all-urls.txt", false, false)
	readScanFile("js-urls.txt", true, false)
	readScanFile("interesting-urls.txt", false, true)

	// ── 4. JS heuristic back-tagging ─────────────────────────────────────────
	for i := range result {
		u := strings.ToLower(result[i].URL)
		if !result[i].IsJS && (strings.HasSuffix(u, ".js") ||
			strings.Contains(u, ".js?") ||
			strings.HasSuffix(u, ".jsx") ||
			strings.HasSuffix(u, ".mjs")) {
			result[i].IsJS = true
		}
	}

	return result
}

// extractURLScanDomain derives the directory key used by urls.go from a scan target.
// When skipSubdomainEnum=true (subdomain_run), urls.go uses dirDomain=domain (the
// full subdomain). When false (domain_run), it strips to root domain.
// Since we can't know which was used, return the target as-is — the full subdomain
// is the correct key for subdomain_run, which is the most common case.
func extractURLScanDomain(target string) string {
	h := strings.TrimPrefix(target, "https://")
	h = strings.TrimPrefix(h, "http://")
	if idx := strings.Index(h, "/"); idx != -1 {
		h = h[:idx]
	}
	if idx := strings.Index(h, ":"); idx != -1 {
		h = h[:idx]
	}
	return strings.ToLower(strings.TrimSpace(h))
}
