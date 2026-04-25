package gobot

// GET /api/scans/:id/results/urls
//
// Dedicated, paginated endpoint that serves ALL collected URLs for a scan —
// bypassing the 250-per-file and 1200-total-row limits of /results/parsed.
//
// Sources read (in priority order, deduplicated):
//   urls.json          → {items:[…]} envelope  (all-urls, all sources merged)
//   js-urls.json       → {items:[…]} envelope  (JS URLs only)
//   js-urls.txt        → plain text fallback
//   interesting-urls.json → {items:[…]} filtered subset
//   all-urls.txt       → plain text fallback
//
// Query params:
//   page    int  (default 1)
//   limit   int  (default 500, max 5000)
//   q       string — substring filter applied to the URL
//   type    "all" | "js" | "interesting"  (default "all")

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/modules/db"
)

// URLEntry is one discovered URL with metadata.
type URLEntry struct {
	URL          string `json:"url"`
	IsJS         bool   `json:"is_js,omitempty"`
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

	// Collect and deduplicate all URLs from every source file.
	allURLs := collectAllURLEntries(scanID)

	// Apply type filter.
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
		"scan_id":  scanID,
		"total":    total,
		"page":     page,
		"limit":    limit,
		"type":     typeFilter,
		"urls":     filtered[start:end],
	})
}

// collectAllURLEntries reads every URL-producing file for a scan and returns a
// deduplicated list tagged with is_js and is_interesting flags.
func collectAllURLEntries(scanID string) []URLEntry {
	seen := map[string]int{} // url → index in result
	result := []URLEntry{}

	add := func(rawURL string, isJS, isInteresting bool) {
		u := strings.TrimSpace(rawURL)
		if u == "" || u == "#" {
			return
		}
		if idx, exists := seen[u]; exists {
			// Already known — promote flags only.
			if isJS {
				result[idx].IsJS = true
			}
			if isInteresting {
				result[idx].IsInteresting = true
			}
			return
		}
		seen[u] = len(result)
		result = append(result, URLEntry{
			URL:           u,
			IsJS:          isJS,
			IsInteresting: isInteresting,
		})
	}

	// Helper: read {items:[...]} JSON envelope.
	readJSONItems := func(fileName string, isJS, isInteresting bool) {
		raw, _, err := loadFileContent(scanID, fileName)
		if err != nil || len(raw) == 0 {
			return
		}
		// Try array first.
		var arr []string
		if json.Unmarshal(raw, &arr) == nil {
			for _, u := range arr {
				add(u, isJS, isInteresting)
			}
			return
		}
		// Try envelope {items:[...]} or {urls:[...]}.
		var wrapper map[string]interface{}
		if json.Unmarshal(raw, &wrapper) != nil {
			return
		}
		for _, key := range []string{"items", "urls", "url_list"} {
			if arr, ok := wrapper[key].([]interface{}); ok {
				for _, v := range arr {
					if s, ok := v.(string); ok {
						add(s, isJS, isInteresting)
					}
				}
				return
			}
		}
	}

	// Helper: read plain-text file (one URL per line).
	readTextFile := func(fileName string, isJS, isInteresting bool) {
		raw, _, err := loadFileContent(scanID, fileName)
		if err != nil || len(raw) == 0 {
			return
		}
		sc := bufio.NewScanner(bytes.NewReader(raw))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			add(line, isJS, isInteresting)
		}
	}

	// 1. All URLs (main corpus from every OSINT source + spider).
	readJSONItems("urls.json", false, false)
	readTextFile("all-urls.txt", false, false)

	// 2. JS URLs specifically.
	readJSONItems("js-urls.json", true, false)
	readTextFile("js-urls.txt", true, false)

	// 3. Interesting (filtered) subset — promotes the flag on already-seen URLs.
	readJSONItems("interesting-urls.json", false, true)
	readTextFile("interesting-urls.txt", false, true)

	// 4. Back-tag JS entries discovered via the is_js heuristic.
	for i := range result {
		u := strings.ToLower(result[i].URL)
		if !result[i].IsJS && (strings.Contains(u, ".js") || strings.HasSuffix(u, ".jsx") || strings.HasSuffix(u, ".mjs")) {
			result[i].IsJS = true
		}
	}

	return result
}
