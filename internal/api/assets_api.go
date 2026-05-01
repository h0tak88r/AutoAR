package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/db"
)

// AssetEntry is one discovered host with enriched recon data.
type AssetEntry struct {
	Host         string   `json:"host"`
	IsLive       bool     `json:"is_live"`
	StatusCode   int      `json:"status_code,omitempty"`
	Title        string   `json:"title,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	CNAMEs       []string `json:"cnames,omitempty"`
	IPs          []string `json:"ips,omitempty"`
	URL          string   `json:"url,omitempty"`
}

func apiScanAssets(c *gin.Context) {
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
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "100"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 100
	}
	if perPage > 1000 {
		perPage = 1000
	}

	assets := buildAssets(scanID)
	total := len(assets)

	// Slice for pagination
	start := (page - 1) * perPage
	if start < 0 { start = 0 }
	end := start + perPage
	
	if start >= total {
		start = 0
		if total > 0 { end = total } else { end = 0 }
		pagedAssets := []AssetEntry{}
		if total > 0 && start < total { // should not happen with start=0
             // ...
		}
		c.JSON(http.StatusOK, gin.H{
			"scan_id":  scanID,
			"total":    total,
			"page":     page,
			"per_page": perPage,
			"assets":   pagedAssets,
		})
		return
	}

	if end > total {
		end = total
	}
	pagedAssets := assets[start:end]

	c.JSON(http.StatusOK, gin.H{
		"scan_id":  scanID,
		"total":    total,
		"page":     page,
		"per_page": perPage,
		"assets":   pagedAssets,
	})
}

// buildAssets reads several result files and merges them by hostname.
func buildAssets(scanID string) []AssetEntry {
	byHost := map[string]*AssetEntry{}

	getOrCreate := func(host string) *AssetEntry {
		host = normalizeHost(host)
		if host == "" {
			return nil
		}
		if e, ok := byHost[host]; ok {
			return e
		}
		e := &AssetEntry{Host: host}
		byHost[host] = e
		return e
	}

	appendUniq := func(sl []string, v string) []string {
		v = strings.TrimSpace(v)
		if v == "" {
			return sl
		}
		for _, x := range sl {
			if x == v {
				return sl
			}
		}
		return append(sl, v)
	}

	// ── 1. All subdomains ────────────────────────────────────────────────────
	for _, name := range []string{
		"all-subs.txt", "subdomains.txt", "enumerated-subs.txt",
	} {
		walkLines(scanID, name, func(line string) {
			getOrCreate(line)
		})
	}
	// Also read the new JSON envelope format (WriteLinesAsJSON: {items: ["sub1", ...]})
	if raw, _, err := loadFileContent(scanID, "subdomains.json"); err == nil && len(raw) > 0 {
		var wrapper map[string]interface{}
		if json.Unmarshal(raw, &wrapper) == nil {
			if items, ok := wrapper["items"].([]interface{}); ok {
				for _, it := range items {
					if s, ok := it.(string); ok {
						getOrCreate(s)
					}
				}
			}
		}
	}
	// ── 1. Database-first discovery (Most complete source) ──────────────────
	// For enumeration-style scans, pull the full record from the subdomains table.
	if scan, err := db.GetScan(scanID); err == nil && scan.Target != "" {
		st := scan.ScanType
		subdomainScanTypes := map[string]bool{
			"domain_run": true, "subdomain_run": true, "recon": true,
			"subdomains": true, "livehosts": true, "dns_cf1016": true, "dns-cf1016": true,
		}
		if subdomainScanTypes[st] {
			// The DB stores subdomains under the ROOT domain key, not a subdomain target.
			// Try the scan target as-is first, then progressively strip labels until we
			// find the key that exists in the domains table.
			candidates := domainCandidates(scan.Target)
			for _, candidate := range candidates {
				dbEntries, err := db.ListSubdomainsWithStatus(candidate)
				if err != nil || len(dbEntries) == 0 {
					continue
				}
				for _, s := range dbEntries {
					e := getOrCreate(s.Subdomain)
					if e == nil { continue }
					e.IsLive = s.IsLive
					if s.HTTPSURL != "" {
						e.URL = s.HTTPSURL
					} else if s.HTTPURL != "" {
						e.URL = s.HTTPURL
					}
					if s.HTTPSStatus > 0 {
						e.StatusCode = s.HTTPSStatus
					} else if s.HTTPStatus > 0 {
						e.StatusCode = s.HTTPStatus
					}
					if s.Techs != "" {
						for _, t := range strings.Split(s.Techs, ",") {
							e.Technologies = appendUniq(e.Technologies, t)
						}
					}
					if s.CNAMEs != "" {
						for _, c := range strings.Split(s.CNAMEs, ",") {
							e.CNAMEs = appendUniq(e.CNAMEs, c)
						}
					}
				}
				break // Found a match — stop trying candidates
			}
		}
	}

	// ── 2. Files fallback/enrichment ─────────────────────────────────────────
	for _, name := range []string{
		"all-subs.txt", "subdomains.txt", "enumerated-subs.txt",
	} {
		walkLines(scanID, name, func(line string) {
			getOrCreate(line)
		})
	}
	// Also read the new JSON envelope format (WriteLinesAsJSON: {items: ["sub1", ...]})
	if raw, _, err := loadFileContent(scanID, "subdomains.json"); err == nil && len(raw) > 0 {
		var wrapper map[string]interface{}
		if json.Unmarshal(raw, &wrapper) == nil {
			if items, ok := wrapper["items"].([]interface{}); ok {
				for _, it := range items {
					if s, ok := it.(string); ok {
						getOrCreate(s)
					}
				}
			} else if items, ok := wrapper["subdomains"].([]interface{}); ok {
				for _, it := range items {
					if s, ok := it.(string); ok {
						getOrCreate(s)
					}
				}
			}
		}
	}

	// ── 2. Live subdomains ───────────────────────────────────────────────────
	for _, name := range []string{
		"live-subs.txt", "live-hosts.txt", "httpx.txt",
	} {
		walkLines(scanID, name, func(line string) {
			// Could be a URL (https://sub.example.com) or bare host
			host := normalizeHost(line)
			if e := getOrCreate(host); e != nil {
				e.IsLive = true
				if strings.HasPrefix(strings.ToLower(line), "http") && e.URL == "" {
					e.URL = strings.TrimSpace(line)
				}
			}
		})
	}
	// Also read livehosts.json — {"results": [{"URL":"https://...", "StatusCode":200, ...}]}
	if raw, _, err := loadFileContent(scanID, "livehosts.json"); err == nil && len(raw) > 0 {
		var wrapper map[string]interface{}
		if json.Unmarshal(raw, &wrapper) == nil {
			if results, ok := wrapper["results"].([]interface{}); ok {
				for _, r := range results {
					obj, ok := r.(map[string]interface{})
					if !ok {
						continue
					}
					rawURL := strPick(obj, "URL", "url", "Host", "host")
					host := normalizeHost(rawURL)
					if e := getOrCreate(host); e != nil {
						e.IsLive = true
						if strings.HasPrefix(strings.ToLower(rawURL), "http") && e.URL == "" {
							e.URL = rawURL
						}
						if sc := intPick(obj, "StatusCode", "status_code", "statusCode"); sc > 0 && e.StatusCode == 0 {
							e.StatusCode = sc
						}
					}
				}
			}
		}
	}
	// (Database-first discovery above already handled ListLiveSubdomains info)

	// ── 3. Tech-detect — status code, title, tech ────────────────────────────
	// First try the new structured JSON array format (written by tech.go WriteJSONToScanDir):
	// [{"matched-at":"https://host", "status_code":200, "title":"...", "technologies":[...]}]
	for _, name := range []string{"tech-detect.json"} {
		raw, _, err := loadFileContent(scanID, name)
		if err != nil || len(raw) == 0 {
			continue
		}
		// Try JSON array first (new format)
		var arr []map[string]interface{}
		if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 {
			for _, obj := range arr {
				rawURL := strPick(obj, "matched-at", "url", "input", "host")
				host := normalizeHost(rawURL)
				if host == "" {
					continue
				}
				e := getOrCreate(host)
				if e == nil {
					continue
				}
				if strings.HasPrefix(strings.ToLower(rawURL), "http") {
					e.IsLive = true
					if e.URL == "" {
						e.URL = rawURL
					}
				}
				if sc := intPick(obj, "status_code", "status-code", "statusCode"); sc > 0 && e.StatusCode == 0 {
					e.StatusCode = sc
					if sc < 400 {
						e.IsLive = true
					}
				}
				if t := strPick(obj, "title"); t != "" && e.Title == "" {
					e.Title = t
				}
				if techs, ok := obj["technologies"].([]interface{}); ok {
					for _, t := range techs {
						e.Technologies = appendUniq(e.Technologies, strings.TrimSpace(fmt.Sprint(t)))
					}
				}
			}
			continue // Array parsed — skip JSONL attempt
		}
		// Fallback: try JSONL format (legacy httpx -json output — one object per line)
		scanner := bufio.NewScanner(bytes.NewReader(raw))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if !strings.HasPrefix(line, "{") {
				continue
			}
			var obj map[string]interface{}
			if json.Unmarshal([]byte(line), &obj) != nil {
				continue
			}
			rawURL := strPick(obj, "url", "input", "host")
			host := normalizeHost(rawURL)
			if host == "" {
				continue
			}
			e := getOrCreate(host)
			if e == nil {
				continue
			}
			if strings.HasPrefix(strings.ToLower(rawURL), "http") {
				e.IsLive = true
				if e.URL == "" {
					e.URL = rawURL
				}
			}
			if sc := intPick(obj, "status-code", "status_code", "statusCode"); sc > 0 {
				e.StatusCode = sc
				if sc < 400 {
					e.IsLive = true
				}
			}
			if t := strPick(obj, "title"); t != "" && e.Title == "" {
				e.Title = t
			}
			if techs, ok := obj["tech"].([]interface{}); ok {
				for _, t := range techs {
					e.Technologies = appendUniq(e.Technologies, strings.TrimSpace(fmt.Sprint(t)))
				}
			}
			if techs, ok := obj["technologies"].([]interface{}); ok {
				for _, t := range techs {
					e.Technologies = appendUniq(e.Technologies, strings.TrimSpace(fmt.Sprint(t)))
				}
			}
		}
	}

	// Fallback: parse tech-detect.txt plain text format written by the tech module:
	// "https://host.example.com [200] [Page Title] [nginx] [WordPress,PHP]"
	for _, name := range []string{"tech-detect.txt"} {
		raw, _, err := loadFileContent(scanID, name)
		if err != nil || len(raw) == 0 {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(raw))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// First token is the URL
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			rawURL := fields[0]
			host := normalizeHost(rawURL)
			if host == "" {
				continue
			}
			e := getOrCreate(host)
			if e == nil {
				continue
			}
			if strings.HasPrefix(strings.ToLower(rawURL), "http") {
				e.IsLive = true
				if e.URL == "" {
					e.URL = rawURL
				}
			}
			// Extract bracketed fields: [statusCode] [title] [server] [techs]
			// Format: url [200] [Title text] [nginx/1.x] [WordPress,PHP]
			rest := strings.TrimSpace(strings.TrimPrefix(line, rawURL))
			var brackets []string
			for {
				start := strings.Index(rest, "[")
				if start < 0 {
					break
				}
				end := strings.Index(rest[start:], "]")
				if end < 0 {
					break
				}
				val := rest[start+1 : start+end]
				brackets = append(brackets, strings.TrimSpace(val))
				rest = rest[start+end+1:]
			}
			if len(brackets) >= 1 && e.StatusCode == 0 {
				var code int
				if _, err := fmt.Sscanf(brackets[0], "%d", &code); err == nil && code > 0 {
					e.StatusCode = code
					if code < 400 {
						e.IsLive = true
					}
				}
			}
			if len(brackets) >= 2 && e.Title == "" && brackets[1] != "" {
				e.Title = brackets[1]
			}
			// brackets[2] = server header (skip)
			// brackets[3] = comma-separated technologies
			if len(brackets) >= 4 && brackets[3] != "" {
				for _, t := range strings.Split(brackets[3], ",") {
					s := strings.TrimSpace(t)
					if s != "" {
						e.Technologies = appendUniq(e.Technologies, s)
					}
				}
			}
		}
	}

	// ── 4. CNAMEs — plain text + structured JSON ─────────────────────────────
	for _, name := range []string{"cnames.txt", "cname.txt", "cname-results.txt", "cname-records.txt"} {
		walkLines(scanID, name, func(line string) {
			// dnsx format: "sub.domain.com CNAME target.domain.com" OR
			// "sub.domain.com --> target.domain.com"
			parts := strings.Fields(strings.ReplaceAll(strings.ReplaceAll(line, "-->", " "), "->", " "))
			if len(parts) < 2 {
				return
			}
			host := normalizeHost(parts[0])
			// Last token is the CNAME target
			cname := strings.TrimSuffix(strings.TrimSpace(parts[len(parts)-1]), ".")
			if e := getOrCreate(host); e != nil && cname != "" && cname != host {
				e.CNAMEs = appendUniqStr(e.CNAMEs, cname)
			}
		})
	}
	// Also parse cname-records.json (structured file written by the cnames module)
	// Format: {"records": [{"subdomain": "sub.example.com", "cname": "target.example.com", "type": "CNAME"}]}
	if raw, _, err := loadFileContent(scanID, "cname-records.json"); err == nil && len(raw) > 0 {
		var wrapper map[string]interface{}
		if json.Unmarshal(raw, &wrapper) == nil {
			if records, ok := wrapper["records"].([]interface{}); ok {
				for _, r := range records {
					obj, ok := r.(map[string]interface{})
					if !ok {
						continue
					}
					subdomain := strings.TrimSpace(fmt.Sprint(obj["subdomain"]))
					cnameVal := strings.TrimSuffix(strings.TrimSpace(fmt.Sprint(obj["cname"])), ".")
					if subdomain == "" || cnameVal == "" || cnameVal == "<nil>" {
						continue
					}
					host := normalizeHost(subdomain)
					if e := getOrCreate(host); e != nil && cnameVal != host {
						e.CNAMEs = appendUniqStr(e.CNAMEs, cnameVal)
					}
				}
			}
		}
	}


	// ── 5. Build sorted slice ────────────────────────────────────────────────
	result := make([]AssetEntry, 0, len(byHost))
	for _, e := range byHost {
		result = append(result, *e)
	}
	sort.Slice(result, func(i, j int) bool {
		// Live before dead, then alphabetical
		if result[i].IsLive != result[j].IsLive {
			return result[i].IsLive
		}
		return result[i].Host < result[j].Host
	})
	return result
}

// ── helpers ──────────────────────────────────────────────────────────────────

// walkLines reads a file line-by-line and calls fn for each non-empty, non-comment line.
func walkLines(scanID, fileName string, fn func(string)) {
	raw, _, err := loadFileContent(scanID, fileName)
	if err != nil || len(raw) == 0 {
		return
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fn(line)
	}
}

// normalizeHost extracts the bare hostname from a URL or bare host string.
func normalizeHost(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(s), "http") {
		u, err := url.Parse(s)
		if err == nil {
			s = u.Hostname()
		}
	}
	// Strip trailing dot (DNSex)
	s = strings.TrimSuffix(s, ".")
	s = strings.ToLower(strings.TrimSpace(s))
	return s
}

// domainCandidates returns the input plus progressively shorter parent domains.
// e.g. "www.fasttest.com" → ["www.fasttest.com", "fasttest.com"]
// This lets buildAssets find subdomains stored under a root domain key even when
// the scan target is a subdomain (e.g. subdomain_run against www.fasttest.com).
func domainCandidates(target string) []string {
	h := normalizeHost(target)
	if h == "" {
		return nil
	}
	var out []string
	for {
		out = append(out, h)
		dot := strings.Index(h, ".")
		if dot < 0 {
			break
		}
		parent := h[dot+1:]
		if !strings.Contains(parent, ".") {
			// Stop before we hit a bare TLD (e.g. "com")
			break
		}
		h = parent
	}
	return out
}

// strPick returns the first non-empty string value from keys in obj.
func strPick(obj map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := obj[k]; ok && v != nil {
			s := strings.TrimSpace(fmt.Sprint(v))
			if s != "" && s != "<nil>" {
				return s
			}
		}
	}
	return ""
}

// intPick returns the first non-zero int value from keys in obj.
func intPick(obj map[string]interface{}, keys ...string) int {
	for _, k := range keys {
		if v, ok := obj[k]; ok && v != nil {
			switch t := v.(type) {
			case float64:
				if t > 0 {
					return int(t)
				}
			case int:
				if t > 0 {
					return t
				}
			}
		}
	}
	return 0
}

// appendUniqStr is a package-level variant of appendUniq for string slices.
func appendUniqStr(sl []string, v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return sl
	}
	for _, x := range sl {
		if x == v {
			return sl
		}
	}
	return append(sl, v)
}
