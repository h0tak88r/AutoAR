package gobot

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/modules/db"
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

// GET /api/scans/:id/results/assets
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

	assets := buildAssets(scanID)
	c.JSON(http.StatusOK, gin.H{
		"scan_id": scanID,
		"total":   len(assets),
		"assets":  assets,
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

	// ── 3. Tech-detect (httpx JSONL) — status code, title, tech, IPs ────────
	for _, name := range []string{
		"tech-detect.txt", "tech-detect.json",
		"httpx.json", "httpx-output.txt",
	} {
		raw, _, err := loadFileContent(scanID, name)
		if err != nil || len(raw) == 0 {
			continue
		}
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

			// Determine host from several possible fields
			rawURL := strPick(obj, "url", "input", "host")
			host := normalizeHost(rawURL)
			if host == "" {
				continue
			}

			e := getOrCreate(host)
			if e == nil {
				continue
			}

			// URL
			if strings.HasPrefix(strings.ToLower(rawURL), "http") {
				e.IsLive = true
				if e.URL == "" {
					e.URL = rawURL
				}
			}
			// Status code
			if sc := intPick(obj, "status-code", "status_code", "statusCode"); sc > 0 {
				e.StatusCode = sc
				if sc < 400 {
					e.IsLive = true
				}
			}
			// Title
			if t := strPick(obj, "title"); t != "" && e.Title == "" {
				e.Title = t
			}
			// Technologies
			if techs, ok := obj["tech"].([]interface{}); ok {
				for _, t := range techs {
					s := strings.TrimSpace(fmt.Sprint(t))
					e.Technologies = appendUniq(e.Technologies, s)
				}
			}
			// technologies (alternative key)
			if techs, ok := obj["technologies"].([]interface{}); ok {
				for _, t := range techs {
					s := strings.TrimSpace(fmt.Sprint(t))
					e.Technologies = appendUniq(e.Technologies, s)
				}
			}
			// IPs from "a" field (httpx DNS A records)
			if ips, ok := obj["a"].([]interface{}); ok {
				for _, ip := range ips {
					e.IPs = appendUniq(e.IPs, strings.TrimSpace(fmt.Sprint(ip)))
				}
			}
		}
	}

	// ── 4. CNAMEs ────────────────────────────────────────────────────────────
	for _, name := range []string{"cnames.txt", "cname.txt", "cname-results.txt"} {
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
