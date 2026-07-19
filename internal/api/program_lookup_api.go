package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/bbcatalog"
	"github.com/h0tak88r/AutoAR/internal/db"
)

// lookupResult is one row in a program-lookup response.
type lookupResult struct {
	Source        string `json:"source"` // h1, bc, it, ywh, as93
	Company       string `json:"company"`
	Handle        string `json:"handle"`
	URL           string `json:"url"`
	Rewards       string `json:"rewards"`
	SafeHarbor    string `json:"safe_harbor"`
	OffersBounty  bool   `json:"offers_bounty"`
	MatchType     string `json:"match_type"`              // "keyword" or "domain"
	MatchedDomain string `json:"matched_domain,omitempty"`
	InScope       *bool  `json:"in_scope,omitempty"` // set for domain matches
}

// looksLikeDomain heuristically decides whether a query is a domain vs a keyword.
func looksLikeDomain(q string) bool {
	q = strings.TrimSpace(q)
	if q == "" || strings.ContainsAny(q, " \t") {
		return false
	}
	q = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(q, "http://"), "https://"), "/")
	return strings.Contains(q, ".") && !strings.Contains(q, " ")
}

// GET /api/assets/program-lookup?q=<keyword-or-domain>&mode=auto|keyword|domain
func apiProgramLookup(c *gin.Context) {
	q := strings.TrimSpace(c.Query("q"))
	if q == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "q is required"})
		return
	}
	mode := strings.ToLower(c.DefaultQuery("mode", "auto"))
	const limit = 100

	var out []lookupResult
	seen := map[string]bool{} // dedupe by source|handle|matchType

	doKeyword := mode == "keyword" || mode == "auto"
	doDomain := mode == "domain" || (mode == "auto" && looksLikeDomain(q))

	if doDomain {
		// Strip scheme/path so a URL paste still matches.
		dq := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(q, "http://"), "https://"), "/")
		if i := strings.IndexByte(dq, '/'); i >= 0 {
			dq = dq[:i]
		}
		matches, err := db.SearchCatalogByDomain(dq, limit)
		if err == nil {
			for _, m := range matches {
				k := "d|" + m.Source + "|" + m.Handle
				if seen[k] {
					continue
				}
				seen[k] = true
				in := m.InScope
				out = append(out, lookupResult{
					Source: m.Source, Company: m.Company, Handle: m.Handle, URL: m.URL,
					Rewards: m.Rewards, SafeHarbor: m.SafeHarbor, OffersBounty: m.OffersBounty,
					MatchType: "domain", MatchedDomain: m.MatchedDomain, InScope: &in,
				})
			}
		}
	}

	if doKeyword {
		progs, err := db.SearchCatalogByKeyword(q, limit)
		if err == nil {
			for _, p := range progs {
				k := "k|" + p.Source + "|" + p.Handle
				if seen[k] {
					continue
				}
				seen[k] = true
				out = append(out, lookupResult{
					Source: p.Source, Company: p.Company, Handle: p.Handle, URL: p.URL,
					Rewards: p.Rewards, SafeHarbor: p.SafeHarbor, OffersBounty: p.OffersBounty,
					MatchType: "keyword",
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"query":     q,
		"is_domain": looksLikeDomain(q),
		"results":   out,
		"total":     len(out),
	})
}

// POST /api/assets/program-sync — rebuild the catalog in the background.
func apiProgramSync(c *gin.Context) {
	if bbcatalog.SyncAsync() {
		c.JSON(http.StatusAccepted, gin.H{"status": "started", "message": "Catalog sync started in the background"})
		return
	}
	c.JSON(http.StatusConflict, gin.H{"status": "running", "message": "A sync is already in progress"})
}

// GET /api/assets/catalog-status — counts + last sync summary.
func apiCatalogStatus(c *gin.Context) {
	progs, doms, _ := db.CatalogCounts()
	running, last, at := bbcatalog.SyncStatus()
	var lastAt string
	if !at.IsZero() {
		lastAt = at.Format(time.RFC3339)
	}
	c.JSON(http.StatusOK, gin.H{
		"programs":       progs,
		"domains":        doms,
		"sync_running":   running,
		"last_sync_at":   lastAt,
		"last_sync":      last,
	})
}
