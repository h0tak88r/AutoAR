package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/bbcatalog"
	"github.com/h0tak88r/AutoAR/internal/db"
	scopemod "github.com/h0tak88r/AutoAR/internal/scanner/scope"
)

// lookupResult is one row in a program-lookup response.
type lookupResult struct {
	Source        string   `json:"source"` // h1, bc, it, ywh, as93
	Company       string   `json:"company"`
	Handle        string   `json:"handle"`
	URL           string   `json:"url"`
	Rewards       string   `json:"rewards"`
	SafeHarbor    string   `json:"safe_harbor"`
	OffersBounty  bool     `json:"offers_bounty"`
	MatchType     string   `json:"match_type"` // "keyword" or "domain"
	MatchedDomain string   `json:"matched_domain,omitempty"`
	MatchKind     string   `json:"match_kind,omitempty"` // domain matches: exact | wildcard | related | guess
	InScope       *bool    `json:"in_scope,omitempty"`   // set for exact/wildcard domain matches; nil for related
	Accounts      []string `json:"accounts,omitempty"`   // your account labels that can see this program
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
		// Exact host + parent-domain walk over exact and "*." catalog entries
		// (db.SearchCatalogByDomain normalizes scheme/port/path itself). No
		// substring matching: example.com never hits notexample.com.
		matches, err := db.SearchCatalogByDomain(q, limit)
		if err == nil {
			for _, m := range matches {
				k := "d|" + m.Source + "|" + m.Handle
				if seen[k] {
					continue
				}
				seen[k] = true
				r := lookupResult{
					Source: m.Source, Company: m.Company, Handle: m.Handle, URL: scopemod.PublicProgramURL(m.URL),
					Rewards: m.Rewards, SafeHarbor: m.SafeHarbor, OffersBounty: m.OffersBounty,
					MatchType: "domain", MatchedDomain: m.MatchedDomain, MatchKind: m.MatchKind,
				}
				// A program that only lists a parent host (or "*.host" for the
				// apex itself) is related, not a scope verdict either way.
				if m.MatchKind != db.CatalogMatchRelated {
					in := m.InScope
					r.InScope = &in
				}
				out = append(out, r)
			}
		}
	}

	// No catalog entry for the host or any parent: look for programs named
	// like its root domain (888kiss.aliexpress.com → "aliexpress"). These
	// name the likely owner; they are not a scope verdict.
	rootDomain := ""
	if doDomain && len(out) == 0 {
		var progs []db.CatalogProgram
		rootDomain, progs = rootNamePrograms(db.NormalizeCatalogHost(q))
		for _, p := range progs {
			k := "d|" + p.Source + "|" + p.Handle
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, lookupResult{
				Source: p.Source, Company: p.Company, Handle: p.Handle, URL: scopemod.PublicProgramURL(p.URL),
				Rewards: p.Rewards, SafeHarbor: p.SafeHarbor, OffersBounty: p.OffersBounty,
				MatchType: "domain", MatchedDomain: rootDomain, MatchKind: "guess",
			})
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
					Source: p.Source, Company: p.Company, Handle: p.Handle, URL: scopemod.PublicProgramURL(p.URL),
					Rewards: p.Rewards, SafeHarbor: p.SafeHarbor, OffersBounty: p.OffersBounty,
					MatchType: "keyword",
				})
			}
		}
	}

	// Which of your accounts can see each program (catalog-sync visibility,
	// keyed <source>|<handle>) — i.e. which account to submit from.
	accts := programAccountsMap()
	for i := range out {
		if labels := accts[out[i].Source+"|"+out[i].Handle]; len(labels) > 0 {
			out[i].Accounts = labels
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"query":     q,
		"is_domain": looksLikeDomain(q),
		"root":      rootDomain,
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
		"programs":     progs,
		"domains":      doms,
		"sync_running": running,
		"last_sync_at": lastAt,
		"last_sync":    last,
	})
}
