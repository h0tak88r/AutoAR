package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/h0tak88r/AutoAR/internal/dorks"
	"github.com/h0tak88r/AutoAR/internal/seclab"
)

// apiDorksHandler serves the recon dork corpus.
//
//	GET /api/dorks                      -> {severity: [{title,icon,platforms,query}]}
//	                                       (the Security Lab page's shape; {T} kept
//	                                       for client-side target substitution)
//	GET /api/dorks?format=full&target=  -> {version, platforms, dorks:[resolved]}
//	    &category=&platform=&severity=&q=  (flattened + filtered; {T} substituted
//	                                       and a clickable URL built when target set)
func apiDorksHandler(c *gin.Context) {
	db, err := dorks.Load()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if c.Query("format") == "full" {
		opts := dorks.FilterOpts{
			Category: c.Query("category"),
			Platform: c.Query("platform"),
			Severity: c.Query("severity"),
			Query:    c.Query("q"),
		}
		resolved := db.Resolve(opts, c.Query("target"))
		c.JSON(http.StatusOK, gin.H{
			"version":   db.Version,
			"generated": db.Generated,
			"count":     len(resolved),
			"platforms": db.Platforms,
			"dorks":     resolved,
		})
		return
	}
	c.JSON(http.StatusOK, db.LegacyGrouped())
}

// apiSeclabHandler serves a Security Lab reference dataset as raw JSON.
//
//	GET /api/seclab/ssrf                -> SSRF payload groups
//	GET /api/seclab/xss                 -> XSS cheat sheet
//	GET /api/seclab/takeover-subdomain  -> subdomain takeover fingerprints
//	GET /api/seclab/takeover-dns        -> DNS/NS takeover fingerprints
func apiSeclabHandler(c *gin.Context) {
	raw, err := seclab.Raw(c.Param("name"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error(), "available": seclab.Names()})
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", raw)
}
