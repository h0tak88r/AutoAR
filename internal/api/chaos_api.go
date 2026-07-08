package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/scanner/chaos"
)

// POST /api/chaos/subdomains
// Body: { "domain": "example.com", "save": true }
// Fetches the domain's known subdomains from ProjectDiscovery Chaos (CHAOS_API_KEY)
// and optionally persists them to the Subdomains DB.
func apiChaosSubdomains(c *gin.Context) {
	var req struct {
		Domain string `json:"domain"`
		Save   bool   `json:"save"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	// Normalize once so the fetch, the persisted domain record, and the response
	// all key off the exact same canonical domain (e.g. "https://Example.com/" →
	// "example.com") — otherwise saved subdomains attach to a bogus domain row.
	domain := chaos.NormalizeDomain(req.Domain)
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}
	if !chaos.Configured() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "CHAOS_API_KEY is not set — add it in Settings → Bug Bounty Platform API Keys"})
		return
	}

	subs, err := chaos.FetchSubdomains(domain)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	saved := 0
	if req.Save && len(subs) > 0 {
		if err := db.BatchInsertSubdomains(domain, subs, false); err != nil {
			// Return the results anyway — the fetch succeeded, only persistence failed.
			c.JSON(http.StatusOK, gin.H{
				"domain": domain, "count": len(subs), "subdomains": subs,
				"saved": 0, "save_error": err.Error(),
			})
			return
		}
		saved = len(subs)
	}

	c.JSON(http.StatusOK, gin.H{
		"domain": domain, "count": len(subs), "subdomains": subs, "saved": saved,
	})
}
