package api

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/accounts"
	scopemod "github.com/h0tak88r/AutoAR/internal/scanner/scope"
	"github.com/sw33tLie/bbscope/pkg/scope"
)

// platformMeta describes one bug bounty platform for the UI.
type platformMeta struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Logo        string   `json:"logo"` // emoji or short text
	AuthFields  []string `json:"auth_fields"`
	EnvKeys     []string `json:"env_keys"`
	Description string   `json:"description"`
}

var platforms = []platformMeta{
	{
		ID:          "h1",
		Name:        "HackerOne",
		Logo:        "",
		AuthFields:  []string{"username", "token"},
		EnvKeys:     []string{"H1_USERNAME", "H1_TOKEN"},
		Description: "Fetch in-scope root domains from all accessible HackerOne programs.",
	},
	{
		ID:          "bc",
		Name:        "Bugcrowd",
		Logo:        "",
		AuthFields:  []string{"token"},
		EnvKeys:     []string{"BUGCROWD_TOKEN"},
		Description: "Fetch in-scope root domains from all accessible Bugcrowd programs.",
	},
	{
		ID:          "ywh",
		Name:        "YesWeHack",
		Logo:        "",
		AuthFields:  []string{"token"},
		EnvKeys:     []string{"YWH_TOKEN"},
		Description: "Fetch in-scope root domains from all accessible YesWeHack programs. Use your JWT token from the YWH API.",
	},
	{
		ID:          "it",
		Name:        "Intigriti",
		Logo:        "",
		AuthFields:  []string{"token"},
		EnvKeys:     []string{"INTIGRITI_TOKEN", "INTIGRITI_API_KEY"},
		Description: "Fetch in-scope root domains from all accessible Intigriti programs.",
	},
	{
		ID:          "immunefi",
		Name:        "Immunefi",
		Logo:        "",
		AuthFields:  []string{},
		EnvKeys:     []string{},
		Description: "Fetch public Web3/smart-contract programs from Immunefi (no auth required).",
	},
}

// GET /api/scope/platforms — returns list of supported platforms + their env key status
func apiScopePlatforms(c *gin.Context) {
	type platformStatus struct {
		platformMeta
		EnvConfigured bool `json:"env_configured"`
		AccountCount  int  `json:"account_count"`
	}
	out := make([]platformStatus, 0, len(platforms))
	for _, p := range platforms {
		configured := len(p.EnvKeys) == 0 // immunefi needs no creds
		for _, k := range p.EnvKeys {
			if os.Getenv(k) != "" {
				configured = true
				break
			}
		}
		cnt := accounts.Count(p.ID)
		if cnt > 0 {
			configured = true
		}
		out = append(out, platformStatus{p, configured, cnt})
	}
	c.JSON(http.StatusOK, gin.H{"platforms": out})
}

// scopeFetchRequest is the body for POST /api/scope/fetch
type scopeFetchRequest struct {
	Platform     string `json:"platform"`
	Username     string `json:"username,omitempty"`
	Token        string `json:"token,omitempty"`
	Email        string `json:"email,omitempty"`
	Password     string `json:"password,omitempty"`
	BBPOnly      bool   `json:"bbp_only"`
	PvtOnly      bool   `json:"pvt_only"`
	PublicOnly   bool   `json:"public_only"`
	ActiveOnly   bool   `json:"active_only"`
	IncludeOOS   bool   `json:"include_oos"`
	ExtractRoots *bool  `json:"extract_roots,omitempty"` // default true if omitted
}

// POST /api/scope/fetch — fetch programs + extract root domains from a bug bounty platform
func apiFetchScope(c *gin.Context) {
	var req scopeFetchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}
	if req.Platform == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "platform is required (h1, bc, ywh, it, immunefi)"})
		return
	}

	// Map platform string to Platform type
	var platform scopemod.Platform
	switch strings.ToLower(req.Platform) {
	case "h1", "hackerone":
		platform = scopemod.PlatformHackerOne
	case "bc", "bugcrowd":
		platform = scopemod.PlatformBugcrowd
	case "it", "intigriti":
		platform = scopemod.PlatformIntigriti
	case "ywh", "yeswehack":
		platform = scopemod.PlatformYesWeHack
	case "immunefi":
		platform = scopemod.PlatformImmunefi
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported platform: " + req.Platform})
		return
	}

	extractRoots := true // default
	if req.ExtractRoots != nil {
		extractRoots = *req.ExtractRoots
	}

	baseOpts := scopemod.Options{
		Platform:     platform,
		Categories:   "all",
		Concurrency:  5,
		BBPOnly:      req.BBPOnly,
		PvtOnly:      req.PvtOnly,
		PublicOnly:   req.PublicOnly,
		ActiveOnly:   req.ActiveOnly,
		IncludeOOS:   req.IncludeOOS,
		ExtractRoots: extractRoots,
	}

	var programs []scope.ProgramData
	var fetchErr error
	accountsUsed := 0

	if strings.TrimSpace(req.Token) != "" || platform == scopemod.PlatformImmunefi {
		// Explicit token in the request (or no-auth immunefi) → single fetch.
		opts := baseOpts
		opts.Username = firstNonEmpty(req.Username, os.Getenv("H1_USERNAME"))
		opts.Token = req.Token
		opts.Email = firstNonEmpty(req.Email, os.Getenv("YWH_EMAIL"))
		opts.Password = firstNonEmpty(req.Password, os.Getenv("YWH_PASSWORD"))
		programs, fetchErr = scopemod.FetchScope(opts)
		accountsUsed = 1
	} else {
		// No explicit creds → fetch across every stored account for the platform and merge.
		for _, a := range accounts.For(accounts.Canonical(req.Platform)) {
			opts := baseOpts
			opts.Username = a.Username
			opts.Token = a.Token
			opts.Email = a.Email
			opts.Password = a.Password
			ps, e := scopemod.FetchScope(opts)
			if e != nil {
				if fetchErr == nil {
					fetchErr = e
				}
				continue
			}
			programs = append(programs, ps...)
			accountsUsed++
		}
	}
	if len(programs) == 0 && fetchErr != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to fetch scope: " + fetchErr.Error()})
		return
	}

	var rootDomains []string
	if extractRoots {
		var err error
		rootDomains, err = scopemod.ExtractRootDomains(programs)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to extract root domains: " + err.Error()})
			return
		}
	} else {
		rootDomains = []string{}
	}

	rawTargets := scopemod.ExtractRawTargets(programs)

	// Merging multiple accounts can yield duplicate domains/targets — dedupe.
	rootDomains = uniqueStrings(rootDomains)
	rawTargets = uniqueStrings(rawTargets)

	c.JSON(http.StatusOK, gin.H{
		"platform":      req.Platform,
		"programs":      len(programs),
		"accounts_used": accountsUsed,
		"root_domains":  rootDomains,
		"raw_targets":   rawTargets,
		"domain_count":  len(rootDomains),
		"target_count":  len(rawTargets),
	})
}
