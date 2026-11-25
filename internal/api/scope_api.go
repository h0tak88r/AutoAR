package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/accounts"
	"github.com/h0tak88r/AutoAR/internal/bbcatalog"
	"github.com/h0tak88r/AutoAR/internal/logger"
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
		ID:          "bizone",
		Name:        "BI.ZONE",
		Logo:        "",
		AuthFields:  []string{"token"},
		EnvKeys:     []string{"BIZONE_SESSION"},
		Description: "Fetch in-scope root domains from BI.ZONE bug-bounty tasks. Token = the browser sessionid cookie.",
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

	// BI.ZONE has no bbscope backend: its fetcher is native (session-cookie
	// JSON API, see programs_bizone.go). It feeds the same extract/dedupe
	// tail below, so the Platforms page card works like every other source.
	if strings.EqualFold(strings.TrimSpace(req.Platform), "bizone") || strings.EqualFold(strings.TrimSpace(req.Platform), "bi.zone") {
		select {
		case scopeFetchSlots <- struct{}{}:
			defer func() { <-scopeFetchSlots }()
		default:
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "a scope fetch is already running — try again when it finishes"})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), scopeFetchTimeout)
		defer cancel()

		var programs []scope.ProgramData
		var fetchErr error
		accountsUsed := 0
		if tok := strings.TrimSpace(req.Token); tok != "" {
			programs, fetchErr = fetchBizonePrograms(ctx, tok)
			accountsUsed = 1
		} else {
			for _, a := range accounts.For("bizone") {
				ps, e := fetchBizonePrograms(ctx, a.Token)
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
		bizoneRespond(c, "bizone", req, programs, accountsUsed)
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

	// Bounded concurrency: each child pulls every program's scope (minutes of
	// upstream calls); unbounded parallel requests would fan out into as many
	// children hammering the same platform tokens.
	select {
	case scopeFetchSlots <- struct{}{}:
		defer func() { <-scopeFetchSlots }()
	default:
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "a scope fetch is already running — try again when it finishes"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), scopeFetchTimeout)
	defer cancel()

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
		programs, fetchErr = fetchScopeIsolated(ctx, opts)
		accountsUsed = 1
	} else {
		// No explicit creds → fetch across every stored account for the platform and merge.
		for _, a := range accounts.For(accounts.Canonical(req.Platform)) {
			if platform == scopemod.PlatformBugcrowd {
				// A session AutoAR keeps alive; bbscope's own sign-in is outdated.
				token, _, detail := accounts.BugcrowdSession(a, false)
				if token == "" {
					if fetchErr == nil {
						fetchErr = fmt.Errorf("bugcrowd/%s: %s", a.Label, detail)
					}
					continue
				}
				a.Token, a.Email, a.Password = token, "", ""
			}
			opts := baseOpts
			opts.Username = a.Username
			opts.Token = a.Token
			opts.Email = a.Email
			opts.Password = a.Password
			ps, e := fetchScopeIsolated(ctx, opts)
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

// bizoneRespond mirrors the shared extract/dedupe/response tail of
// apiFetchScope for the native BI.ZONE path.
func bizoneRespond(c *gin.Context, platformID string, req scopeFetchRequest, programs []scope.ProgramData, accountsUsed int) {
	extractRoots := req.ExtractRoots == nil || *req.ExtractRoots
	var rootDomains []string
	if extractRoots {
		var err error
		rootDomains, err = scopemod.ExtractRootDomains(programs)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to extract root domains: " + err.Error()})
			return
		}
	}
	rawTargets := scopemod.ExtractRawTargets(programs)
	rootDomains = uniqueStrings(rootDomains)
	rawTargets = uniqueStrings(rawTargets)
	c.JSON(http.StatusOK, gin.H{
		"platform":      platformID,
		"programs":      len(programs),
		"accounts_used": accountsUsed,
		"root_domains":  rootDomains,
		"raw_targets":   rawTargets,
		"domain_count":  len(rootDomains),
		"target_count":  len(rawTargets),
	})
}

const scopeFetchTimeout = 30 * time.Minute

// scopeFetchSlots bounds concurrent scope-fetch children.
var scopeFetchSlots = make(chan struct{}, 2)

// fetchScopeIsolated runs scopemod.FetchScope in a disposable `scope-fetch`
// child process. bbscope log.Fatal()s (os.Exit) on HTTP errors, stale tokens
// and rate limits — and its Intigriti client indexes upstream strings
// unchecked — so running it in the API process could kill the server (and
// every running scan) from one button click. Options (credentials included)
// travel over stdin; the result comes back as JSON.
func fetchScopeIsolated(ctx context.Context, opts scopemod.Options) ([]scope.ProgramData, error) {
	in, err := json.Marshal(opts)
	if err != nil {
		return nil, err
	}
	out, tail, runErr := bbcatalog.RunChild(ctx, []string{"scope-fetch"}, in)
	var res scopemod.FetchResult
	if len(out) > 0 {
		if jerr := json.Unmarshal(out, &res); jerr != nil && runErr == nil {
			runErr = fmt.Errorf("bad child result: %w", jerr)
		}
	}
	if runErr != nil {
		logger.GetLogger().Infof("[SCOPE-FETCH] %s child failed: %v\n--- child output tail ---\n%s", opts.Platform, runErr, tail)
		return res.Programs, fmt.Errorf("%s fetch failed (%v): %s", opts.Platform, runErr, bbcatalog.LastLine(tail, 300))
	}
	if res.Error != "" {
		return res.Programs, errors.New(res.Error)
	}
	return res.Programs, nil
}
