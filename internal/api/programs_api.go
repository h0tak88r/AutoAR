package api

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/accounts"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/tidwall/gjson"
)

// ─────────────────────────────────────────────────────────────────────────────
// Shared types
// ─────────────────────────────────────────────────────────────────────────────

// ProgramSummary is the unified view sent to the UI for both H1 and BC.
type ProgramSummary struct {
	ID                    string       `json:"id"`
	Platform              string       `json:"platform"` // "h1" or "bc"
	Handle                string       `json:"handle"`
	Name                  string       `json:"name"`
	URL                   string       `json:"url"`
	State                 string       `json:"state"`            // public_mode, soft_launched, open, etc.
	SubmissionState       string       `json:"submission_state"` // open, closed, paused
	OffersBounties        bool         `json:"offers_bounties"`
	Currency              string       `json:"currency"`
	FastPayments          bool         `json:"fast_payments"`
	SafeHarbor            bool         `json:"safe_harbor"`
	Bookmarked            bool         `json:"bookmarked"`
	ScopeTargets          int          `json:"scope_targets"`            // count of in-scope targets
	LatestTarget          string       `json:"latest_target"`            // one representative target
	LatestTargetUpdatedAt string       `json:"latest_target_updated_at"` // latest in-scope target update time
	LatestTargetBrief     string       `json:"latest_target_brief"`      // brief context for the latest target
	UpdatedAt             string       `json:"updated_at"`               // when we last fetched this
	Stats                 ProgramStats `json:"stats"`
	Assets                []string     `json:"-"`                        // all in-scope asset identifiers (internal, for scope-change monitoring)
	ExternalPlatform      string       `json:"external_platform,omitempty"` // real platform for aggregator sources (e.g. "Immunefi" for Platform=="ha")
	Sources               []string     `json:"sources,omitempty"`        // account label(s) that can see this program (multi-account)
}

// mergeProgramsByHandle appends src programs into dst, deduping by (platform,
// handle). When a program is already present from another account, the source
// account label is unioned onto its Sources tag rather than duplicating the row.
func mergeProgramsByHandle(dst []ProgramSummary, idx map[string]int, src []ProgramSummary, sourceLabel string) []ProgramSummary {
	for _, p := range src {
		key := strings.ToLower(p.Platform + "|" + p.Handle)
		if at, ok := idx[key]; ok {
			dst[at].Sources = appendUniqueStr(dst[at].Sources, sourceLabel)
			continue
		}
		if sourceLabel != "" {
			p.Sources = appendUniqueStr(p.Sources, sourceLabel)
		}
		dst = append(dst, p)
		idx[key] = len(dst) - 1
	}
	return dst
}

func appendUniqueStr(s []string, v string) []string {
	if v == "" {
		return s
	}
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// ProgramStats holds user-specific stats from H1.
type ProgramStats struct {
	ReportsForUser      int     `json:"reports_for_user"`
	ValidReportsForUser int     `json:"valid_reports_for_user"`
	BountyEarnedForUser float64 `json:"bounty_earned_for_user"`
}

type programScopeRequest struct {
	Programs []programScopeRequestItem `json:"programs"`
	Force    bool                      `json:"force"` // bypass the scope cache (manual Refresh)
}

type programScopeRequestItem struct {
	Platform string `json:"platform"`
	Handle   string `json:"handle"`
	URL      string `json:"url"`
}

type cachedProgramScope struct {
	Summary   ProgramSummary
	ExpiresAt time.Time
}

var (
	programScopeCacheMu sync.Mutex
	programScopeCache   = map[string]cachedProgramScope{}
)

const programScopeCacheTTL = 15 * time.Minute

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/scope/programs
// ─────────────────────────────────────────────────────────────────────────────

func apiListPrograms(c *gin.Context) {
	platform := strings.ToLower(c.DefaultQuery("platform", "all"))
	bbpOnly := true
	includeScope := c.DefaultQuery("include_scope", "false") == "true"
	sortBy := c.DefaultQuery("sort", "name")
	forceRefresh := c.DefaultQuery("refresh", "false") == "true"

	// The DB-backed cache is only usable when a DB is configured. Without it we
	// skip all cache/background-refresh logic and just do a live fetch (the
	// original behavior) — otherwise every request would kick an expensive
	// upstream rebuild that can never be persisted.
	cacheOn := programsCacheEnabled()

	if cacheOn {
		// A manual "refresh now" rebuilds in the background (the rebuild makes ~1000
		// upstream calls and takes ~a minute — far too long to block the request on).
		// We kick it off and still serve the current cache instantly below.
		if forceRefresh {
			refreshProgramsCacheAsync()
		}

		// Warm-cache fast path: serve the pre-fetched payload (scope already baked in)
		// instantly. If it is stale, refresh in the background and still serve now.
		if payload, ok := loadProgramsCache(); ok && len(payload.Programs) > 0 {
			stale := time.Since(payload.GeneratedAt) > programsCacheTTL
			if stale && !forceRefresh {
				refreshProgramsCacheAsync()
			}
			serveProgramsPayload(c, payload, platform, sortBy, stale)
			return
		}

		// Cold path (cache not built yet): fall back to a live fetch so the first-ever
		// load still works, and kick a background build so the next load is instant.
		defer refreshProgramsCacheAsync()
	}

	var allPrograms []ProgramSummary
	var mu sync.Mutex
	var wg sync.WaitGroup

	if platform == "all" || platform == "h1" || platform == "hackerone" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			progs, err := fetchH1Programs(bbpOnly, includeScope)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching H1 programs: %v\n", err)
				return
			}
			mu.Lock()
			allPrograms = append(allPrograms, progs...)
			mu.Unlock()
		}()
	}

	if platform == "all" || platform == "bc" || platform == "bugcrowd" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			progs, err := fetchBCPrograms(bbpOnly, includeScope)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching BC programs: %v\n", err)
				return
			}
			mu.Lock()
			allPrograms = append(allPrograms, progs...)
			mu.Unlock()
		}()
	}

	if platform == "all" || platform == "it" || platform == "intigriti" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			progs, err := fetchITPrograms(bbpOnly, includeScope)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching Intigriti programs: %v\n", err)
				return
			}
			mu.Lock()
			allPrograms = append(allPrograms, progs...)
			mu.Unlock()
		}()
	}

	if platform == "all" || platform == "ywh" || platform == "yeswehack" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			progs, err := fetchYWHPrograms(bbpOnly, includeScope)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching YesWeHack programs: %v\n", err)
				return
			}
			mu.Lock()
			allPrograms = append(allPrograms, progs...)
			mu.Unlock()
		}()
	}

	wg.Wait()

	sortPrograms(allPrograms, sortBy)

	if allPrograms == nil {
		allPrograms = []ProgramSummary{}
	}

	c.JSON(http.StatusOK, gin.H{
		"programs":       allPrograms,
		"total":          len(allPrograms),
		"has_h1_token":   accounts.Count("h1") > 0,
		"has_bc_token":   accounts.Count("bc") > 0,
		"has_it_token":   accounts.Count("it") > 0,
		"h1_accounts":    accounts.Count("h1"),
		"bc_accounts":    accounts.Count("bc"),
		"it_accounts":    accounts.Count("it"),
		"scope_included": includeScope,
		"warm":           false,
	})
}

// serveProgramsPayload filters the cached payload by platform, sorts it, and
// writes the JSON response. Scope is always included in the cache, so the UI
// can render the full table without per-program follow-up calls.
func serveProgramsPayload(c *gin.Context, payload programsCachePayload, platform, sortBy string, stale bool) {
	programs := make([]ProgramSummary, 0, len(payload.Programs))
	for _, p := range payload.Programs {
		switch platform {
		case "all", "":
			programs = append(programs, p)
		case "h1", "hackerone":
			if p.Platform == "h1" {
				programs = append(programs, p)
			}
		case "bc", "bugcrowd":
			if p.Platform == "bc" {
				programs = append(programs, p)
			}
		case "it", "intigriti":
			if p.Platform == "it" {
				programs = append(programs, p)
			}
		case "ywh", "yeswehack":
			if p.Platform == "ywh" {
				programs = append(programs, p)
			}
		case "ha", "hackadvisor", "external":
			if p.Platform == "ha" {
				programs = append(programs, p)
			}
		}
	}

	sortPrograms(programs, sortBy)

	c.JSON(http.StatusOK, gin.H{
		"programs":       programs,
		"total":          len(programs),
		"has_h1_token":   payload.HasH1Token,
		"has_bc_token":   payload.HasBCToken,
		"has_it_token":   payload.HasITToken,
		"has_ywh_token":  payload.HasYWHToken,
		"has_ha_token":   payload.HasHAToken,
		"scope_included": true,
		"warm":           true,
		"stale":          stale,
		"generated_at":   payload.GeneratedAt.Format(time.RFC3339),
	})
}

// sortPrograms sorts in place by the given key.
func sortPrograms(programs []ProgramSummary, sortBy string) {
	switch sortBy {
	case "name":
		sort.Slice(programs, func(i, j int) bool {
			return strings.ToLower(programs[i].Name) < strings.ToLower(programs[j].Name)
		})
	case "reports":
		sort.Slice(programs, func(i, j int) bool {
			return programs[i].Stats.ReportsForUser > programs[j].Stats.ReportsForUser
		})
	case "bounty":
		sort.Slice(programs, func(i, j int) bool {
			return programs[i].Stats.BountyEarnedForUser > programs[j].Stats.BountyEarnedForUser
		})
	}
}

func apiProgramScopeSummaries(c *gin.Context) {
	var req programScopeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if len(req.Programs) > 80 {
		req.Programs = req.Programs[:80]
	}

	summaries := make(map[string]ProgramSummary, len(req.Programs))
	var mu sync.Mutex
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup

	// Build one auth per account so a program only one account can see still resolves.
	var h1Auths []string
	for _, a := range accounts.For("h1") {
		if a.Username != "" && a.Token != "" {
			h1Auths = append(h1Auths, base64.StdEncoding.EncodeToString([]byte(a.Username+":"+a.Token)))
		}
	}
	var bcTokens []string
	for _, a := range accounts.For("bc") {
		if a.Token != "" {
			bcTokens = append(bcTokens, a.Token)
		}
	}

	for _, item := range req.Programs {
		item.Platform = strings.ToLower(strings.TrimSpace(item.Platform))
		item.Handle = strings.TrimSpace(item.Handle)
		if item.Platform == "" || item.Handle == "" {
			continue
		}

		cacheKey := programScopeCacheKey(item.Platform, item.Handle)
		if !req.Force {
			if summary, ok := getCachedProgramScope(cacheKey); ok {
				mu.Lock()
				summaries[cacheKey] = summary
				mu.Unlock()
				continue
			}
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(item programScopeRequestItem, cacheKey string) {
			defer wg.Done()
			defer func() { <-sem }()

			var summary ProgramSummary
			fetched := false
			switch item.Platform {
			case "h1", "hackerone":
				// Try each H1 account until one can see the program's scope.
				for _, auth := range h1Auths {
					summary, fetched = fetchH1ScopeSummary(item.Handle, auth)
					if fetched {
						break
					}
				}
			case "bc", "bugcrowd":
				// fetchBCScopeSummary doesn't return ok — all 8 failure paths
				// return a zero-valued summary. Treat any empty result as a
				// failed fetch so we don't overwrite persisted good data.
				for _, tok := range bcTokens {
					summary = fetchBCScopeSummary(item.Handle, item.URL, tok)
					fetched = summary.ScopeTargets > 0 || summary.LatestTarget != ""
					if fetched {
						break
					}
				}
			case "ha", "hackadvisor":
				if hasHackAdvisorToken() {
					summary, fetched = fetchHAScopeSummary(item.Handle)
				}
			}

			summary.Platform = item.Platform
			summary.Handle = item.Handle
			// Only cache a successful fetch — caching a rate-limited/empty result would
			// hide the program's real scope until the TTL expires.
			if fetched {
				setCachedProgramScope(cacheKey, summary)
				// Persist last-known-good in the DB — so a search-driven refresh
				// for a program that the warmer keeps rate-limiting still wins.
				_ = db.UpsertProgramScope(db.PersistedProgramScope{
					Platform: summary.Platform, Handle: summary.Handle,
					ScopeTargets: summary.ScopeTargets, LatestTarget: summary.LatestTarget,
					LatestTargetUpdatedAt: summary.LatestTargetUpdatedAt, LatestTargetBrief: summary.LatestTargetBrief,
				})
				// User-initiated force-fetch (Programs page search) → also feed the
				// scope-update watch so a genuinely-newer-than-watermark program
				// alerts Discord immediately, instead of waiting for the next
				// warmer refresh that might re-rate-limit it.
				if req.Force {
					ProgramWatchCheckProgram(summary)
				}
			}
			mu.Lock()
			summaries[cacheKey] = summary
			mu.Unlock()
		}(item, cacheKey)
	}

	wg.Wait()
	c.JSON(http.StatusOK, gin.H{"summaries": summaries})
}

// ─────────────────────────────────────────────────────────────────────────────
// HackerOne program fetching
// ─────────────────────────────────────────────────────────────────────────────

func fetchH1Programs(bbpOnly, includeScope bool) ([]ProgramSummary, error) {
	accts := accounts.For("h1")
	if len(accts) == 0 {
		// No credentials anywhere — fall back to the public GraphQL listing.
		return fetchH1WithGraphQL(bbpOnly)
	}

	var merged []ProgramSummary
	idx := map[string]int{}
	var firstErr error
	for _, a := range accts {
		progs, err := fetchH1WithREST(bbpOnly, includeScope, a.Username, a.Token)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			fmt.Fprintf(os.Stderr, "H1 account %q fetch error: %v\n", a.Label, err)
			continue
		}
		merged = mergeProgramsByHandle(merged, idx, progs, a.Label)
	}
	// Only surface an error if every account failed (no data at all).
	if len(merged) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return merged, nil
}

func fetchH1WithREST(bbpOnly, includeScope bool, username, token string) ([]ProgramSummary, error) {
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + token))
	client := &http.Client{Timeout: 30 * time.Second}

	var allPrograms []ProgramSummary
	currentURL := "https://api.hackerone.com/v1/hackers/programs?page%5Bsize%5D=100"

	for currentURL != "" {
		req, err := http.NewRequest("GET", currentURL, nil)
		if err != nil {
			return allPrograms, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Basic "+auth)

		resp, err := client.Do(req)
		if err != nil {
			return allPrograms, err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return allPrograms, fmt.Errorf("H1 API returned %d: %s", resp.StatusCode, string(body[:min(500, len(body))]))
		}

		bodyStr := string(body)
		dataArr := gjson.Get(bodyStr, "data")
		for _, item := range dataArr.Array() {
			attrs := item.Get("attributes")
			if bbpOnly && !attrs.Get("offers_bounties").Bool() {
				continue
			}
			handle := attrs.Get("handle").Str
			prog := ProgramSummary{
				ID:              strconv.Itoa(int(item.Get("id").Int())),
				Platform:        "h1",
				Handle:          handle,
				Name:            attrs.Get("name").Str,
				URL:             "https://hackerone.com/" + handle,
				State:           attrs.Get("state").Str,
				SubmissionState: attrs.Get("submission_state").Str,
				OffersBounties:  attrs.Get("offers_bounties").Bool(),
				Currency:        strings.ToUpper(attrs.Get("currency").Str),
				FastPayments:    attrs.Get("fast_payments").Bool(),
				SafeHarbor:      attrs.Get("gold_standard_safe_harbor").Bool(),
				Bookmarked:      attrs.Get("bookmarked").Bool(),
				UpdatedAt:       time.Now().UTC().Format(time.RFC3339),
				Stats: ProgramStats{
					ReportsForUser:      int(attrs.Get("number_of_reports_for_user").Int()),
					ValidReportsForUser: int(attrs.Get("number_of_valid_reports_for_user").Int()),
					BountyEarnedForUser: attrs.Get("bounty_earned_for_user").Float(),
				},
			}
			allPrograms = append(allPrograms, prog)
		}
		currentURL = gjson.Get(bodyStr, "links.next").Str
	}

	if includeScope {
		enrichH1ScopeCounts(allPrograms, auth)
	}
	return allPrograms, nil
}

func fetchH1WithGraphQL(bbpOnly bool) ([]ProgramSummary, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	var allPrograms []ProgramSummary
	var cursor string

	for {
		afterClause := ""
		if cursor != "" {
			afterClause = fmt.Sprintf(`, after: "%s"`, cursor)
		}

		query := fmt.Sprintf(`query { teams(first: 100%s) { edges { cursor node { id handle name offers_bounties state submission_state currency } } pageInfo { hasNextPage endCursor } } }`, afterClause)

		reqBody := bytes.NewBufferString(fmt.Sprintf(`{"query": %q}`, query))
		req, err := http.NewRequest("POST", "https://hackerone.com/graphql", reqBody)
		if err != nil {
			return allPrograms, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return allPrograms, err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return allPrograms, fmt.Errorf("H1 GraphQL returned %d", resp.StatusCode)
		}

		bodyStr := string(body)
		edges := gjson.Get(bodyStr, "data.teams.edges")
		if !edges.Exists() {
			break
		}

		for _, edge := range edges.Array() {
			node := edge.Get("node")
			if bbpOnly && !node.Get("offers_bounties").Bool() {
				continue
			}

			handle := node.Get("handle").Str
			prog := ProgramSummary{
				ID:              node.Get("id").Str,
				Platform:        "h1",
				Handle:          handle,
				Name:            node.Get("name").Str,
				URL:             "https://hackerone.com/" + handle,
				State:           node.Get("state").Str,
				SubmissionState: node.Get("submission_state").Str,
				OffersBounties:  node.Get("offers_bounties").Bool(),
				Currency:        strings.ToUpper(node.Get("currency").Str),
				UpdatedAt:       time.Now().UTC().Format(time.RFC3339),
			}
			allPrograms = append(allPrograms, prog)
		}

		pageInfo := gjson.Get(bodyStr, "data.teams.pageInfo")
		if !pageInfo.Get("hasNextPage").Bool() {
			break
		}
		cursor = pageInfo.Get("endCursor").Str
		if cursor == "" {
			break
		}
	}

	return allPrograms, nil
}

func enrichH1ScopeCounts(programs []ProgramSummary, auth string) {
	sem := make(chan struct{}, 10) // max 10 concurrent
	var wg sync.WaitGroup

	for i := range programs {
		wg.Add(1)
		sem <- struct{}{}
		go func(p *ProgramSummary) {
			defer wg.Done()
			defer func() { <-sem }()

			summary, ok := fetchH1ScopeSummary(p.Handle, auth)
			if ok {
				p.ScopeTargets = summary.ScopeTargets
				p.LatestTarget = summary.LatestTarget
				p.LatestTargetUpdatedAt = summary.LatestTargetUpdatedAt
				p.LatestTargetBrief = summary.LatestTargetBrief
				// Persist last-known-good — failed/rate-limited fetches don't
				// reach here, so a transient 429 never overwrites real data.
				_ = db.UpsertProgramScope(db.PersistedProgramScope{
					Platform: p.Platform, Handle: p.Handle,
					ScopeTargets: p.ScopeTargets, LatestTarget: p.LatestTarget,
					LatestTargetUpdatedAt: p.LatestTargetUpdatedAt, LatestTargetBrief: p.LatestTargetBrief,
				})
			}
		}(&programs[i])
	}
	wg.Wait()
}

// fetchH1ScopeSummary returns the scope summary and an ok flag. ok is false when the
// request fails or H1 returns a non-200 (e.g. 429 rate-limit / 403) — the caller must
// NOT cache a !ok result, otherwise a transient failure would hide a program's real
// scope (showing "—") for the whole cache TTL.
//
// 429s are retried with exponential backoff (honoring Retry-After when supplied) so
// the warmer doesn't routinely leave hundreds of programs with stale empty scopes.
func fetchH1ScopeSummary(handle, auth string) (ProgramSummary, bool) {
	url := fmt.Sprintf("https://api.hackerone.com/v1/hackers/programs/%s/structured_scopes?page%%5Bsize%%5D=100", handle)
	client := &http.Client{Timeout: 15 * time.Second}

	var body []byte
	var statusCode int
	const maxAttempts = 3
	backoff := 2 * time.Second
	for attempt := 0; attempt < maxAttempts; attempt++ {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return ProgramSummary{}, false
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Basic "+auth)

		resp, err := client.Do(req)
		if err != nil {
			return ProgramSummary{}, false
		}
		body, _ = io.ReadAll(resp.Body)
		statusCode = resp.StatusCode
		// Honor an explicit Retry-After (seconds) if H1 sent one.
		retryAfter := backoff
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, err := strconv.Atoi(strings.TrimSpace(ra)); err == nil && secs > 0 && secs < 30 {
				retryAfter = time.Duration(secs) * time.Second
			}
		}
		resp.Body.Close()

		if statusCode != http.StatusTooManyRequests || attempt == maxAttempts-1 {
			break // 200 (success), 4xx that isn't 429 (auth/permission), or out of retries
		}
		time.Sleep(retryAfter)
		backoff *= 2
	}

	if statusCode != http.StatusOK {
		return ProgramSummary{}, false
	}

	scopes := gjson.Get(string(body), "data")
	summary := ProgramSummary{Platform: "h1", Handle: handle}
	for _, s := range scopes.Array() {
		attrs := s.Get("attributes")
		if attrs.Get("eligible_for_submission").Bool() {
			summary.ScopeTargets++
			target := attrs.Get("asset_identifier").Str
			if target != "" {
				summary.Assets = append(summary.Assets, target)
			}
			updatedAt := firstGJSONString(attrs, "updated_at", "created_at", "last_updated_at")
			if target != "" && (summary.LatestTarget == "" || isNewerProgramTime(updatedAt, summary.LatestTargetUpdatedAt)) {
				summary.LatestTarget = target
				summary.LatestTargetUpdatedAt = updatedAt
				summary.LatestTargetBrief = firstGJSONString(attrs, "instruction", "instructions", "asset_type")
			}
		}
	}
	return summary, true
}

// ─────────────────────────────────────────────────────────────────────────────
// Bugcrowd program fetching
// ─────────────────────────────────────────────────────────────────────────────

func fetchBCPrograms(bbpOnly, includeScope bool) ([]ProgramSummary, error) {
	accts := accounts.For("bc")
	if len(accts) == 0 {
		return nil, nil
	}
	var merged []ProgramSummary
	idx := map[string]int{}
	var firstErr error
	for _, a := range accts {
		progs, err := fetchBCProgramsWithToken(a.Token, bbpOnly, includeScope)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		merged = mergeProgramsByHandle(merged, idx, progs, a.Label)
	}
	if len(merged) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return merged, nil
}

func fetchBCProgramsWithToken(token string, bbpOnly, includeScope bool) ([]ProgramSummary, error) {
	if token == "" {
		// No BC token — return empty list gracefully (public BC API requires auth)
		return nil, nil
	}

	client := &http.Client{Timeout: 30 * time.Second}

	var allPrograms []ProgramSummary

	// Fetch bug bounty engagements first, optionally VDNs too
	categories := []string{"bug_bounty"}
	if !bbpOnly {
		categories = append(categories, "vdp")
	}

	for _, category := range categories {
		pageIndex := 1
		for {
			listURL := fmt.Sprintf("https://bugcrowd.com/engagements.json?category=%s&sort_by=promoted&sort_direction=desc&page=%d",
				url.QueryEscape(category), pageIndex)

			req, err := http.NewRequest("GET", listURL, nil)
			if err != nil {
				break
			}
			req.Header.Set("Cookie", "_crowdcontrol_session_key="+token)
			req.Header.Set("User-Agent", "AutoAR/1.0")
			req.Header.Set("Accept", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				break
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				break
			}

			bodyStr := string(body)
			engagements := gjson.Get(bodyStr, "engagements")
			if len(engagements.Array()) == 0 {
				break
			}

			engagements.ForEach(func(_, eng gjson.Result) bool {
				briefURL := eng.Get("briefUrl").Str
				accessStatus := eng.Get("accessStatus").Str
				name := strings.TrimPrefix(briefURL, "/engagements/")
				// Try to get a display name from the brief document
				displayName := eng.Get("name").Str
				if displayName == "" {
					displayName = name
				}

				prog := ProgramSummary{
					ID:              name,
					Platform:        "bc",
					Handle:          name,
					Name:            displayName,
					URL:             "https://bugcrowd.com" + briefURL,
					State:           accessStatus,
					SubmissionState: accessStatus,
					OffersBounties:  category == "bug_bounty",
					Currency:        "usd",
					UpdatedAt:       time.Now().UTC().Format(time.RFC3339),
				}
				allPrograms = append(allPrograms, prog)
				return true
			})

			pageIndex++
			totalCount := gjson.Get(bodyStr, "paginationMeta.totalCount").Int()
			if int64(len(allPrograms)) >= totalCount {
				break
			}

			// Rate limit — BC is aggressive
			time.Sleep(1500 * time.Millisecond)
		}
	}

	if includeScope {
		enrichBCScopeCounts(allPrograms, token)
	}

	return allPrograms, nil
}

func enrichBCScopeCounts(programs []ProgramSummary, token string) {
	sem := make(chan struct{}, 3) // BC rate limits aggressively
	var wg sync.WaitGroup

	for i := range programs {
		wg.Add(1)
		sem <- struct{}{}
		go func(p *ProgramSummary) {
			defer wg.Done()
			defer func() { <-sem }()
			time.Sleep(500 * time.Millisecond) // extra spacing for BC

			summary := fetchBCScopeSummary(p.Handle, p.URL, token)
			// Only persist (and overwrite the in-memory row) when fetch actually
			// returned scope — empty/transient failures leave prior data intact.
			if summary.ScopeTargets > 0 || summary.LatestTarget != "" {
				p.ScopeTargets = summary.ScopeTargets
				p.LatestTarget = summary.LatestTarget
				p.LatestTargetUpdatedAt = summary.LatestTargetUpdatedAt
				p.LatestTargetBrief = summary.LatestTargetBrief
				_ = db.UpsertProgramScope(db.PersistedProgramScope{
					Platform: p.Platform, Handle: p.Handle,
					ScopeTargets: p.ScopeTargets, LatestTarget: p.LatestTarget,
					LatestTargetUpdatedAt: p.LatestTargetUpdatedAt, LatestTargetBrief: p.LatestTargetBrief,
				})
			}
		}(&programs[i])
	}
	wg.Wait()
}

func fetchBCScopeSummary(handle, programURL, token string) ProgramSummary {
	summary := ProgramSummary{Platform: "bc", Handle: handle}
	briefPath := ""
	if idx := strings.Index(programURL, "/engagements/"); idx >= 0 {
		briefPath = programURL[idx:]
	}
	if briefPath == "" && handle != "" {
		briefPath = "/engagements/" + handle
	}
	if briefPath == "" {
		return summary
	}

	getBriefURL := "https://bugcrowd.com" + briefPath
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", getBriefURL, nil)
	if err != nil {
		return summary
	}
	req.Header.Set("Cookie", "_crowdcontrol_session_key="+token)
	req.Header.Set("User-Agent", "AutoAR/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return summary
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	idxStart := strings.Index(string(body), "data-api-endpoints=")
	if idxStart < 0 {
		return summary
	}
	idxStart += len("data-api-endpoints=")
	if idxStart >= len(body) {
		return summary
	}
	quote := string(body)[idxStart]
	idxEnd := strings.Index(string(body)[idxStart+1:], string(quote))
	if idxEnd < 0 {
		return summary
	}
	raw := string(body)[idxStart+1 : idxStart+1+idxEnd]
	parsed := gjson.Get(raw, "engagementBriefApi.getBriefVersionDocument").Str
	if parsed == "" {
		return summary
	}

	scopeURL := "https://bugcrowd.com" + parsed + ".json"
	scopeReq, _ := http.NewRequest("GET", scopeURL, nil)
	scopeReq.Header.Set("Cookie", "_crowdcontrol_session_key="+token)
	scopeReq.Header.Set("User-Agent", "AutoAR/1.0")
	scopeResp, scopeErr := client.Do(scopeReq)
	if scopeErr != nil {
		return summary
	}
	scopeBody, _ := io.ReadAll(scopeResp.Body)
	scopeResp.Body.Close()

	gjson.Get(string(scopeBody), "data.scope").ForEach(func(_, scope gjson.Result) bool {
		if scope.Get("inScope").Bool() {
			scope.Get("targets").ForEach(func(_, t gjson.Result) bool {
				summary.ScopeTargets++
				target := firstGJSONString(t, "uri", "name", "target")
				if target != "" {
					summary.Assets = append(summary.Assets, target)
				}
				updatedAt := firstGJSONString(t, "updatedAt", "updated_at", "lastUpdatedAt", "createdAt", "created_at")
				if target != "" && (summary.LatestTarget == "" || isNewerProgramTime(updatedAt, summary.LatestTargetUpdatedAt)) {
					summary.LatestTarget = target
					summary.LatestTargetUpdatedAt = updatedAt
					summary.LatestTargetBrief = firstGJSONString(t, "description", "details", "category", "type")
				}
				return true
			})
		}
		return true
	})
	return summary
}

// ─────────────────────────────────────────────────────────────────────────────
// Intigriti program fetching
//
// Implemented directly against the Intigriti researcher API (instead of bbscope)
// because bbscope calls log.Fatal on a bad token / HTTP error, which would
// os.Exit the whole server when the background warmer runs. This client returns
// errors instead.
// ─────────────────────────────────────────────────────────────────────────────

const intigritiAPIBase = "https://api.intigriti.com/external/researcher/v1"

// intigritiToken returns the configured Intigriti token. INTIGRITI_TOKEN is the
// canonical name; INTIGRITI_API_KEY is accepted as an alias.
func intigritiToken() string {
	if t := strings.TrimSpace(os.Getenv("INTIGRITI_TOKEN")); t != "" {
		return t
	}
	return strings.TrimSpace(os.Getenv("INTIGRITI_API_KEY"))
}

func hasIntigritiToken() bool { return intigritiToken() != "" }

func fetchITPrograms(bbpOnly, includeScope bool) ([]ProgramSummary, error) {
	accts := accounts.For("it")
	if len(accts) == 0 {
		return nil, nil
	}
	var merged []ProgramSummary
	idx := map[string]int{}
	var firstErr error
	for _, a := range accts {
		progs, err := fetchITProgramsWithToken(a.Token, bbpOnly, includeScope)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		merged = mergeProgramsByHandle(merged, idx, progs, a.Label)
	}
	if len(merged) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return merged, nil
}

func fetchITProgramsWithToken(token string, bbpOnly, includeScope bool) ([]ProgramSummary, error) {
	if token == "" {
		// No token — return empty gracefully (mirrors Bugcrowd behavior).
		return nil, nil
	}

	client := &http.Client{Timeout: 30 * time.Second}
	var allPrograms []ProgramSummary
	offset, total := 0, 0

	for {
		listURL := fmt.Sprintf("%s/programs?statusId=3&limit=500&offset=%d", intigritiAPIBase, offset)
		req, err := http.NewRequest("GET", listURL, nil)
		if err != nil {
			return allPrograms, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return allPrograms, err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			return allPrograms, fmt.Errorf("Intigriti API: invalid token (401)")
		}
		if resp.StatusCode != http.StatusOK {
			return allPrograms, fmt.Errorf("Intigriti API returned %d: %s", resp.StatusCode, string(body[:min(300, len(body))]))
		}

		bodyStr := string(body)
		if offset == 0 {
			total = int(gjson.Get(bodyStr, "maxCount").Int())
		}
		records := gjson.Get(bodyStr, "records").Array()
		if len(records) == 0 {
			break
		}

		for _, rec := range records {
			maxBounty := rec.Get("maxBounty.value").Int()
			if bbpOnly && maxBounty == 0 {
				continue
			}
			id := rec.Get("id").String()
			if id == "" {
				continue
			}
			// webLinks.detail looks like ".../programs/<company>/<handle>?..."; the
			// path after '=' (or the raw value) is the researcher-facing path.
			detail := rec.Get("webLinks.detail").String()
			programPath := detail
			if i := strings.Index(detail, "="); i >= 0 && i+1 < len(detail) {
				programPath = detail[i+1:]
			}
			// Intigriti's webLinks.detail paths look like
			//   ".../programs/<company>/<program-handle>/detail"
			// — the LAST segment is the literal word "detail", not the handle.
			// Strip a trailing "/detail" first, then take the last segment.
			// (Without this every IT program gets handle="detail", which collides
			// into a single program_assets bucket and floods the scope monitor.)
			handlePath := strings.TrimRight(programPath, "/")
			handlePath = strings.TrimSuffix(handlePath, "/detail")
			handle := handlePath
			if i := strings.LastIndex(handlePath, "/"); i >= 0 {
				handle = handlePath[i+1:]
			}
			name := strings.TrimSpace(rec.Get("name").Str)
			if name == "" {
				name = handle
			}
			url := "https://app.intigriti.com/researcher" + programPath
			if programPath == "" {
				url = "https://app.intigriti.com/"
			}
			// confidentialityLevel: 4 = Public, else private-ish.
			state := "public_mode"
			if rec.Get("confidentialityLevel.id").Int() != 4 {
				state = "soft_launched"
			}

			allPrograms = append(allPrograms, ProgramSummary{
				ID:                    id,
				Platform:              "it",
				Handle:                handle,
				Name:                  name,
				URL:                   url,
				State:                 state,
				SubmissionState:       "open",
				OffersBounties:        maxBounty > 0,
				Currency:              "EUR",
				LatestTargetUpdatedAt: firstGJSONString(rec, "lastUpdatedAt", "updatedAt", "lastActivityAt", "lastSolved"),
				UpdatedAt:             time.Now().UTC().Format(time.RFC3339),
			})
		}

		offset += len(records)
		if total == 0 || offset >= total {
			break
		}
	}

	if includeScope {
		enrichITScopeCounts(allPrograms, token)
	}
	return allPrograms, nil
}

func enrichITScopeCounts(programs []ProgramSummary, token string) {
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 20 * time.Second}

	for i := range programs {
		wg.Add(1)
		sem <- struct{}{}
		go func(p *ProgramSummary) {
			defer wg.Done()
			defer func() { <-sem }()

			summary := fetchITScopeSummary(client, token, p.ID)
			// Only persist on a real scope payload — IT often rate-limits and the
			// fetcher swallows that as an empty summary; leaving the in-memory row
			// alone preserves whatever was already there (e.g. from the merged DB).
			if summary.ScopeTargets > 0 || summary.LatestTarget != "" {
				p.ScopeTargets = summary.ScopeTargets
				if p.LatestTarget == "" {
					p.LatestTarget = summary.LatestTarget
					p.LatestTargetBrief = summary.LatestTargetBrief
				}
				// Overwrite LatestTargetUpdatedAt with the asset-level timestamp from
				// fetchITScopeSummary (may be empty if IT didn't expose it). DROP the
				// program-level lastUpdatedAt that fetchITPrograms set — otherwise the
				// scope-update watch fires on every program edit (bounty bump, etc.)
				// not just on real scope changes.
				p.LatestTargetUpdatedAt = summary.LatestTargetUpdatedAt
				_ = db.UpsertProgramScope(db.PersistedProgramScope{
					Platform: p.Platform, Handle: p.Handle,
					ScopeTargets: p.ScopeTargets, LatestTarget: p.LatestTarget,
					LatestTargetUpdatedAt: p.LatestTargetUpdatedAt, LatestTargetBrief: p.LatestTargetBrief,
				})
			}
		}(&programs[i])
	}
	wg.Wait()
}

// fetchITScopeSummary fetches one program's scope by ID. programID is stored in
// ProgramSummary.ID by fetchITPrograms.
func fetchITScopeSummary(client *http.Client, token, programID string) ProgramSummary {
	summary := ProgramSummary{Platform: "it"}
	if programID == "" {
		return summary
	}

	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest("GET", intigritiAPIBase+"/programs/"+programID, nil)
		if err != nil {
			return summary
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return summary
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return summary
		}
		bodyStr := string(body)
		// Intigriti rate-limits with a "Request blocked" body — back off once.
		if strings.Contains(bodyStr, "Request blocked") && attempt == 0 {
			time.Sleep(2 * time.Second)
			continue
		}

		gjson.Get(bodyStr, "domains.content").ForEach(func(_, v gjson.Result) bool {
			if v.Get("tier.id").Int() == 5 { // tier 5 = out of scope
				return true
			}
			summary.ScopeTargets++
			target := strings.TrimSpace(v.Get("endpoint").Str)
			if target != "" {
				summary.Assets = append(summary.Assets, target)
			}
			// Per-asset timestamp (try common IT field names). Use the LATEST one
			// across all assets so the watch fires only when scope genuinely changes
			// — NOT on unrelated program edits (bounty bump, description change, …)
			// which would otherwise look like scope updates if we used the program
			// list's program-level lastUpdatedAt.
			updatedAt := firstGJSONString(v, "updatedAt", "lastUpdatedAt", "modifiedAt", "addedAt", "createdAt")
			if target != "" && (summary.LatestTarget == "" || isNewerProgramTime(updatedAt, summary.LatestTargetUpdatedAt)) {
				summary.LatestTarget = target
				summary.LatestTargetBrief = firstGJSONString(v, "description", "type.value")
				summary.LatestTargetUpdatedAt = updatedAt
			}
			return true
		})
		return summary
	}
	return summary
}

func firstGJSONString(result gjson.Result, paths ...string) string {
	for _, path := range paths {
		value := strings.TrimSpace(result.Get(path).Str)
		if value != "" {
			return value
		}
	}
	return ""
}

func programScopeCacheKey(platform, handle string) string {
	return strings.ToLower(strings.TrimSpace(platform)) + ":" + strings.ToLower(strings.TrimSpace(handle))
}

func getCachedProgramScope(cacheKey string) (ProgramSummary, bool) {
	programScopeCacheMu.Lock()
	defer programScopeCacheMu.Unlock()

	cached, ok := programScopeCache[cacheKey]
	if !ok {
		return ProgramSummary{}, false
	}
	if time.Now().After(cached.ExpiresAt) {
		delete(programScopeCache, cacheKey)
		return ProgramSummary{}, false
	}
	return cached.Summary, true
}

func setCachedProgramScope(cacheKey string, summary ProgramSummary) {
	programScopeCacheMu.Lock()
	defer programScopeCacheMu.Unlock()

	programScopeCache[cacheKey] = cachedProgramScope{
		Summary:   summary,
		ExpiresAt: time.Now().Add(programScopeCacheTTL),
	}
}

func isNewerProgramTime(candidate, current string) bool {
	if current == "" {
		return true
	}
	candidateTime, candidateOK := parseProgramTime(candidate)
	currentTime, currentOK := parseProgramTime(current)
	if !candidateOK {
		return false
	}
	if !currentOK {
		return true
	}
	return candidateTime.After(currentTime)
}

func parseProgramTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}
