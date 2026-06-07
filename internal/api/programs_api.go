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
}

// ProgramStats holds user-specific stats from H1.
type ProgramStats struct {
	ReportsForUser      int     `json:"reports_for_user"`
	ValidReportsForUser int     `json:"valid_reports_for_user"`
	BountyEarnedForUser float64 `json:"bounty_earned_for_user"`
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/scope/programs
// ─────────────────────────────────────────────────────────────────────────────

func apiListPrograms(c *gin.Context) {
	platform := strings.ToLower(c.DefaultQuery("platform", "all"))
	bbpOnly := true
	sortBy := c.DefaultQuery("sort", "name")

	var allPrograms []ProgramSummary
	var mu sync.Mutex
	var wg sync.WaitGroup

	if platform == "all" || platform == "h1" || platform == "hackerone" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			progs, err := fetchH1Programs(bbpOnly)
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
			progs, err := fetchBCPrograms(bbpOnly)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching BC programs: %v\n", err)
				return
			}
			mu.Lock()
			allPrograms = append(allPrograms, progs...)
			mu.Unlock()
		}()
	}

	wg.Wait()

	// Sort
	switch sortBy {
	case "name":
		sort.Slice(allPrograms, func(i, j int) bool {
			return strings.ToLower(allPrograms[i].Name) < strings.ToLower(allPrograms[j].Name)
		})
	case "reports":
		sort.Slice(allPrograms, func(i, j int) bool {
			return allPrograms[i].Stats.ReportsForUser > allPrograms[j].Stats.ReportsForUser
		})
	case "bounty":
		sort.Slice(allPrograms, func(i, j int) bool {
			return allPrograms[i].Stats.BountyEarnedForUser > allPrograms[j].Stats.BountyEarnedForUser
		})
	}

	if allPrograms == nil {
		allPrograms = []ProgramSummary{}
	}

	c.JSON(http.StatusOK, gin.H{
		"programs":     allPrograms,
		"total":        len(allPrograms),
		"has_h1_token": os.Getenv("H1_USERNAME") != "" && os.Getenv("H1_TOKEN") != "",
		"has_bc_token": os.Getenv("BUGCROWD_TOKEN") != "",
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// HackerOne program fetching
// ─────────────────────────────────────────────────────────────────────────────

func fetchH1Programs(bbpOnly bool) ([]ProgramSummary, error) {
	username := os.Getenv("H1_USERNAME")
	token := os.Getenv("H1_TOKEN")

	if username != "" && token != "" {
		return fetchH1WithREST(bbpOnly, username, token)
	}
	return fetchH1WithGraphQL(bbpOnly)
}

func fetchH1WithREST(bbpOnly bool, username, token string) ([]ProgramSummary, error) {
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

	enrichH1ScopeCounts(allPrograms, auth)
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

			url := fmt.Sprintf("https://api.hackerone.com/v1/hackers/programs/%s/structured_scopes?page%%5Bsize%%5D=100", p.Handle)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return
			}
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Authorization", "Basic "+auth)

			client := &http.Client{Timeout: 15 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			scopes := gjson.Get(string(body), "data")
			count := 0
			var latestTarget string
			var latestUpdatedAt string
			var latestBrief string
			for _, s := range scopes.Array() {
				attrs := s.Get("attributes")
				if attrs.Get("eligible_for_submission").Bool() {
					count++
					target := attrs.Get("asset_identifier").Str
					updatedAt := firstGJSONString(attrs, "updated_at", "created_at", "last_updated_at")
					if target != "" && (latestTarget == "" || isNewerProgramTime(updatedAt, latestUpdatedAt)) {
						latestTarget = target
						latestUpdatedAt = updatedAt
						latestBrief = firstGJSONString(attrs, "instruction", "instructions", "asset_type")
					}
				}
			}
			p.ScopeTargets = count
			p.LatestTarget = latestTarget
			p.LatestTargetUpdatedAt = latestUpdatedAt
			p.LatestTargetBrief = latestBrief
		}(&programs[i])
	}
	wg.Wait()
}

// ─────────────────────────────────────────────────────────────────────────────
// Bugcrowd program fetching
// ─────────────────────────────────────────────────────────────────────────────

func fetchBCPrograms(bbpOnly bool) ([]ProgramSummary, error) {
	token := os.Getenv("BUGCROWD_TOKEN")
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

	// Enrich with scope counts
	enrichBCScopeCounts(allPrograms, token)

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

			getBriefURL := fmt.Sprintf("https://bugcrowd.com%s", p.URL[strings.Index(p.URL, "/engagements/"):])
			client := &http.Client{Timeout: 15 * time.Second}
			req, err := http.NewRequest("GET", getBriefURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("Cookie", "_crowdcontrol_session_key="+token)
			req.Header.Set("User-Agent", "AutoAR/1.0")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			// Look for the React component that has the API endpoints
			apiEndpoints := gjson.Get(string(body), `div[data-react-class='ResearcherEngagementBrief']|@this`).Str
			if apiEndpoints == "" {
				// Try to find via regex in the response
				idxStart := strings.Index(string(body), "data-api-endpoints=")
				if idxStart >= 0 {
					idxStart += len("data-api-endpoints=")
					quote := string(body)[idxStart]
					idxEnd := strings.Index(string(body)[idxStart+1:], string(quote))
					if idxEnd >= 0 {
						raw := string(body)[idxStart+1 : idxStart+1+idxEnd]
						parsed := gjson.Get(raw, "engagementBriefApi.getBriefVersionDocument").Str
						if parsed != "" {
							// Fetch the brief version document for scope count
							scopeURL := "https://bugcrowd.com" + parsed + ".json"
							scopeReq, _ := http.NewRequest("GET", scopeURL, nil)
							scopeReq.Header.Set("Cookie", "_crowdcontrol_session_key="+token)
							scopeReq.Header.Set("User-Agent", "AutoAR/1.0")
							scopeResp, scopeErr := client.Do(scopeReq)
							if scopeErr == nil {
								scopeBody, _ := io.ReadAll(scopeResp.Body)
								scopeResp.Body.Close()

								count := 0
								var latestTarget string
								var latestUpdatedAt string
								var latestBrief string
								gjson.Get(string(scopeBody), "data.scope").ForEach(func(_, scope gjson.Result) bool {
									if scope.Get("inScope").Bool() {
										scope.Get("targets").ForEach(func(_, t gjson.Result) bool {
											count++
											target := firstGJSONString(t, "uri", "name", "target")
											updatedAt := firstGJSONString(t, "updatedAt", "updated_at", "lastUpdatedAt", "createdAt", "created_at")
											if target != "" && (latestTarget == "" || isNewerProgramTime(updatedAt, latestUpdatedAt)) {
												latestTarget = target
												latestUpdatedAt = updatedAt
												latestBrief = firstGJSONString(t, "description", "details", "category", "type")
											}
											return true
										})
									}
									return true
								})
								p.ScopeTargets = count
								p.LatestTarget = latestTarget
								p.LatestTargetUpdatedAt = latestUpdatedAt
								p.LatestTargetBrief = latestBrief
							}
						}
					}
				}
			}
		}(&programs[i])
	}
	wg.Wait()
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
