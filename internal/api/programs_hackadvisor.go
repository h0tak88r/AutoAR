package api

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

// ─────────────────────────────────────────────────────────────────────────────
// HackAdvisor program source (https://hackadvisor.io/api-docs)
//
// HackAdvisor aggregates bug-bounty programs across many platforms — including
// ones AutoAR can't reach natively (Immunefi, Standoff365, BI.ZONE, YesWeHack,
// self-hosted). We surface those as "external targets" in the Programs page.
//
// Crucially, the list endpoint returns scope_updated_at per program directly, so
// the passive scope-update watch works for these programs with no extra calls.
//
//   GET /api/v1/programs/?page_size=100&ordering=-scope_updated_at   (paginated)
//   GET /api/v1/programs/{id}/scope/                                 (assets)
//   Auth: Authorization: Bearer <HACKADVISOR_TOKEN>
// ─────────────────────────────────────────────────────────────────────────────

const hackAdvisorBase = "https://hackadvisor.io/api/v1"

func hackAdvisorToken() string {
	return strings.TrimSpace(os.Getenv("HACKADVISOR_TOKEN"))
}

// firstN returns up to n elements of s (nil-safe).
func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func hasHackAdvisorToken() bool {
	return hackAdvisorToken() != ""
}

// nativePlatformTitles are the HackAdvisor platform names AutoAR already fetches
// directly (with the user's own tokens, incl. private invites). By default we
// skip these from HackAdvisor to avoid duplicate rows; set
// HACKADVISOR_INCLUDE_NATIVE=true to include them anyway.
var nativePlatformTitles = map[string]bool{
	"hackerone": true,
	"bugcrowd":  true,
	"intigriti": true,
}

func hackAdvisorIncludeNative() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("HACKADVISOR_INCLUDE_NATIVE")), "true")
}

// fetchHackAdvisorPrograms pulls the full HackAdvisor catalogue (paginated) and
// maps it to ProgramSummary rows tagged Platform="ha". bbpOnly keeps only programs
// that offer a bounty. The list already carries scope_count + scope_updated_at, so
// no per-program enrichment is needed for the catalogue view.
func fetchHackAdvisorPrograms(bbpOnly bool) ([]ProgramSummary, error) {
	token := hackAdvisorToken()
	if token == "" {
		return nil, nil // not configured — no-op
	}
	includeNative := hackAdvisorIncludeNative()

	client := &http.Client{Timeout: 30 * time.Second}
	url := hackAdvisorBase + "/programs/?page_size=100&ordering=-scope_updated_at"

	var all []ProgramSummary
	const maxPages = 30 // safety cap (~3000 programs at 100/page)
	for page := 0; page < maxPages && url != ""; page++ {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return all, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			return all, err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			return all, fmt.Errorf("HackAdvisor API: invalid token (401)")
		}
		if resp.StatusCode != http.StatusOK {
			return all, fmt.Errorf("HackAdvisor API returned %d", resp.StatusCode)
		}

		bodyStr := string(body)
		gjson.Get(bodyStr, "results").ForEach(func(_, r gjson.Result) bool {
			platformTitle := strings.TrimSpace(r.Get("platform.title").Str)
			if !includeNative && nativePlatformTitles[strings.ToLower(platformTitle)] {
				return true // skip natively-fetched platforms to avoid dupes
			}
			maxReward := r.Get("max_reward").Int()
			minReward := r.Get("min_reward").Int()
			offersBounty := maxReward > 0 || minReward > 0
			if bbpOnly && !offersBounty {
				return true
			}
			id := r.Get("id").Int()
			if id == 0 {
				return true
			}
			handle := strconv.FormatInt(id, 10)
			p := ProgramSummary{
				ID:                    "ha-" + handle,
				Platform:              "ha",
				Handle:                handle,
				Name:                  strings.TrimSpace(r.Get("title").Str),
				URL:                   strings.TrimSpace(r.Get("link").Str),
				State:                 "open",
				SubmissionState:       "open",
				OffersBounties:        offersBounty,
				ScopeTargets:          int(r.Get("scope_count").Int()),
				LatestTargetUpdatedAt: strings.TrimSpace(r.Get("scope_updated_at").Str),
				ExternalPlatform:      platformTitle,
			}
			if offersBounty {
				p.Currency = "USD"
			}
			all = append(all, p)
			return true
		})

		url = strings.TrimSpace(gjson.Get(bodyStr, "next").Str)
	}
	return all, nil
}

// fetchHAScopeSummary fetches one HackAdvisor program's in-scope assets.
// handle is the numeric program id (as string). Returns ok=false on failure so
// the caller doesn't cache/persist an empty result.
func fetchHAScopeSummary(handle string) (ProgramSummary, bool) {
	token := hackAdvisorToken()
	if token == "" || strings.TrimSpace(handle) == "" {
		return ProgramSummary{}, false
	}
	url := fmt.Sprintf("%s/programs/%s/scope/", hackAdvisorBase, handle)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ProgramSummary{}, false
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return ProgramSummary{}, false
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ProgramSummary{}, false
	}

	bodyStr := string(body)
	summary := ProgramSummary{Platform: "ha", Handle: handle}
	summary.LatestTargetUpdatedAt = strings.TrimSpace(gjson.Get(bodyStr, "updated_at").Str)
	gjson.Get(bodyStr, "assets").ForEach(func(_, a gjson.Result) bool {
		// Treat an asset as in-scope unless in_scope is EXPLICITLY false. Some
		// platforms (e.g. Immunefi) omit the field entirely on in-scope assets —
		// filtering on in_scope==true would drop all of them and undercount vs the
		// list's scope_count.
		if inScope := a.Get("in_scope"); inScope.Exists() && !inScope.Bool() {
			return true
		}
		target := strings.TrimSpace(a.Get("target").Str)
		if target == "" {
			return true
		}
		summary.ScopeTargets++
		summary.Assets = append(summary.Assets, target)
		if summary.LatestTarget == "" {
			summary.LatestTarget = target
			summary.LatestTargetBrief = strings.TrimSpace(a.Get("description").Str)
		}
		return true
	})
	return summary, summary.ScopeTargets > 0
}
