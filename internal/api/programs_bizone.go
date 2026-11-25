package api

// BI.ZONE bug-bounty source. There is no public API; this uses the same
// session-cookie recipe the report submissions use (see docs/SESSION-HANDOFF.md):
// the browser `sessionid` cookie against bugbounty.bi.zone's internal JSON API.
//
// Tasks (GET /api/bug-bounty/tasks/) are the programs; each task description
// carries its scope as prose/HTML, so roots are extracted from the text the
// same way a hunter reads the page. Read-only: listing + parsing, no writes.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	bbscope "github.com/sw33tLie/bbscope/pkg/scope"
)

const (
	bizoneBase    = "https://bugbounty.bi.zone"
	bizonePageLen = 100
	bizoneMaxPage = 10
)

// bizoneDomainRe matches hostnames ending in common public TLDs, with an
// optional :port. Deliberately excludes file names (no .png/.jpg TLDs here).
var bizoneDomainRe = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:ru|su|by|kz|ua|com|net|org|io|me|dev|ai|info|biz|app|cloud|site|online|tech|company|team|space)(?::[0-9]{1,5})?\b`)

// bizoneSkip hosts that are the platform itself (media/avatars leak into
// descriptions as URLs) — never part of any program's scope.
var bizoneSkip = map[string]bool{
	"bi.zone": true, "bugbounty.bi.zone": true, "hackadvisor.io": true,
}

var bizoneTagRe = regexp.MustCompile(`<[^>]+>`)

// fetchBizonePrograms lists every visible task and extracts scope domains
// from each description. One page of tasks per request, capped, polite.
func fetchBizonePrograms(ctx context.Context, sessionCookie string) ([]bbscope.ProgramData, error) {
	if strings.TrimSpace(sessionCookie) == "" {
		return nil, fmt.Errorf("BI.ZONE session cookie required (stored account or token field)")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	var out []bbscope.ProgramData
	for page := 0; page < bizoneMaxPage; page++ {
		url := fmt.Sprintf("%s/api/bug-bounty/tasks/?limit=%d&offset=%d", bizoneBase, bizonePageLen, page*bizonePageLen)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Cookie", "sessionid="+sessionCookie)
		req.Header.Set("X-Auth-Version", "v2")
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; AutoAR-scope)")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			resp.Body.Close()
			return nil, fmt.Errorf("BI.ZONE session rejected (%d) — paste a fresh sessionid cookie", resp.StatusCode)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("BI.ZONE tasks HTTP %d", resp.StatusCode)
		}
		var body struct {
			Results []struct {
				ID          int    `json:"id"`
				TextTask    string `json:"textTask"`
				Description string `json:"description"`
				InScope     bool   `json:"inScope"`
				InArchive   bool   `json:"inArchive"`
				Company     struct {
					Slug string `json:"slug"`
					Name string `json:"name"`
				} `json:"company"`
			} `json:"results"`
		}
		err = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("BI.ZONE tasks decode: %w", err)
		}
		for _, t := range body.Results {
			if t.InArchive || !t.InScope {
				continue
			}
			text := bizoneTagRe.ReplaceAllString(t.Description, " ")
			seen := map[string]bool{}
			var in []bbscope.ScopeElement
			for _, m := range bizoneDomainRe.FindAllString(text, -1) {
				host := strings.ToLower(strings.TrimSuffix(m, "."))
				if bizoneSkip[host] || seen[host] {
					continue
				}
				seen[host] = true
				// Untyped (aggregator-style): the scope layer then admits
				// bare apexes as enumeration roots and keeps specific hosts
				// as raw targets only — never widening subdomains to roots.
				in = append(in, bbscope.ScopeElement{Target: host})
			}
			if len(in) == 0 {
				continue
			}
			name := strings.TrimSpace(t.Company.Name)
			if t.TextTask != "" {
				name += " — " + strings.TrimSpace(t.TextTask)
			}
			out = append(out, bbscope.ProgramData{
				Url:        fmt.Sprintf("%s/tasks/%d/", bizoneBase, t.ID),
				InScope:    in,
				OutOfScope: nil,
			})
			// ProgramData has no name field; the URL anchors it and the
			// description keeps the readable title next to each element.
			for i := range in {
				out[len(out)-1].InScope[i].Description = name
			}
		}
		if len(body.Results) < bizonePageLen {
			break // last page
		}
		time.Sleep(500 * time.Millisecond) // stay polite between pages
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no BI.ZONE tasks returned scope domains (session expired or empty account?)")
	}
	return out, nil
}
