// Package huntermonitor talks to HackerOne's public GraphQL API (the same
// endpoint hackerone.com's own profile/hacktivity pages use) to track a
// hunter's public reputation snapshot and resolved-report activity. No
// authentication is required — the endpoint is unauthenticated and, unlike
// some vendor sites, is not behind bot-protection that blocks plain HTTP
// clients.
package huntermonitor

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const graphqlEndpoint = "https://hackerone.com/graphql"

// latest_disclosable_action values worth alerting on. BugResolved is the report
// being fixed; BountyAwarded is the hunter getting paid for one. Both mean the
// hunter just landed something, and a given report surfaces as whichever of the
// two happened most recently — so tracking only BugResolved silently drops every
// report whose latest activity was the payout.
const (
	ActionBugResolved   = "Activities::BugResolved"
	ActionBountyAwarded = "Activities::BountyAwarded"
)

var httpClient = &http.Client{Timeout: 20 * time.Second}

// UserSnapshot is a hunter's public identity plus current reputation stats.
type UserSnapshot struct {
	UserID     string // raw numeric H1 user id, e.g. "2508920"
	Username   string
	Reputation float64
	Signal     float64
	Rank       float64
}

// ResolvedReport is one entry from a hunter's public hacktivity feed.
type ResolvedReport struct {
	ID            string
	ProgramHandle string
	ProgramName   string
	Action        string
	ActivityAt    string
}

// IsResolved reports whether this hacktivity entry represents the hunter
// landing a report — either it was resolved or a bounty was paid for it.
func (r ResolvedReport) IsResolved() bool {
	return r.Action == ActionBugResolved || r.Action == ActionBountyAwarded
}

// ActionLabel renders the action for a Discord alert.
func (r ResolvedReport) ActionLabel() string {
	switch r.Action {
	case ActionBountyAwarded:
		return "bounty awarded"
	case ActionBugResolved:
		return "resolved"
	default:
		return strings.TrimPrefix(r.Action, "Activities::")
	}
}

type graphQLError struct {
	Message string `json:"message"`
}

func doGraphQL(query string, variables map[string]interface{}, out interface{}) error {
	payload, err := json.Marshal(map[string]interface{}{
		"query":     query,
		"variables": variables,
	})
	if err != nil {
		return fmt.Errorf("failed to encode graphql request: %w", err)
	}

	req, err := http.NewRequest("POST", graphqlEndpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; AutoAR-HunterMonitor/1.0)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("hackerone graphql request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read hackerone graphql response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hackerone graphql returned status %d: %s", resp.StatusCode, truncate(string(respBody), 300))
	}

	var envelope struct {
		Data   json.RawMessage `json:"data"`
		Errors []graphQLError  `json:"errors"`
	}
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return fmt.Errorf("failed to parse hackerone graphql response: %w", err)
	}
	if len(envelope.Errors) > 0 {
		msgs := make([]string, len(envelope.Errors))
		for i, e := range envelope.Errors {
			msgs[i] = e.Message
		}
		return fmt.Errorf("hackerone graphql error: %s", strings.Join(msgs, "; "))
	}
	if len(envelope.Data) == 0 {
		return fmt.Errorf("hackerone graphql returned no data")
	}
	return json.Unmarshal(envelope.Data, out)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

const userStatsQuery = `
query($username: String!) {
  user(username: $username) {
    id
    username
    statistics_snapshot(snapshot_type: last_90_days) {
      reputation
      signal
      rank
    }
  }
}`

// FetchUserSnapshot resolves a HackerOne username to its numeric user ID and
// current public reputation/signal/rank snapshot.
func FetchUserSnapshot(username string) (*UserSnapshot, error) {
	var result struct {
		User *struct {
			ID       string `json:"id"`
			Username string `json:"username"`
			Snapshot *struct {
				Reputation float64 `json:"reputation"`
				Signal     float64 `json:"signal"`
				Rank       float64 `json:"rank"`
			} `json:"statistics_snapshot"`
		} `json:"user"`
	}

	if err := doGraphQL(userStatsQuery, map[string]interface{}{"username": username}, &result); err != nil {
		return nil, err
	}
	if result.User == nil {
		return nil, fmt.Errorf("hackerone user %q not found", username)
	}

	numericID, err := decodeRelayNumericID(result.User.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to decode user id for %q: %w", username, err)
	}

	snap := &UserSnapshot{UserID: numericID, Username: result.User.Username}
	if result.User.Snapshot != nil {
		snap.Reputation = result.User.Snapshot.Reputation
		snap.Signal = result.User.Snapshot.Signal
		snap.Rank = result.User.Snapshot.Rank
	}
	return snap, nil
}

// decodeRelayNumericID decodes a base64 GraphQL Relay Global ID such as
// "Z2lkOi8vaGFja2Vyb25lL1VzZXIvMjUwODkyMA==" (-> "gid://hackerone/User/2508920")
// and returns the trailing numeric ID ("2508920"). The hacktivity search API
// rejects the encoded GID form and requires this raw numeric ID.
func decodeRelayNumericID(gid string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(gid)
	if err != nil {
		return "", err
	}
	parts := strings.Split(string(decoded), "/")
	numericID := parts[len(parts)-1]
	if numericID == "" {
		return "", fmt.Errorf("empty numeric id in decoded gid %q", string(decoded))
	}
	return numericID, nil
}

// hackerOneAPIHacktivity is the official REST hacktivity endpoint. Authenticated
// with any hacker API token it returns entries the anonymous view withholds:
// reports on private/confidential programs, with the report title redacted but
// the program handle+name, the action and the timestamp intact. Verified against
// hunter "whocallme" — anonymous stops at 2026-06-23 while the same request with
// Basic auth returns 2026-07-31 BountyAwarded on program "beside_bbp" (Beside),
// matching what the profile page shows a logged-in viewer. This is the only
// source for private-program activity; the public GraphQL hacktivity index has
// none of it.
const hackerOneAPIHacktivity = "https://api.hackerone.com/v1/hackers/hacktivity"

// FetchHacktivityAPI returns the reporter's most recent hacktivity via the
// official API, authenticated as the supplied hacker account. Results come back
// newest-first. size is capped by the API (100).
func FetchHacktivityAPI(apiUser, apiToken, reporterUsername string, size int) ([]ResolvedReport, error) {
	if apiUser == "" || apiToken == "" {
		return nil, fmt.Errorf("hackerone api credentials required")
	}
	if size <= 0 || size > 100 {
		size = 100
	}

	q := url.Values{}
	q.Set("queryString", "reporter:"+reporterUsername)
	q.Set("page[size]", strconv.Itoa(size))

	req, err := http.NewRequest("GET", hackerOneAPIHacktivity+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(apiUser, apiToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "AutoAR-HunterMonitor/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hackerone api request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read hackerone api response: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("hackerone api rejected the credentials (401) — token may be revoked or expired")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hackerone api returned status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var payload struct {
		Data []struct {
			ID         json.Number `json:"id"`
			Attributes struct {
				Action     string `json:"latest_disclosable_action"`
				ActivityAt string `json:"latest_disclosable_activity_at"`
			} `json:"attributes"`
			Relationships struct {
				Program struct {
					Data struct {
						Attributes struct {
							Handle string `json:"handle"`
							Name   string `json:"name"`
						} `json:"attributes"`
					} `json:"data"`
				} `json:"program"`
			} `json:"relationships"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse hackerone api response: %w", err)
	}

	out := make([]ResolvedReport, 0, len(payload.Data))
	for _, d := range payload.Data {
		p := d.Relationships.Program.Data.Attributes
		out = append(out, ResolvedReport{
			ID:            d.ID.String(),
			ProgramHandle: p.Handle,
			ProgramName:   p.Name,
			Action:        d.Attributes.Action,
			ActivityAt:    d.Attributes.ActivityAt,
		})
	}
	return out, nil
}

const hacktivitySearchQuery = `
query($query: QueryInput, $size: Int, $sort: SortInput) {
  search(index: CompleteHacktivityReportIndex, query: $query, size: $size, sort: $sort) {
    total_count
    nodes {
      ... on HacktivityDocument {
        _id
        latest_disclosable_action
        latest_disclosable_activity_at
        team { handle name }
      }
    }
  }
}`

// FetchHacktivity returns up to size entries from the hunter's public
// hacktivity feed (one entry per report, reflecting its most recent
// disclosable public action), given their raw numeric H1 user ID.
//
// Results are sorted newest-first, which matters: the endpoint hard-caps the
// response at 100 rows no matter what size is asked for, and its default order
// is arbitrary (stable, but not chronological). Unsorted, a hunter with more
// than 100 disclosed reports would get an arbitrary 100-row slice — a newly
// resolved report could fall outside it and never be alerted on, and a shift in
// that ordering could pull an old report into view and fire a false alert.
// Sorting by activity date makes the window "the 100 most recent", so new
// resolutions always enter at the top and older ones never re-enter.
func FetchHacktivity(numericUserID string, size int) ([]ResolvedReport, error) {
	variables := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": []interface{}{
					map[string]interface{}{
						"terms": map[string]interface{}{
							"reporter_id": []interface{}{numericUserID},
						},
					},
				},
			},
		},
		"size": size,
		"sort": map[string]interface{}{
			"field":     "latest_disclosable_activity_at",
			"direction": "DESC",
		},
	}

	var result struct {
		Search struct {
			TotalCount int `json:"total_count"`
			Nodes      []struct {
				ID         string `json:"_id"`
				Action     string `json:"latest_disclosable_action"`
				ActivityAt string `json:"latest_disclosable_activity_at"`
				Team       struct {
					Handle string `json:"handle"`
					Name   string `json:"name"`
				} `json:"team"`
			} `json:"nodes"`
		} `json:"search"`
	}

	if err := doGraphQL(hacktivitySearchQuery, variables, &result); err != nil {
		return nil, err
	}

	out := make([]ResolvedReport, 0, len(result.Search.Nodes))
	for _, n := range result.Search.Nodes {
		out = append(out, ResolvedReport{
			ID:            n.ID,
			ProgramHandle: n.Team.Handle,
			ProgramName:   n.Team.Name,
			Action:        n.Action,
			ActivityAt:    n.ActivityAt,
		})
	}
	return out, nil
}
