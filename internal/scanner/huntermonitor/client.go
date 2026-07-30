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
	"strings"
	"time"
)

const graphqlEndpoint = "https://hackerone.com/graphql"

// ActionBugResolved is the latest_disclosable_action value HackerOne uses
// when a report's most recent public state change is resolution.
const ActionBugResolved = "Activities::BugResolved"

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

// IsResolved reports whether this hacktivity entry's most recent public
// action is a bug resolution.
func (r ResolvedReport) IsResolved() bool {
	return r.Action == ActionBugResolved
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

const hacktivitySearchQuery = `
query($query: QueryInput, $size: Int) {
  search(index: CompleteHacktivityReportIndex, query: $query, size: $size) {
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
