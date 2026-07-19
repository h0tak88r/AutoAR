// Package bbcatalog syncs a searchable catalog of bug-bounty programs from the
// operator's authenticated platform accounts and the public bug-bounties.as93.net
// aggregator. Only paying programs are kept — VDPs (recognition/swag-only) are
// dropped so a lookup never surfaces a non-paying program.
package bbcatalog

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	as93URL = "https://bug-bounties.as93.net/api/programs.json"
	as93TTL = 24 * time.Hour
)

// As93Program is one entry from the as93 aggregator (company + policy URL; it
// carries no scope/domain data, so it feeds keyword search only).
type As93Program struct {
	Company    string   `json:"company"`
	URL        string   `json:"url"`
	Slug       string   `json:"slug"`
	Rewards    []string `json:"rewards"`
	SafeHarbor string   `json:"safe_harbor"`
}

type as93Response struct {
	Meta struct {
		Total     int    `json:"total"`
		Generated string `json:"generated"`
	} `json:"meta"`
	Programs []As93Program `json:"programs"`
}

var (
	as93Mu        sync.Mutex
	as93Cache     []As93Program
	as93FetchedAt time.Time
	as93Fetching  bool
)

// hasBounty reports whether a program pays a cash bounty (as opposed to a
// recognition/swag-only VDP). The as93 taxonomy tags paying programs "*bounty".
func hasBounty(rewards []string) bool {
	for _, r := range rewards {
		if strings.Contains(strings.ToLower(r), "bounty") {
			return true
		}
	}
	return false
}

// As93Programs returns the bounty-only aggregator programs. It serves the
// in-memory cache and refreshes in the background when older than 24h; the first
// call (cold cache) fetches synchronously.
func As93Programs() ([]As93Program, error) {
	as93Mu.Lock()
	cached := as93Cache
	age := time.Since(as93FetchedAt)
	fetching := as93Fetching
	as93Mu.Unlock()

	if len(cached) > 0 {
		if age > as93TTL && !fetching {
			go func() { _, _ = refreshAs93() }() // background refresh; ignore error, keep serving cache
		}
		return cached, nil
	}
	return refreshAs93()
}

// refreshAs93 fetches, filters to bounty-only, and replaces the cache.
func refreshAs93() ([]As93Program, error) {
	as93Mu.Lock()
	if as93Fetching {
		c := as93Cache
		as93Mu.Unlock()
		return c, nil
	}
	as93Fetching = true
	as93Mu.Unlock()
	defer func() { as93Mu.Lock(); as93Fetching = false; as93Mu.Unlock() }()

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodGet, as93URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "AutoAR-catalog")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("as93 fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("as93 fetch: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	var parsed as93Response
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("as93 parse: %w", err)
	}

	bounty := make([]As93Program, 0, len(parsed.Programs))
	for _, p := range parsed.Programs {
		if hasBounty(p.Rewards) {
			bounty = append(bounty, p)
		}
	}

	as93Mu.Lock()
	as93Cache = bounty
	as93FetchedAt = time.Now()
	as93Mu.Unlock()
	return bounty, nil
}
