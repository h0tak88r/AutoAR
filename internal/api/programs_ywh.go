package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/accounts"
)

// fetchYWHPrograms fetches YesWeHack programs (with in-scope assets) across every
// configured YWH account and merges them, so YesWeHack shows up on the Programs
// page and feeds the root pipeline.
//
// This is a NATIVE HTTP client rather than bbscope's YesWeHack client on purpose:
// bbscope calls log.Fatal on any HTTP error, which os.Exit(1)s the whole API
// server — unacceptable for a background warmer that runs every few minutes.
func fetchYWHPrograms(bbpOnly, includeScope bool) ([]ProgramSummary, error) {
	accts := accounts.For("ywh")
	if len(accts) == 0 {
		return nil, nil
	}
	var merged []ProgramSummary
	idx := map[string]int{}
	var firstErr error
	for _, a := range accts {
		if a.Token == "" {
			continue
		}
		progs, err := fetchYWHProgramsWithToken(a.Token, bbpOnly, includeScope)
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

type ywhListItem struct {
	Slug        string `json:"slug"`
	Title       string `json:"title"`
	Bounty      bool   `json:"bounty"`
	Disabled    bool   `json:"disabled"`
	Public      bool   `json:"public"`
	ScopesCount int    `json:"scopes_count"`
	LastUpdate  string `json:"last_update_at"`
}

func fetchYWHProgramsWithToken(token string, bbpOnly, includeScope bool) ([]ProgramSummary, error) {
	if token == "" {
		return nil, nil
	}
	client := &http.Client{Timeout: 30 * time.Second}

	// 1. Collect every matching program from the paginated list.
	var items []ywhListItem
	page, nbPages := 1, 1
	for page <= nbPages {
		req, err := http.NewRequest("GET", fmt.Sprintf("https://api.yeswehack.com/programs?page=%d", page), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("YWH programs list: %w", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("YesWeHack API: invalid or expired token (401)")
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("YesWeHack API returned %d", resp.StatusCode)
		}

		var payload struct {
			Items      []ywhListItem `json:"items"`
			Pagination struct {
				NbPages int `json:"nb_pages"`
			} `json:"pagination"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, fmt.Errorf("YesWeHack parse: %w", err)
		}
		if payload.Pagination.NbPages > 0 {
			nbPages = payload.Pagination.NbPages
		}
		for _, it := range payload.Items {
			if it.Slug == "" || it.Disabled {
				continue
			}
			if bbpOnly && !it.Bounty {
				continue
			}
			items = append(items, it)
		}
		page++
	}

	// 2. Build summaries, fetching per-program scope concurrently (bounded) so the
	//    warmer isn't held up by hundreds of sequential scope requests.
	out := make([]ProgramSummary, len(items))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, it := range items {
		name := it.Title
		if name == "" {
			name = it.Slug
		}
		out[i] = ProgramSummary{
			Platform:              "ywh",
			Handle:                it.Slug,
			Name:                  name,
			URL:                   "https://yeswehack.com/programs/" + it.Slug,
			OffersBounties:        it.Bounty,
			ScopeTargets:          it.ScopesCount,
			LatestTargetUpdatedAt: it.LastUpdate,
		}
		if !includeScope {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, slug string) {
			defer wg.Done()
			defer func() { <-sem }()
			if assets := fetchYWHProgramScope(client, token, slug); len(assets) > 0 {
				out[i].Assets = assets
				out[i].ScopeTargets = len(assets)
				out[i].LatestTarget = assets[0]
			}
		}(i, it.Slug)
	}
	wg.Wait()
	return out, nil
}

// fetchYWHProgramScope returns the raw in-scope targets for one program. Downstream
// root extraction (ScopeElementRoots) filters out mobile/app/source targets, so we
// pass everything through here. Errors are swallowed — a program with no fetched
// scope simply keeps its list-level scopes_count.
func fetchYWHProgramScope(client *http.Client, token, slug string) []string {
	req, err := http.NewRequest("GET", "https://api.yeswehack.com/programs/"+slug, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	var payload struct {
		Scopes []struct {
			Scope     string `json:"scope"`
			ScopeType string `json:"scope_type"`
		} `json:"scopes"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return nil
	}
	var assets []string
	for _, sc := range payload.Scopes {
		if t := strings.TrimSpace(sc.Scope); t != "" {
			assets = append(assets, t)
		}
	}
	return assets
}
