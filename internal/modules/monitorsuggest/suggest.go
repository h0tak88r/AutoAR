// Package monitorsuggest discovers release/changelog-style URLs for a domain and optionally ranks them with AI.
package monitorsuggest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/modules/brain"
)

// Candidate is a URL that responded with HTML (probed before AI ranking).
type Candidate struct {
	URL    string `json:"url"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Snippet string `json:"snippet,omitempty"`
}

// Suggestion is a ranked monitor target for the UI.
type Suggestion struct {
	URL      string `json:"url"`
	Title    string `json:"title,omitempty"`
	Score    int    `json:"score"`
	Reason   string `json:"reason"`
	Strategy string `json:"strategy"` // hash | regex
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>([^<]{1,300})</title>`)
var scriptRe = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
var styleRe = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)

// releasePaths are common locations for changelogs, blogs, and product news.
var releasePaths = []string{
	"/changelog",
	"/changelogs",
	"/releases",
	"/release-notes",
	"/releasenotes",
	"/whats-new",
	"/whatsnew",
	"/what-is-new",
	"/product-updates",
	"/product/news",
	"/news",
	"/blog",
	"/blogs",
	"/company/blog",
	"/engineering/blog",
	"/engineering",
	"/resources/blog",
	"/learn/blog",
	"/support/release-notes",
	"/support/updates",
	"/updates",
	"/roadmap",
	"/status",
	"/feeds/news",
	"/docs/changelog",
	"/docs/releases",
}

const maxBodySnip = 400
const fetchTimeout = 12 * time.Second

// NormalizeDomain strips scheme/path and lowercases the host.
func NormalizeDomain(raw string) (string, error) {
	s := strings.TrimSpace(strings.ToLower(raw))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" || strings.Contains(s, " ") {
		return "", fmt.Errorf("invalid domain")
	}
	return s, nil
}

// Discover fetches likely release/changelog pages for the given host (no AI).
func Discover(ctx context.Context, host string) ([]Candidate, error) {
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}

	bases := []string{host}
	if !strings.HasPrefix(host, "www.") {
		bases = append(bases, "www."+host)
	}

	client := &http.Client{
		Timeout: fetchTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	type job struct {
		base string
		path string
	}
	var jobs []job
	seen := map[string]struct{}{}
	for _, base := range bases {
		for _, p := range releasePaths {
			u := "https://" + base + p
			if _, ok := seen[u]; ok {
				continue
			}
			seen[u] = struct{}{}
			jobs = append(jobs, job{base: base, path: p})
		}
	}

	var mu sync.Mutex
	var out []Candidate
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, j := range jobs {
		j := j
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			u := "https://" + j.base + j.path
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "AutoAR-MonitorSuggest/1.0 (+https://github.com/h0tak88r/AutoAR)")
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return
			}
			ct := strings.ToLower(resp.Header.Get("Content-Type"))
			if !strings.Contains(ct, "text/html") && ct != "" {
				return
			}
			b, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
			if err != nil || len(b) == 0 {
				return
			}
			body := string(b)
			title := extractTitle(body)
			snip := snippetFromHTML(body)

			mu.Lock()
			out = append(out, Candidate{
				URL:     u,
				Title:   title,
				Status:  resp.StatusCode,
				Snippet: snip,
			})
			mu.Unlock()
		}()
	}
	wg.Wait()

	// Dedupe by URL (redirects may merge)
	byURL := map[string]Candidate{}
	for _, c := range out {
		byURL[c.URL] = c
	}
	out = out[:0]
	for _, c := range byURL {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out, nil
}

func extractTitle(html string) string {
	m := titleRe.FindStringSubmatch(html)
	if len(m) > 1 {
		return strings.TrimSpace(stripTags(m[1]))
	}
	return ""
}

func stripTags(s string) string {
	s = scriptRe.ReplaceAllString(s, " ")
	s = styleRe.ReplaceAllString(s, " ")
	return strings.TrimSpace(regexp.MustCompile(`<[^>]+>`).ReplaceAllString(s, " "))
}

func snippetFromHTML(html string) string {
	s := stripTags(html)
	s = regexp.MustCompile(`\s+`).ReplaceAllString(s, " ")
	if len(s) > maxBodySnip {
		s = s[:maxBodySnip] + "…"
	}
	return s
}

// RankWithAI asks the LLM to pick and score URLs; falls back to heuristic if no API key or on error.
func RankWithAI(domain string, candidates []Candidate) ([]Suggestion, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	if os.Getenv("OPENROUTER_API_KEY") == "" && os.Getenv("GEMINI_API_KEY") == "" {
		return heuristicRank(domain, candidates), nil
	}

	payload, _ := json.MarshalIndent(candidates, "", "  ")
	system := `You help security teams choose web pages to monitor for product and release changes.
You MUST respond with ONLY a valid JSON array (no markdown fences, no commentary).
Each element must be an object: {"url":"...","score":0-100,"reason":"short text","strategy":"hash" or "regex"}
Rules:
- Prefer changelog, release notes, "what's new", product updates, engineering blogs about releases.
- Deprioritize generic marketing homepages, careers, login, or unrelated sections.
- Use strategy "hash" for full-page change detection unless the page is very large/noisy — then "regex" with a note (still use "hash" if unsure).
- Include at most 8 items, highest score first. Omit score below 25.
- Only include URLs from the provided list.`

	user := fmt.Sprintf("Target domain context: %s\n\nCandidates (JSON):\n%s", domain, string(payload))

	reply, err := brain.ChatWithAI(nil, user, system)
	if err != nil {
		return heuristicRank(domain, candidates), nil
	}

	raw := strings.TrimSpace(reply)
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	raw = strings.TrimSpace(raw)

	var parsed []struct {
		URL      string `json:"url"`
		Score    int    `json:"score"`
		Reason   string `json:"reason"`
		Strategy string `json:"strategy"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return heuristicRank(domain, candidates), nil
	}

	allowed := map[string]struct{}{}
	for _, c := range candidates {
		allowed[c.URL] = struct{}{}
	}

	var sug []Suggestion
	for _, p := range parsed {
		if _, ok := allowed[p.URL]; !ok {
			continue
		}
		if p.Score < 25 {
			continue
		}
		st := strings.ToLower(strings.TrimSpace(p.Strategy))
		if st != "regex" {
			st = "hash"
		}
		title := ""
		for _, c := range candidates {
			if c.URL == p.URL {
				title = c.Title
				break
			}
		}
		sug = append(sug, Suggestion{
			URL:      p.URL,
			Title:    title,
			Score:    p.Score,
			Reason:   p.Reason,
			Strategy: st,
		})
	}
	if len(sug) == 0 {
		return heuristicRank(domain, candidates), nil
	}
	sort.Slice(sug, func(i, j int) bool { return sug[i].Score > sug[j].Score })
	return sug, nil
}

func heuristicRank(domain string, candidates []Candidate) []Suggestion {
	var out []Suggestion
	for _, c := range candidates {
		score := 40
		u := strings.ToLower(c.URL)
		t := strings.ToLower(c.Title)
		s := strings.ToLower(c.Snippet)

		for _, kw := range []string{"changelog", "release", "what's new", "whats new", "product update", "notes", "roadmap"} {
			if strings.Contains(u+t+s, kw) {
				score += 12
			}
		}
		if strings.Contains(u, "/blog") {
			score += 5
		}
		if strings.Contains(u, "/news") {
			score += 5
		}
		if score > 100 {
			score = 100
		}
		out = append(out, Suggestion{
			URL:      c.URL,
			Title:    c.Title,
			Score:    score,
			Reason:   "Heuristic keyword match (AI unavailable or failed)",
			Strategy: "hash",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

// SuggestFromDomain runs discovery + optional AI ranking.
func SuggestFromDomain(ctx context.Context, rawDomain string) ([]Suggestion, []Candidate, error) {
	host, err := NormalizeDomain(rawDomain)
	if err != nil {
		return nil, nil, err
	}
	cands, err := Discover(ctx, host)
	if err != nil {
		return nil, nil, err
	}
	sug, err := RankWithAI(host, cands)
	if err != nil {
		return nil, cands, err
	}
	return sug, cands, nil
}
