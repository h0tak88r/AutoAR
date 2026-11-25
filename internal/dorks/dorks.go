// Package dorks is the single source of truth for AutoAR's recon dork corpus.
//
// The same embedded database (dorks.json) powers three surfaces:
//   - the Security Lab "Recon Dorks" page (GET /api/dorks, legacy grouped shape)
//   - the MCP recon_dorks tool, so an AI agent can pull dorks programmatically
//   - any Go caller via Load()/Filter()/Resolve().
//
// A dork's Query holds a NATIVE expression with {T} as the target placeholder
// (e.g. `site:{T} ext:env` for Google, `hostname:"{T}" port:9200` for Shodan).
// The owning platform's url_template wraps it into a clickable URL. For
// backwards compatibility a Query that is already a full http(s) URL is used
// verbatim (older builtin entries baked the URL in).
package dorks

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

//go:embed dorks.json
var dorksJSON []byte

// Platform is a search surface and the URL template that runs a native query.
// The template carries a {Q} placeholder (URL-encoded query) or {Q64}
// (base64-encoded query, for FOFA-style APIs).
type Platform struct {
	Label       string `json:"label"`
	URLTemplate string `json:"url_template"`
}

// Dork is one recon query. Query uses {T} for the target.
type Dork struct {
	Title       string   `json:"title"`
	Icon        string   `json:"icon,omitempty"`
	Platforms   []string `json:"platforms"`
	Query       string   `json:"query"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Source      string   `json:"source,omitempty"`
}

// Category groups dorks and carries the severity its dorks inherit.
type Category struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description,omitempty"`
	Dorks       []Dork `json:"dorks"`
}

// DB is the whole corpus.
type DB struct {
	Version    string              `json:"version"`
	Generated  string              `json:"generated"`
	Platforms  map[string]Platform `json:"platforms"`
	Categories []Category          `json:"categories"`
}

var (
	loaded   *DB
	loadErr  error
	loadOnce sync.Once
)

// Load parses and validates the embedded corpus once.
func Load() (*DB, error) {
	loadOnce.Do(func() {
		var db DB
		if err := json.Unmarshal(dorksJSON, &db); err != nil {
			loadErr = fmt.Errorf("dorks: parse embedded corpus: %w", err)
			return
		}
		if len(db.Categories) == 0 {
			loadErr = fmt.Errorf("dorks: corpus has no categories")
			return
		}
		loaded = &db
	})
	return loaded, loadErr
}

// PrimaryPlatform returns the dork's first platform, defaulting to google.
func (d Dork) PrimaryPlatform() string {
	if len(d.Platforms) > 0 && d.Platforms[0] != "" {
		return d.Platforms[0]
	}
	return "google"
}

var targetStripRE = regexp.MustCompile(`[^a-zA-Z0-9.\-_]`)

// SanitizeTarget mirrors the frontend: drop scheme and path, keep host chars.
func SanitizeTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "example.com"
	}
	raw = regexp.MustCompile(`(?i)^https?://`).ReplaceAllString(raw, "")
	if i := strings.IndexByte(raw, '/'); i >= 0 {
		raw = raw[:i]
	}
	raw = targetStripRE.ReplaceAllString(raw, "")
	if raw == "" {
		return "example.com"
	}
	return raw
}

const encTargetSentinel = "ZZTARGETZZ" // survives url.QueryEscape unchanged

// encodeQuery URL-encodes a native query. When target is empty the {T}
// placeholder is preserved literally (so the browser can substitute it later);
// otherwise {T} has already been replaced and the whole string is encoded.
func encodeQuery(q, target string) string {
	if target != "" {
		return url.QueryEscape(q)
	}
	tmp := strings.ReplaceAll(q, "{T}", encTargetSentinel)
	return strings.ReplaceAll(url.QueryEscape(tmp), encTargetSentinel, "{T}")
}

func isHTTPURL(s string) bool {
	s = strings.ToLower(s)
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// BuildURL turns a dork into a clickable URL for the given platform. target ""
// keeps {T} literal in the URL (the page substitutes client-side); a non-empty
// target is substituted server-side. A Query that is already a full URL is
// returned as-is (after target substitution).
func (db *DB) BuildURL(d Dork, platform, target string) string {
	q := d.Query
	if target != "" {
		q = strings.ReplaceAll(q, "{T}", target)
	}
	if isHTTPURL(q) {
		return q
	}
	tmpl := "https://www.google.com/search?q={Q}"
	if p, ok := db.Platforms[platform]; ok && p.URLTemplate != "" {
		tmpl = p.URLTemplate
	}
	if strings.Contains(tmpl, "{Q64}") {
		b64 := base64.StdEncoding.EncodeToString([]byte(q))
		tmpl = strings.ReplaceAll(tmpl, "{Q64}", url.QueryEscape(b64))
	}
	tmpl = strings.ReplaceAll(tmpl, "{Q}", encodeQuery(q, target))
	return tmpl
}

// FilterOpts narrows a corpus query. Empty fields match everything.
type FilterOpts struct {
	Category string // category id (exact) or title substring
	Platform string // platform key a dork must list
	Severity string // critical|high|medium|low|info
	Query    string // substring over title/query/description/tags
}

func matchDork(d Dork, cat Category, o FilterOpts) bool {
	if o.Severity != "" && !strings.EqualFold(cat.Severity, o.Severity) {
		return false
	}
	if o.Category != "" && !strings.EqualFold(cat.ID, o.Category) &&
		!strings.Contains(strings.ToLower(cat.Title), strings.ToLower(o.Category)) {
		return false
	}
	if o.Platform != "" {
		found := false
		for _, p := range d.Platforms {
			if strings.EqualFold(p, o.Platform) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if o.Query != "" {
		q := strings.ToLower(o.Query)
		hay := strings.ToLower(d.Title + " " + d.Query + " " + d.Description + " " + strings.Join(d.Tags, " "))
		if !strings.Contains(hay, q) {
			return false
		}
	}
	return true
}

// ResolvedDork is a dork flattened with its category/severity and (when a
// target is given) the substituted query plus the clickable URL.
type ResolvedDork struct {
	Title       string   `json:"title"`
	Icon        string   `json:"icon,omitempty"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Platforms   []string `json:"platforms"`
	Query       string   `json:"query"`
	URL         string   `json:"url"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Source      string   `json:"source,omitempty"`
}

// Resolve returns the matching dorks flattened and, when target != "", with
// {T} substituted and a ready-to-open URL on each. This is the shape the MCP
// tool and programmatic callers consume.
func (db *DB) Resolve(o FilterOpts, target string) []ResolvedDork {
	if target != "" {
		target = SanitizeTarget(target)
	}
	out := []ResolvedDork{}
	for _, cat := range db.Categories {
		for _, d := range cat.Dorks {
			if !matchDork(d, cat, o) {
				continue
			}
			q := d.Query
			if target != "" {
				q = strings.ReplaceAll(q, "{T}", target)
			}
			out = append(out, ResolvedDork{
				Title: d.Title, Icon: d.Icon, Category: cat.ID, Severity: cat.Severity,
				Platforms: d.Platforms, Query: q, URL: db.BuildURL(d, d.PrimaryPlatform(), target),
				Description: d.Description, Tags: d.Tags, Source: d.Source,
			})
		}
	}
	return out
}

// legacyItem is the shape the Security Lab page's renderer expects.
type legacyItem struct {
	Title     string   `json:"title"`
	Icon      string   `json:"icon"`
	Platforms []string `json:"platforms"`
	Query     string   `json:"query"`
}

// LegacyGrouped renders the corpus into the {severity: [items]} map the page
// renders. Google queries stay raw (the page wraps them in a search URL and
// substitutes {T} client-side); every other platform's query becomes a full
// URL with {T} kept literal for the same client-side substitution.
func (db *DB) LegacyGrouped() map[string][]legacyItem {
	out := map[string][]legacyItem{}
	for _, cat := range db.Categories {
		for _, d := range cat.Dorks {
			plat := d.PrimaryPlatform()
			query := d.Query
			if !(plat == "google" && !isHTTPURL(query)) {
				query = db.BuildURL(d, plat, "")
			}
			out[cat.Severity] = append(out[cat.Severity], legacyItem{
				Title: d.Title, Icon: d.Icon, Platforms: d.Platforms, Query: query,
			})
		}
	}
	return out
}

// Count returns the total number of dorks in the corpus.
func (db *DB) Count() int {
	n := 0
	for _, c := range db.Categories {
		n += len(c.Dorks)
	}
	return n
}
