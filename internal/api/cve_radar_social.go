package api

// Free social/blog intel sources for the CVE radar's PoC gate.
//
// The CVE-2026-21589 race was lost to signal latency: watchTowr published full
// PoCs on Oct 6 and hunters moved within hours, while our only PoC sources
// (GitHub search, blinded by a dead token; the PDCP template index, 25h stale)
// caught up on Oct 7. These feeds buy the same day-one signal for free:
//
//   - watchTowr blog RSS  — every post ships working PoCs; a CVE id in a new
//     post is PoC-confirmed outright.
//   - Hacker News (Algolia API, no key) — CVE stories, gated to titles/links
//     that scream exploit (PoC/exploit/watchTowr/0day/...).
//   - GitHub PoC firehose (poc_firehose.go) — every new repo naming a CVE.
//   - Sploitus (sploitus.com) — exploit aggregator indexing Metasploit,
//     Exploit-DB, Packet Storm, 0day.today, GitHub and more; a date-sorted
//     search for "CVE" surfaces the newest indexed exploits each cycle.
//   - Full Disclosure (seclists.org RSS) — the public disclosure mailing list;
//     fresh advisories (often with PoCs) land here hours-to-days early. Vendor
//     patch bulletins (Apple SA) are skipped so they don't count as PoCs.
//
// r/netsec was dropped: Reddit 403s datacenter IPs, so it failed every cycle.
//
// All of them feed the same map the Exploit-DB commit feed fills: CVE id ->
// labeled link. A hit confirms fresh AND pending radar candidates without
// spending GitHub search budget. Watermarks follow the EDB pattern: advance
// to the newest item actually processed; failures keep the old watermark.

import (
	"encoding/json"
	"encoding/xml"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
)

const (
	cveRadarWatchTowrFeedURL = "https://labs.watchtowr.com/feed/"
	cveRadarHNBaseURL        = "https://hn.algolia.com/api/v1/search_by_date"
	cveRadarSploitusURL      = "https://sploitus.com/search"
	cveRadarFullDiscFeedURL  = "https://seclists.org/rss/fulldisclosure.rss"

	cveRadarWTWatermarkKey       = "cve_radar_watchtowr_wm"
	cveRadarHNWatermarkKey       = "cve_radar_hn_wm"
	cveRadarSploitusWatermarkKey = "cve_radar_sploitus_wm"
	cveRadarFDWatermarkKey       = "cve_radar_fulldisclosure_wm"
)

// socialPoCKeywordRE gates HN/netsec mentions: a bare CVE number in a story
// title is usually patch-Tuesday coverage, not a weaponized bug. Only treat a
// mention as a PoC signal when the title or link says exploit.
var socialPoCKeywordRE = regexp.MustCompile(`(?i)\bpoc\b|proof.of.concept|exploit|watchtowr|0day|zero.day|weaponi[sz]|in.the.wild|\brce\b`)

// socialPoCGate reports whether a story title/link carries exploit signal.
func socialPoCGate(text string) bool {
	return socialPoCKeywordRE.MatchString(text)
}

// cveRadarExternalPoCFeeds merges every free external PoC source into one
// CVE-id -> labeled-link map ("watchTowr blog: <https://...>"), including the
// hits persisted from earlier cycles (cveRadarFeedHitsTTL). Feed watermarks
// advance as soon as an item is read, so a PoC post that lands BEFORE the CVE
// is tracked (NVD lag, score added later) used to be consumed and forgotten —
// now it still confirms the CVE whenever it becomes a candidate.
func cveRadarExternalPoCFeeds() map[string]string {
	fresh := map[string]string{}
	feeds := []struct {
		label string
		fn    func() map[string]string
	}{
		{"Exploit-DB commit", cveRadarExploitDBFeed},
		{"watchTowr blog", cveRadarWatchTowrFeed},
		{"Hacker News", cveRadarHNFeed},
		{"GitHub PoC repo", cveRadarGitHubFirehose},
		{"Sploitus", cveRadarSploitusFeed},
		{"Full Disclosure", cveRadarFullDisclosureFeed},
	}
	for _, f := range feeds {
		for cve, link := range f.fn() {
			if _, seen := fresh[cve]; !seen {
				fresh[cve] = f.label + ": " + cveRadarSafeLink(link)
			}
		}
	}
	return cveRadarMergeFeedHits(fresh)
}

// cveRadarFeedHit is one persisted feed signal.
type cveRadarFeedHit struct {
	Proof  string `json:"proof"`
	SeenAt int64  `json:"seen_at"` // unix seconds
}

// cveRadarMergeFeedHits folds this cycle's hits into the persisted set
// (first sighting wins), prunes entries past the TTL, saves, and returns the
// merged CVE -> proof map.
func cveRadarMergeFeedHits(fresh map[string]string) map[string]string {
	stored := map[string]cveRadarFeedHit{}
	if v, _ := db.GetSetting(cveRadarFeedHitsKey); v != "" {
		_ = json.Unmarshal([]byte(v), &stored)
	}
	merged, changed := mergeFeedHits(stored, fresh, time.Now())
	if changed {
		if b, err := json.Marshal(stored); err == nil {
			_ = db.SetSetting(cveRadarFeedHitsKey, string(b))
		}
	}
	return merged
}

// mergeFeedHits is the pure core of cveRadarMergeFeedHits: mutates stored
// (add new, prune expired) and reports whether it changed.
func mergeFeedHits(stored map[string]cveRadarFeedHit, fresh map[string]string, now time.Time) (map[string]string, bool) {
	changed := false
	for cve, proof := range fresh {
		if _, ok := stored[cve]; !ok {
			stored[cve] = cveRadarFeedHit{Proof: proof, SeenAt: now.Unix()}
			changed = true
		}
	}
	out := make(map[string]string, len(stored))
	for cve, h := range stored {
		if now.Sub(time.Unix(h.SeenAt, 0)) > cveRadarFeedHitsTTL {
			delete(stored, cve)
			changed = true
			continue
		}
		out[cve] = h.Proof
	}
	return out, changed
}

// feedWatermark resolves a feed watermark with the same silent one-hour
// baseline the EDB feed uses on first run.
func feedWatermark(key string) time.Time {
	wm := cveRadarParseWatermarkSetting(key)
	if wm.IsZero() {
		return time.Now().UTC().Add(-time.Hour)
	}
	return wm
}

// parseRSSTime handles the pubDate variants seen in the wild.
func parseRSSTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC1123Z, time.RFC1123, time.RFC3339, "Mon, 2 Jan 2006 15:04:05 -0700", "Mon, 2 Jan 2006 15:04:05 MST"} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t, nil
		}
	}
	return time.Time{}, strconv.ErrSyntax
}

var rssHTMLTagRE = regexp.MustCompile(`<[^>]+>`)

// parseWatchTowrRSS extracts CVE-id -> post-link from the blog's RSS body for
// items published after wm; returns the map and the newest processed pubDate.
func parseWatchTowrRSS(body []byte, wm time.Time) (map[string]string, time.Time) {
	out := map[string]string{}
	maxTs := wm
	var rss struct {
		Channel struct {
			Items []struct {
				Title       string `xml:"title"`
				Link        string `xml:"link"`
				PubDate     string `xml:"pubDate"`
				Description string `xml:"description"`
			} `xml:"item"`
		} `xml:"channel"`
	}
	if err := xml.Unmarshal(body, &rss); err != nil {
		return out, wm
	}
	for _, it := range rss.Channel.Items {
		ts, err := parseRSSTime(it.PubDate)
		if err != nil || !ts.After(wm) {
			continue
		}
		if ts.After(maxTs) {
			maxTs = ts
		}
		// watchTowr posts always ship working PoCs — no keyword gate needed.
		text := it.Title + " " + it.Link + " " + rssHTMLTagRE.ReplaceAllString(it.Description, " ")
		for _, cve := range cveRE.FindAllString(text, -1) {
			if out[cve] == "" {
				out[cve] = it.Link
			}
		}
	}
	return out, maxTs
}

func cveRadarWatchTowrFeed() map[string]string {
	body, err := cveRadarHTTPWithHeaders(cveRadarWatchTowrFeedURL, nil)
	if err != nil {
		return map[string]string{}
	}
	wm := feedWatermark(cveRadarWTWatermarkKey)
	out, maxTs := parseWatchTowrRSS(body, wm)
	_ = db.SetSetting(cveRadarWTWatermarkKey, strconv.FormatInt(maxTs.Unix(), 10))
	return out
}

// parseHNHits extracts CVE-id -> HN-item-link from an Algolia search_by_date
// response, keyword-gated; returns the map and the newest hit timestamp.
func parseHNHits(body []byte, wm time.Time) (map[string]string, time.Time) {
	out := map[string]string{}
	maxTs := wm
	var res struct {
		Hits []struct {
			ObjectID   string `json:"objectID"`
			Title      string `json:"title"`
			URL        string `json:"url"`
			CreatedAtI int64  `json:"created_at_i"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return out, wm
	}
	for _, h := range res.Hits {
		if h.CreatedAtI > maxTs.Unix() {
			maxTs = time.Unix(h.CreatedAtI, 0).UTC()
		}
		if h.ObjectID == "" {
			continue
		}
		text := h.Title + " " + h.URL
		if !socialPoCGate(text) {
			continue
		}
		for _, cve := range cveRE.FindAllString(text, -1) {
			if out[cve] == "" {
				out[cve] = "https://news.ycombinator.com/item?id=" + h.ObjectID
			}
		}
	}
	return out, maxTs
}

func cveRadarHNFeed() map[string]string {
	wm := feedWatermark(cveRadarHNWatermarkKey)
	q := url.Values{
		"tags":           {"story"},
		"query":          {"CVE"},
		"numericFilters": {"created_at_i>" + strconv.FormatInt(wm.Unix(), 10)},
	}
	body, err := cveRadarHTTPWithHeaders(cveRadarHNBaseURL+"?"+q.Encode(), nil)
	if err != nil {
		return map[string]string{}
	}
	out, maxTs := parseHNHits(body, wm)
	_ = db.SetSetting(cveRadarHNWatermarkKey, strconv.FormatInt(maxTs.Unix(), 10))
	return out
}

// parseSploitusHits extracts CVE-id -> Sploitus permalink from a date-sorted
// /search response, keeping items published on/after wm; returns the map and
// the newest published date seen. Sploitus stamps are date-only, so the
// watermark is day-granular: same-day items re-emit across cycles and are
// deduped downstream by the feed-hit store (first sighting wins). Rows without
// a CVE id in their title/source blurb (e.g. "Vulners Software Audit") map
// nothing and are skipped for free.
func parseSploitusHits(body []byte, wm time.Time) (map[string]string, time.Time) {
	out := map[string]string{}
	maxTs := wm
	var res struct {
		Exploits []struct {
			ID        string `json:"id"`
			Title     string `json:"title"`
			Href      string `json:"href"`
			Published string `json:"published"`
			Source    string `json:"source"`
		} `json:"exploits"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return out, wm
	}
	for _, e := range res.Exploits {
		if ts, err := time.Parse("2006-01-02", strings.TrimSpace(e.Published)); err == nil {
			if ts.After(maxTs) {
				maxTs = ts
			}
			if ts.Before(wm) {
				continue
			}
		}
		if strings.TrimSpace(e.ID) == "" {
			continue
		}
		link := "https://sploitus.com/exploit?id=" + e.ID
		text := e.Title + " " + e.Source + " " + e.Href
		for _, cve := range cveRE.FindAllString(text, -1) {
			if out[cve] == "" {
				out[cve] = link
			}
		}
	}
	return out, maxTs
}

// cveRadarSploitusFeed polls Sploitus — an aggregator indexing exploits from
// Metasploit, Exploit-DB, Packet Storm, 0day.today, GitHub and more — for the
// newest exploits that name a CVE. One date-sorted POST per cycle; a hit
// confirms a public PoC for fresh and pending radar candidates alike.
func cveRadarSploitusFeed() map[string]string {
	wm := feedWatermark(cveRadarSploitusWatermarkKey)
	reqBody, err := json.Marshal(map[string]interface{}{
		"type":   "exploits",
		"sort":   "date",
		"query":  "CVE",
		"title":  false,
		"offset": 0,
	})
	if err != nil {
		return map[string]string{}
	}
	body, err := cveRadarHTTPPostJSON(cveRadarSploitusURL, reqBody)
	if err != nil {
		return map[string]string{}
	}
	out, maxTs := parseSploitusHits(body, wm)
	_ = db.SetSetting(cveRadarSploitusWatermarkKey, strconv.FormatInt(maxTs.Unix(), 10))
	return out
}

// fdVendorBulletinRE marks vendor patch-note posts (Apple security
// announcements) that enumerate CVEs without shipping a PoC — the one Full
// Disclosure noise class that must not count as PoC confirmation.
var fdVendorBulletinRE = regexp.MustCompile(`(?i)^\s*APPLE-SA-`)

// parseFullDisclosureRSS extracts CVE-id -> post-link from the seclists Full
// Disclosure RSS for items published after wm, skipping vendor patch bulletins;
// returns the map and the newest processed pubDate. The watermark advances past
// skipped items too, so a bulletin is never reprocessed.
func parseFullDisclosureRSS(body []byte, wm time.Time) (map[string]string, time.Time) {
	out := map[string]string{}
	maxTs := wm
	var rss struct {
		Channel struct {
			Items []struct {
				Title       string `xml:"title"`
				Link        string `xml:"link"`
				PubDate     string `xml:"pubDate"`
				Description string `xml:"description"`
			} `xml:"item"`
		} `xml:"channel"`
	}
	if err := xml.Unmarshal(body, &rss); err != nil {
		return out, wm
	}
	for _, it := range rss.Channel.Items {
		ts, err := parseRSSTime(it.PubDate)
		if err != nil || !ts.After(wm) {
			continue
		}
		if ts.After(maxTs) {
			maxTs = ts
		}
		if fdVendorBulletinRE.MatchString(strings.TrimSpace(it.Title)) {
			continue // vendor patch note, not a PoC
		}
		text := it.Title + " " + rssHTMLTagRE.ReplaceAllString(it.Description, " ")
		for _, cve := range cveRE.FindAllString(text, -1) {
			if out[cve] == "" {
				out[cve] = it.Link
			}
		}
	}
	return out, maxTs
}

// cveRadarFullDisclosureFeed polls the seclists Full Disclosure RSS — the
// public disclosure list where fresh advisories (frequently with PoCs) surface
// hours-to-days before they reach other channels. One fetch per cycle,
// watermarked by pubDate.
func cveRadarFullDisclosureFeed() map[string]string {
	body, err := cveRadarHTTPWithHeaders(cveRadarFullDiscFeedURL, nil)
	if err != nil {
		return map[string]string{}
	}
	wm := feedWatermark(cveRadarFDWatermarkKey)
	out, maxTs := parseFullDisclosureRSS(body, wm)
	_ = db.SetSetting(cveRadarFDWatermarkKey, strconv.FormatInt(maxTs.Unix(), 10))
	return out
}
