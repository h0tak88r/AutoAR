package api

// PoC firehose: one GitHub search per radar cycle for EVERY repo created in
// the last 25h that names a CVE, instead of spending the per-CVE search budget
// CVE by CVE (89 pending CVEs at 10 searches per cycle meant each was
// re-checked only every ~2h). It sees a new PoC for any CVE — fresh, pending,
// long dropped from the pending queue, or published weeks ago — within one
// cycle of the repo appearing.
//
// The fake-PoC rule still holds: a repo counts only when it is from a trusted
// owner, has a star, or is older than 24h (cveRadarPoCRepoVerdict). Brand-new
// zero-star repos are kept as candidates and re-evaluated every cycle (the
// 25h window returns them with fresh star counts), so a real PoC is confirmed
// the cycle it earns its first star instead of at the next per-CVE search.
//
// Late PoCs: a feed hit for a CVE that is neither fresh nor pending this cycle
// (an older CVE, or one the 48h pending queue dropped) is looked up (NVD by
// id, GitHub advisories as fallback) and confirmed when it passes the alert
// bar. A CVE published more than pocLateMaxAge ago only counts when this is
// its FIRST public PoC repo — "the 50th scanner for Log4Shell" is not news.

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
)

const (
	pocFirehoseWindow   = 25 * time.Hour
	pocFirehoseMaxPages = 3
	pocFirehoseCandKey  = "poc_firehose_candidates"
	pocFirehoseStatsKey = "poc_firehose_stats"
	pocFirehoseCandTTL  = 48 * time.Hour
	pocFirehoseCandCap  = 600
	// Candidates that left the search window unconfirmed are re-checked
	// directly (repo still up, not a fork) — at most this many per cycle.
	pocFirehoseAgeOutMax = 10

	pocLateCheckedKey  = "cve_radar_late_checked"
	pocLateMaxPerCycle = 4
	pocLateMaxAge      = 60 * 24 * time.Hour
	pocLateRetryMiss   = 6 * time.Hour  // no record anywhere yet
	pocLateRetryBelow  = 24 * time.Hour // below the bar, old, or not a first PoC
	pocLateCheckedTTL  = 14 * 24 * time.Hour
)

// pocFirehoseSearchURL is a var so tests can point the firehose at a stub.
var pocFirehoseSearchURL = "https://api.github.com/search/repositories"

// cveAnyCaseRE finds CVE ids in repo names, which are usually lowercase.
var cveAnyCaseRE = regexp.MustCompile(`(?i)\bcve[-_](\d{4})[-_](\d{4,7})\b`)

// cveIDsIn extracts normalized CVE ids (CVE-YYYY-NNNN) from free text.
func cveIDsIn(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range cveAnyCaseRE.FindAllStringSubmatch(text, -1) {
		id := "CVE-" + m[1] + "-" + m[2]
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// pocFirehoseCand is a new repo that names a CVE but is not yet plausible.
type pocFirehoseCand struct {
	Repo      string   `json:"repo"`
	URL       string   `json:"url"`
	CVEs      []string `json:"cves"`
	CreatedAt int64    `json:"created_at"`
	Stars     int      `json:"stars"`
	FirstSeen int64    `json:"first_seen"`
}

// pocFirehoseStats is the last cycle's summary for the pipeline page.
type pocFirehoseStats struct {
	At         int64  `json:"at"`
	Repos      int    `json:"repos"`
	Confirmed  int    `json:"confirmed"`
	Candidates int    `json:"candidates"`
	Error      string `json:"error,omitempty"`
}

// firehoseEvaluate is the pure core: it turns one window of search results
// into confirmed CVE -> repo-URL hits and updates the candidate set. Returned
// ageOuts are candidates that left the window unconfirmed and are old enough
// for the age rule — the caller verifies they still exist before counting
// them.
func firehoseEvaluate(items []cveRadarGHRepo, cands map[string]pocFirehoseCand, now time.Time) (hits map[string]string, ageOuts []pocFirehoseCand) {
	hits = map[string]string{}
	trustedHit := map[string]bool{}
	inWindow := map[string]bool{}
	for _, it := range items {
		if it.Fork {
			continue
		}
		cves := cveIDsIn(it.FullName + " " + it.Description)
		if len(cves) == 0 {
			continue
		}
		key := strings.ToLower(it.FullName)
		inWindow[key] = true
		link := it.HTMLURL
		if !strings.HasPrefix(link, "https://github.com/") {
			link = "https://github.com/" + it.FullName
		}
		ok, trusted := cveRadarPoCRepoVerdict(it, now)
		if !ok {
			c := cands[key]
			if c.FirstSeen == 0 {
				c.FirstSeen = now.Unix()
			}
			c.Repo, c.URL, c.CVEs, c.Stars = it.FullName, link, cves, it.Stars
			if !it.CreatedAt.IsZero() {
				c.CreatedAt = it.CreatedAt.Unix()
			}
			cands[key] = c
			continue
		}
		delete(cands, key)
		for _, id := range cves {
			if hits[id] == "" || (trusted && !trustedHit[id]) {
				hits[id] = link
				trustedHit[id] = trusted
			}
		}
	}
	for key, c := range cands {
		created := time.Unix(c.CreatedAt, 0)
		switch {
		case c.CreatedAt == 0 || now.Sub(time.Unix(c.FirstSeen, 0)) > pocFirehoseCandTTL:
			delete(cands, key)
		case !inWindow[key] && now.Sub(created) > cveRadarPoCMinRepoAge:
			ageOuts = append(ageOuts, c)
		}
	}
	sort.Slice(ageOuts, func(i, j int) bool { return ageOuts[i].CreatedAt < ageOuts[j].CreatedAt })
	return hits, ageOuts
}

// cveRadarGitHubFirehose is the radar feed: CVE -> repo URL for plausible PoC
// repos created in the last 25h (plus aged-out candidates that still exist).
func cveRadarGitHubFirehose() map[string]string {
	now := time.Now().UTC()
	stats := pocFirehoseStats{At: now.Unix()}
	defer func() {
		if b, err := json.Marshal(stats); err == nil {
			_ = db.SetSetting(pocFirehoseStatsKey, string(b))
		}
	}()
	since := now.Add(-pocFirehoseWindow).Format("2006-01-02T15:04:05Z")
	var items []cveRadarGHRepo
	for page := 1; page <= pocFirehoseMaxPages; page++ {
		q := url.Values{
			"q":        {"CVE in:name,description created:>=" + since},
			"sort":     {"updated"},
			"order":    {"desc"},
			"per_page": {"100"},
			"page":     {strconv.Itoa(page)},
		}
		body, err := cveRadarGitHubGet(pocFirehoseSearchURL + "?" + q.Encode())
		if err != nil {
			if page == 1 {
				stats.Error = err.Error()
				logger.GetLogger().Infof("[CVE-RADAR] PoC firehose search failed: %v", err)
				return map[string]string{}
			}
			break
		}
		var res struct {
			TotalCount int              `json:"total_count"`
			Items      []cveRadarGHRepo `json:"items"`
		}
		if err := json.Unmarshal(body, &res); err != nil {
			if page == 1 {
				stats.Error = "decode: " + err.Error()
				return map[string]string{}
			}
			break
		}
		items = append(items, res.Items...)
		if len(res.Items) < 100 || len(items) >= res.TotalCount {
			break
		}
	}
	cands := map[string]pocFirehoseCand{}
	if v, _ := db.GetSetting(pocFirehoseCandKey); v != "" {
		_ = json.Unmarshal([]byte(v), &cands)
	}
	hits, ageOuts := firehoseEvaluate(items, cands, now)
	for i, c := range ageOuts {
		key := strings.ToLower(c.Repo)
		if i >= pocFirehoseAgeOutMax {
			break
		}
		delete(cands, key)
		if !pocRepoStillUp(c.Repo) {
			continue
		}
		for _, id := range c.CVEs {
			if hits[id] == "" {
				hits[id] = c.URL
			}
		}
	}
	if len(cands) > pocFirehoseCandCap {
		keys := make([]string, 0, len(cands))
		for k := range cands {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return cands[keys[i]].FirstSeen < cands[keys[j]].FirstSeen })
		for _, k := range keys[:len(cands)-pocFirehoseCandCap] {
			delete(cands, k)
		}
	}
	if b, err := json.Marshal(cands); err == nil {
		_ = db.SetSetting(pocFirehoseCandKey, string(b))
	}
	stats.Repos, stats.Confirmed, stats.Candidates = len(items), len(hits), len(cands)
	return hits
}

// pocRepoStillUp checks an aged-out candidate: GitHub takes malware repos
// down, and a fork is never a PoC.
func pocRepoStillUp(fullName string) bool {
	body, err := cveRadarGitHubGet("https://api.github.com/repos/" + fullName)
	if err != nil {
		return false
	}
	var r struct {
		Fork     bool `json:"fork"`
		Disabled bool `json:"disabled"`
		Archived bool `json:"archived"`
	}
	return json.Unmarshal(body, &r) == nil && !r.Fork && !r.Disabled
}

var feedProofURLRE = regexp.MustCompile("https?://[^\\s<>\"'`]+")

// splitFeedProof splits a labeled feed proof ("watchTowr blog: <https://…>")
// into its source label and raw URL, so the PoC log stores a clickable link.
func splitFeedProof(proof string) (source, link string) {
	source, link = "feed", proof
	if i := strings.Index(proof, ": "); i > 0 {
		source, link = strings.TrimSpace(proof[:i]), strings.TrimSpace(proof[i+2:])
	}
	link = strings.TrimSuffix(strings.TrimPrefix(link, "<"), ">")
	if !strings.HasPrefix(link, "http://") && !strings.HasPrefix(link, "https://") {
		if m := feedProofURLRE.FindString(proof); m != "" {
			link = m
		}
	}
	return source, link
}

// ── late PoCs ────────────────────────────────────────────────────────────────

// pocLateVerdict decides a late candidate from its record: age within
// pocLateMaxAge passes; an older CVE needs firstPoC (no repo predates the
// window).
func pocLateVerdict(published time.Time, now time.Time, firstPoC func() (bool, error)) (bool, string) {
	if !published.IsZero() && now.Sub(published) <= pocLateMaxAge {
		return true, ""
	}
	first, err := firstPoC()
	if err != nil {
		return false, "first-PoC check failed: " + err.Error()
	}
	if !first {
		return false, "older CVE that already had public PoCs"
	}
	return true, ""
}

// cveRadarLatePoCs confirms feed hits for CVEs the cycle did not otherwise
// handle. processed holds every id the cycle already looked at.
func cveRadarLatePoCs(edb map[string]string, processed map[string]bool, kwRE *regexp.Regexp, now time.Time) []cveRadarItem {
	checked := map[string]int64{}
	if v, _ := db.GetSetting(pocLateCheckedKey); v != "" {
		_ = json.Unmarshal([]byte(v), &checked)
	}
	for id, at := range checked {
		if now.Sub(time.Unix(at, 0)) > pocLateCheckedTTL {
			delete(checked, id)
		}
	}
	ids := make([]string, 0, len(edb))
	for id := range edb {
		if !processed[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	var out []cveRadarItem
	looked := 0
	for _, id := range ids {
		if at, ok := checked[id]; ok && now.Unix() < at {
			continue // re-check not due yet (value = next allowed check)
		}
		if rec, err := db.GetCVE(id); err == nil && rec != nil && rec.PoCPublished {
			checked[id] = now.Add(pocLateCheckedTTL).Unix()
			continue
		}
		if looked >= pocLateMaxPerCycle {
			break
		}
		if looked > 0 {
			nvdSleep(nvdRequestGap) // NVD allows 5 requests / 30s unauthenticated
		}
		looked++
		item, published, found := cveRadarLookupCVE(id)
		if !found {
			checked[id] = now.Add(pocLateRetryMiss).Unix()
			continue
		}
		if !cveRadarPasses(item.Desc, item.CVSS, kwRE) {
			checked[id] = now.Add(pocLateRetryBelow).Unix()
			continue
		}
		ok, why := pocLateVerdict(published, now, func() (bool, error) { return pocIsFirstPublicRepo(id, now) })
		if !ok {
			checked[id] = now.Add(pocLateRetryBelow).Unix()
			if strings.Contains(why, "already had") {
				checked[id] = now.Add(pocLateCheckedTTL).Unix() // that will not change
			}
			logger.GetLogger().Infof("[CVE-RADAR] late PoC for %s not alerted: %s", id, why)
			continue
		}
		item.Proof = edb[id]
		out = append(out, item)
		checked[id] = now.Add(pocLateCheckedTTL).Unix()
	}
	if len(checked) > 3000 {
		for id := range checked {
			delete(checked, id)
			if len(checked) <= 3000 {
				break
			}
		}
	}
	if b, err := json.Marshal(checked); err == nil {
		_ = db.SetSetting(pocLateCheckedKey, string(b))
	}
	return out
}

// cveRadarLookupCVE fetches one CVE's record: the tracked row first, then NVD
// by id, then GitHub advisories.
func cveRadarLookupCVE(id string) (cveRadarItem, time.Time, bool) {
	if rec, err := db.GetCVE(id); err == nil && rec != nil && rec.CVSSScore > 0 {
		pub, _ := time.Parse(time.RFC3339, rec.PublishedAt)
		if pub.IsZero() {
			pub, _ = nvdTime(rec.PublishedAt)
		}
		return cveRadarItem{ID: id, Desc: rec.Description, CVSS: rec.CVSSScore, Vector: rec.CVSSVector,
			CWE: rec.CWE, Published: rec.PublishedAt, Link: "https://nvd.nist.gov/vuln/detail/" + id}, pub, true
	}
	if e, err := nvdLookupCVE(id); err == nil && e != nil {
		pub, _ := nvdTime(e.Published)
		return cveRadarItem{ID: id, Desc: truncateStr(e.cveRadarDesc(), 600), CVSS: e.cveRadarScore(),
			Vector: e.cveRadarVector(), CWE: e.cveRadarCWE(), Published: e.Published,
			Link: "https://nvd.nist.gov/vuln/detail/" + id}, pub, true
	}
	body, err := cveRadarGitHubGet(cveRadarGHSAURL + "?cve_id=" + url.QueryEscape(id))
	if err != nil {
		return cveRadarItem{}, time.Time{}, false
	}
	var advs []cveRadarGHSA
	if json.Unmarshal(body, &advs) != nil || len(advs) == 0 {
		return cveRadarItem{}, time.Time{}, false
	}
	a := advs[0]
	score := a.CVSS.Score
	if score == 0 {
		score = map[string]float64{"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0}[strings.ToLower(a.Severity)]
	}
	desc := a.Summary
	if desc == "" {
		desc = a.Description
	}
	pub, _ := time.Parse(time.RFC3339, a.PublishedAt)
	return cveRadarItem{ID: id, Desc: truncateStr(desc, 600), CVSS: score, Link: a.HTMLURL, Published: a.PublishedAt}, pub, true
}

// nvdLookupCVE fetches one record by id from NVD (one request).
func nvdLookupCVE(id string) (*nvdCVEEntry, error) {
	body, err := cveRadarHTTP(nvdBaseURL + "?cveId=" + url.QueryEscape(id))
	if err != nil {
		return nil, err
	}
	var res struct {
		Vulnerabilities []struct {
			CVE nvdCVEEntry `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("nvd decode: %w", err)
	}
	if len(res.Vulnerabilities) == 0 {
		return nil, nil
	}
	return &res.Vulnerabilities[0].CVE, nil
}

// pocIsFirstPublicRepo reports whether no repo naming the CVE predates the
// firehose window — i.e. the repo the firehose just saw is its first PoC.
func pocIsFirstPublicRepo(id string, now time.Time) (bool, error) {
	before := now.Add(-pocFirehoseWindow).Format("2006-01-02T15:04:05Z")
	q := url.Values{"q": {`"` + id + `" created:<` + before}, "per_page": {"1"}}
	body, err := cveRadarGitHubGet(pocFirehoseSearchURL + "?" + q.Encode())
	if err != nil {
		return false, err
	}
	var res struct {
		TotalCount int `json:"total_count"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return false, err
	}
	return res.TotalCount == 0, nil
}
