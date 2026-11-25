package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// ─── CVE Radar ────────────────────────────────────────────────────────────────
// Polls NVD's publication feed + GitHub Security Advisories for freshly
// PUBLISHED CVEs, and alerts ONLY when a public PoC exists — a CVE without a
// weapon is noise for hunting purposes. PoCs usually appear hours after
// publication, so a CVE that crossed the alert bar but has no PoC yet waits in
// a persistent pending queue and is re-checked every cycle; if no PoC appears
// within cveRadarPendingTTL it is dropped silently (no alert ever).
//
// PoC sources (web-wide):
//   1. GitHub repo search ("CVE-ID", top-2 links with repo name + description)
//      — token-authed via the GITHUB_TOKEN setting when present (30/min vs 10).
//      Forks are dropped and a repo only counts when it has ≥1 star, is older
//      than 24h, or belongs to a known-trusted source: a "public PoC" bar of
//      any repo mentioning the id let same-day fake-PoC malware repos through.
//      GitHub-only matches are labeled "unverified PoC — review before running".
//   2. Exploit-DB feed — commit messages of exploit-database/exploitdb since
//      the last cycle; any CVE id mentioned = curated PoC published, commit
//      URL linked in the alert. Feed hits (this and the social feeds) persist
//      for cveRadarFeedHitsTTL, so a PoC that surfaced before the CVE was
//      tracked still confirms it later.
//
// Every confirmed PoC link is persisted to the settings-backed memory
// (cve_radar_poc_log, newest-first, capped) for later querying.
//
// Alert bar (tunable via env), both stages required before any Discord ping:
//   - CVSS >= CVE_RADAR_CRITICAL_MIN (default 9.0)  -> candidate regardless of product
//   - CVSS >= CVE_RADAR_HIGH_MIN    (default 7.0)   -> candidate when the description
//     names one of the watched products (built-in keyword list, extendable live
//     via the CVE_RADAR_EXTRA_KEYWORDS setting).
//   - AND a PoC source above confirms a public weapon.
//
// The PoC search runs for every candidate (max pocSearchMaxPerCycle per list,
// fresh + pending — the search API is rate limited); overflow candidates go to
// the pending queue for the next cycle rather than being skipped.
//
// The watermarks (poll + exploit-db), the recently-seen CVE-ID set, the
// pending queue, and the PoC log live in the settings table so they survive
// redeploys. First-ever run baselines silently — otherwise a fresh install
// would "discover" years of NVD at once.
//
// Config (both re-read every cycle — no restart needed):
//   CVE_RADAR=off                     — pause (env or settings-table kill switch)
//   CVE_RADAR_INTERVAL_MINUTES        — poll interval (default 5, min 5)
//   CVE_RADAR_CRITICAL_MIN            — always-candidate score (default 9.0)
//   CVE_RADAR_HIGH_MIN                — keyword-gated score (default 7.0)
//   CVE_RADAR_EXTRA_KEYWORDS setting  — comma-separated product keywords added
//                                       to the built-in list without a redeploy
//   GITHUB_TOKEN setting              — optional; steadies/raises search limits

const (
	cveRadarWatermarkKey    = "cve_radar_last_run"
	cveRadarSeenKey         = "cve_radar_seen_ids"
	cveRadarPendingKey      = "cve_radar_pending"
	cveRadarEDBWatermarkKey = "cve_radar_edb_watermark"
	cveRadarGHAuthAlertKey  = "cve_radar_ghauth_alert_at"
	cveRadarPoCLogKey       = "cve_radar_poc_log"
	cveRadarSeenCap         = 500
	cveRadarPendingCap      = 100
	cveRadarPoCLogCap       = 500
	cveRadarListLimit       = 10 // max CVEs listed in one Discord alert
	pocSearchMaxPerCycle    = 5  // per list (fresh + pending); GitHub search is rate limited
	nvdPageLimit            = 200
	cveRadarMaxLookback     = 6 * time.Hour  // downtime catch-up must never flood
	cveRadarPendingTTL      = 48 * time.Hour // keep re-checking a no-PoC CVE this long, then drop silently
)

const (
	// Feed PoC hits (CVE -> labeled link) are remembered this long so a feed
	// signal that arrives BEFORE the CVE is tracked still confirms it later.
	cveRadarFeedHitsKey = "cve_radar_feed_hits"
	cveRadarFeedHitsTTL = 14 * 24 * time.Hour
	// NVD paging: unauthenticated NVD allows 5 requests / 30s — space requests
	// and cap pages per window so a burst can't stall the cycle.
	nvdMaxPages   = 5
	nvdRequestGap = 6 * time.Second
	// Late scores: NVD often publishes a CVE unscored and adds CVSS later. The
	// lastModified window re-reads those, limited to CVEs published this
	// recently (an old CVE re-scored today isn't "fresh").
	cveRadarLateScoreMaxAge = 14 * 24 * time.Hour
	// A GitHub repo younger than this with no stars is not evidence of a PoC.
	cveRadarPoCMinRepoAge = 24 * time.Hour
	// GitHub advisories only become list-visible hours-to-days AFTER their
	// published_at stamp (bulk publication waves), so the cycle watermark
	// filter permanently lost late-visible advisories — CVE-2026-107806 was
	// GHSA-published 2026-10-09 20:45Z but only reached the radar 2026-10-14
	// through NVD's late CVSS enrichment. The radar re-reads everything
	// published within this window each cycle; the cycle-level seen-set
	// dedupes the overlap.
	cveRadarGHSALookback = 72 * time.Hour
	// One advisories page covers a quiet day, but bulk waves exceed it —
	// follow the list cursor up to this many pages per poll.
	cveRadarGHSAMaxPages = 3
)

// cveRadarTrustedPoCOwners are GitHub orgs/users whose repos count as a real
// PoC source regardless of stars/age (curated exploit DBs, vendor research,
// nuclei-templates). Aggregators that auto-list every claimed PoC (fake ones
// included) deliberately don't qualify.
var cveRadarTrustedPoCOwners = map[string]bool{
	"projectdiscovery": true, "rapid7": true, "watchtowrlabs": true,
	"horizon3ai": true, "offensive-security": true, "exploit-database": true,
	"vulhub": true, "packetstormsecurity": true, "assetnote": true,
	"vulncheck-oss": true,
}

// cveRE extracts CVE ids from free text (Exploit-DB commit messages).
var cveRE = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

// cveRadarKeywords are products that actually appear across the platform's
// target base. Matched case-insensitively as substrings of the description.
var cveRadarKeywords = []string{
	"gitlab", "jenkins", "wordpress", "drupal", "confluence", "jira", "bitbucket",
	"vmware", "citrix", "fortinet", "fortios", "pulse secure", "ivanti",
	"exchange", "sharepoint", "spring framework", "struts", "tomcat", "weblogic",
	"websphere", "coldfusion", "magento", "typo3", "nextcloud", "owncloud",
	"discourse", "grafana", "kibana", "elasticsearch", "zabbix", "cacti",
	"rconfig", "manageengine", "zoho", "minio", "harbor", "argocd",
	"teamcity", "sonarqube", "nexus repository", "artifactory", "traefik",
	"haproxy", "nginx", "apache http", "veeam", "moveit", "progress",
	"django", "rails", "redmine", "glpi", "phpmyadmin", "adminer",
}

var (
	cveRadarMu      sync.Mutex
	cveRadarStarted bool
	cveRadarLastRun time.Time
)

// cveRadarItem is one CVE that crossed the alert bar.
type cveRadarItem struct {
	ID    string
	Desc  string
	CVSS  float64
	Link  string
	Proof string // "N repo(s) — url" when the GitHub PoC search confirmed a public PoC
	// Radar-page enrichment (kept in the cves table, not needed for alerting).
	Vector    string // full CVSS vector string
	CWE       string
	Published string // RFC3339
}

// cveRadarPendingItem is a CVE that crossed the alert bar but has no public
// PoC yet; it is re-checked each cycle until one appears or the TTL elapses.
type cveRadarPendingItem struct {
	ID        string  `json:"id"`
	Desc      string  `json:"desc"`
	CVSS      float64 `json:"cvss"`
	Link      string  `json:"link"`
	FirstSeen int64   `json:"first_seen"` // unix seconds
	// LastChecked is the last successful PoC search (unix seconds, 0 = never);
	// the re-check budget goes to the least recently checked items first.
	LastChecked int64 `json:"last_checked,omitempty"`
	// Proof is set when a PoC was confirmed but the alert failed to deliver:
	// the next cycle re-alerts without searching again.
	Proof string `json:"proof,omitempty"`
	// Radar-page enrichment (older persisted blobs simply lack these).
	Vector    string `json:"vector,omitempty"`
	CWE       string `json:"cwe,omitempty"`
	Published string `json:"published,omitempty"`
}

// nvdCVEEntry is the subset of an NVD 2.0 CVE record the radar uses. Metrics
// is a generic map because NVD mixes cvssMetricV40/V31/V30/V2 keys.
type nvdCVEEntry struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Weaknesses []struct {
		Description []struct {
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Metrics map[string][]struct {
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			VectorString string  `json:"vectorString"`
		} `json:"cvssData"`
	} `json:"metrics"`
}

// cveRadarScore returns the highest base score across every NVD metric version.
func (c *nvdCVEEntry) cveRadarScore() float64 {
	best := 0.0
	for _, ms := range c.Metrics {
		for _, m := range ms {
			if m.CVSSData.BaseScore > best {
				best = m.CVSSData.BaseScore
			}
		}
	}
	return best
}

// cveRadarVector returns the vector string of the highest-scoring metric
// (empty when NVD has not scored the record yet).
func (c *nvdCVEEntry) cveRadarVector() string {
	best := 0.0
	vec := ""
	for _, ms := range c.Metrics {
		for _, m := range ms {
			if m.CVSSData.BaseScore > best {
				best = m.CVSSData.BaseScore
				vec = m.CVSSData.VectorString
			}
		}
	}
	return vec
}

// cveRadarCWE returns the first CWE id NVD lists (CWE-NVD-NOVALUE filtered).
func (c *nvdCVEEntry) cveRadarCWE() string {
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			v := strings.ToUpper(strings.TrimSpace(d.Value))
			if strings.HasPrefix(v, "CWE-") && !strings.Contains(v, "NOVALUE") {
				return v
			}
		}
	}
	return ""
}

func (c *nvdCVEEntry) cveRadarDesc() string {
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			return d.Value
		}
	}
	return ""
}

func cveRadarEnabled() bool {
	// DB setting wins over env — the operator can pause the radar without a
	// redeploy, same contract as NUCLEI_TEMPLATE_AUTORUN.
	if v, _ := db.GetSetting("CVE_RADAR"); strings.EqualFold(strings.TrimSpace(v), "off") {
		return false
	}
	return !strings.EqualFold(strings.TrimSpace(os.Getenv("CVE_RADAR")), "off")
}

func cveRadarInterval() time.Duration {
	if v, _ := db.GetSetting("CVE_RADAR_INTERVAL_MINUTES"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 5 {
			return time.Duration(n) * time.Minute
		}
	}
	if v := strings.TrimSpace(os.Getenv("CVE_RADAR_INTERVAL_MINUTES")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 5 {
			return time.Duration(n) * time.Minute
		}
	}
	// 5 min: the GitHub firehose makes a cycle cheap (one search for every
	// new PoC repo), and a PoC-day race is decided in minutes.
	return 5 * time.Minute
}

func cveRadarCriticalMin() float64 {
	if v := strings.TrimSpace(os.Getenv("CVE_RADAR_CRITICAL_MIN")); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return 9.0
}

func cveRadarHighMin() float64 {
	if v := strings.TrimSpace(os.Getenv("CVE_RADAR_HIGH_MIN")); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return 7.0
}

// cveRadarKeywordRE builds the product-keyword matcher: built-in list plus any
// operator-added keywords from the CVE_RADAR_EXTRA_KEYWORDS setting.
func cveRadarKeywordRE() *regexp.Regexp {
	words := append([]string{}, cveRadarKeywords...)
	if extra, _ := db.GetSetting("CVE_RADAR_EXTRA_KEYWORDS"); extra != "" {
		for _, w := range strings.Split(extra, ",") {
			if w = strings.TrimSpace(w); w != "" {
				words = append(words, w)
			}
		}
	}
	parts := make([]string, len(words))
	for i, w := range words {
		parts[i] = regexp.QuoteMeta(w)
	}
	re, err := regexp.Compile("(?i)(" + strings.Join(parts, "|") + ")")
	if err != nil {
		return nil
	}
	return re
}

// StartCVERadar launches the radar goroutine once per process.
// Requires the DB (watermark) — call only when DB_HOST is configured.
// The loop always runs: the CVE_RADAR kill switch and the interval are
// re-read every cycle, so pausing/resuming or retuning never needs a restart.
func StartCVERadar() {
	cveRadarMu.Lock()
	if cveRadarStarted {
		cveRadarMu.Unlock()
		return
	}
	cveRadarStarted = true
	cveRadarMu.Unlock()

	go func() {
		defer utils.RecoverPanic("cve-radar:loop")
		logger.GetLogger().Infof("[CVE-RADAR] started (interval %s, critical>=%.1f, high+keyword>=%.1f, enabled=%v)",
			cveRadarInterval(), cveRadarCriticalMin(), cveRadarHighMin(), cveRadarEnabled())
		// First tick shortly after boot (baseline seed or catch-up).
		time.Sleep(45 * time.Second)
		for {
			utils.GuardedRun("cve-radar:tick", cveRadarCycle)
			time.Sleep(cveRadarInterval())
		}
	}()
}

// cveRadarPaused remembers the last kill-switch state so the pause/resume is
// logged once per transition, not every cycle.
var cveRadarPaused atomic.Bool

// cveRadarCycle runs one poll: NVD publication feed + GitHub advisories since
// the watermark, filters, alerts, advances the watermark. The watermark only
// advances after both sources are polled AND the cycle's seen/pending state is
// persisted — a failed NVD call or a crash mid-cycle retries the same window
// next tick, and the seen-set makes the overlap harmless.
func cveRadarCycle() {
	if !cveRadarEnabled() {
		if !cveRadarPaused.Swap(true) {
			logger.GetLogger().Infof("[CVE-RADAR] paused (CVE_RADAR=off) — re-checked every cycle")
		}
		return
	}
	if cveRadarPaused.Swap(false) {
		logger.GetLogger().Infof("[CVE-RADAR] resumed")
	}

	cveRadarMu.Lock()
	cveRadarLastRun = time.Now()
	cveRadarMu.Unlock()

	kwRE := cveRadarKeywordRE()
	if kwRE == nil {
		logger.GetLogger().Infof("[CVE-RADAR] keyword matcher failed to compile — skipping cycle")
		return
	}

	wm := cveRadarParseWatermark()
	seen := cveRadarLoadSeen()

	now := time.Now().UTC()
	first := wm.IsZero()
	since := wm
	if first {
		since = now.Add(-time.Hour) // short silent baseline window
	}
	if d := now.Sub(since); d > cveRadarMaxLookback {
		since = now.Add(-cveRadarMaxLookback)
	}

	items, err := cveRadarPoll(since, kwRE)
	if err != nil {
		logger.GetLogger().Infof("[CVE-RADAR] poll failed (watermark kept): %v", err)
		return
	}

	if first {
		for _, it := range items {
			seen[it.ID] = true
		}
		cveRadarSaveSeen(seen)
		_ = db.SetSetting(cveRadarWatermarkKey, strconv.FormatInt(now.Unix(), 10))
		logger.GetLogger().Infof("[CVE-RADAR] baseline silent (%d CVEs marked seen)", len(seen))
		if utils.MonitorWebhookConfigured() {
			utils.SendMonitorWebhook(fmt.Sprintf(
				"🛰️ **CVE Radar active** — baseline silent (%d recent CVEs marked seen). "+
					"Fresh publications land here for manual checks: CVSS ≥%.1f any product, ≥%.1f on watched products.",
				len(seen), cveRadarCriticalMin(), cveRadarHighMin()))
		}
		return
	}

	var fresh []cveRadarItem
	for _, it := range items {
		if !seen[it.ID] {
			fresh = append(fresh, it)
		}
	}

	pending := cveRadarLoadPending()
	nowUnix := now.Unix()

	// External PoC feeds (Exploit-DB commits, watchTowr blog RSS, Hacker News,
	// GitHub PoC firehose), merged with the persisted hits of the last
	// cveRadarFeedHitsTTL. Parsed BEFORE gating so both fresh and pending CVEs
	// can confirm from them without spending GitHub search budget.
	edb := cveRadarExternalPoCFeeds()

	// PoC gate: a fresh CVE only alerts once a public PoC exists. PoCs usually
	// appear hours after publication, so unproven CVEs wait in the pending list
	// and are re-checked every cycle until the TTL elapses (then silent drop).
	// Highest CVSS first so the search budget favors the worst candidates.
	sort.SliceStable(fresh, func(i, j int) bool { return fresh[i].CVSS > fresh[j].CVSS })
	var confirmed []cveRadarItem
	searches := 0
	searchedNow := map[string]bool{} // never search one CVE twice in a cycle
	searchDown := false              // GitHub rate-limited/unreachable: stop searching this cycle
	search := func(id string) ([]string, []string, bool) {
		if searchDown {
			return nil, nil, false
		}
		searches++
		searchedNow[id] = true
		display, links, err := cveRadarPocLinks(id)
		if err != nil {
			searchDown = true
			logger.GetLogger().Infof("[CVE-RADAR] PoC search unavailable (%v) — remaining candidates wait for the next cycle", err)
			return nil, nil, false
		}
		return display, links, true
	}
	for _, it := range fresh {
		cveRadarTrackCVE(it)
		if edbLink := edb[it.ID]; edbLink != "" {
			it.Proof = edbLink // already labeled ("watchTowr blog: ..." etc.)
			confirmed = append(confirmed, it)
			src, link := splitFeedProof(edbLink)
			cveRadarLogPoC(it.ID, it.CVSS, src, link)
			continue
		}
		p := cveRadarPendingItem{ID: it.ID, Desc: it.Desc, CVSS: it.CVSS, Link: it.Link, FirstSeen: nowUnix,
			Vector: it.Vector, CWE: it.CWE, Published: it.Published}
		if searches >= pocSearchMaxPerCycle {
			pending = append(pending, p)
			continue
		}
		display, links, ok := search(it.ID)
		if ok {
			p.LastChecked = nowUnix
		}
		if len(display) > 0 {
			it.Proof = strings.Join(display, " · ")
			confirmed = append(confirmed, it)
			for _, l := range links {
				cveRadarLogPoC(it.ID, it.CVSS, "github", l)
			}
		} else {
			pending = append(pending, p)
		}
	}

	// Re-check pending least-recently-checked first (never-checked first): the
	// budget used to go to the same queue head every cycle, so items further
	// back were never searched before their TTL. Alert on PoC appearance, drop
	// past TTL.
	pending = cveRadarDedupePending(pending)
	sort.SliceStable(pending, func(i, j int) bool { return pending[i].LastChecked < pending[j].LastChecked })
	var keptPending []cveRadarPendingItem
	for _, p := range pending {
		if nowUnix-p.FirstSeen > int64(cveRadarPendingTTL/time.Second) {
			continue // no public PoC within the TTL — silent drop
		}
		cveRadarTrackCVE(cveRadarItem{ID: p.ID, Desc: p.Desc, CVSS: p.CVSS, Link: p.Link,
			Vector: p.Vector, CWE: p.CWE, Published: p.Published})
		if p.Proof != "" { // confirmed earlier, alert delivery failed — retry the alert
			confirmed = append(confirmed, cveRadarItem{ID: p.ID, Desc: p.Desc, CVSS: p.CVSS, Link: p.Link, Proof: p.Proof})
			continue
		}
		if edbLink := edb[p.ID]; edbLink != "" {
			confirmed = append(confirmed, cveRadarItem{ID: p.ID, Desc: p.Desc, CVSS: p.CVSS, Link: p.Link, Proof: edbLink})
			src, link := splitFeedProof(edbLink)
			cveRadarLogPoC(p.ID, p.CVSS, src, link)
			continue
		}
		if searchedNow[p.ID] || searches >= 2*pocSearchMaxPerCycle {
			keptPending = append(keptPending, p)
			continue
		}
		display, links, ok := search(p.ID)
		if ok {
			p.LastChecked = nowUnix
		}
		if len(display) > 0 {
			confirmed = append(confirmed, cveRadarItem{ID: p.ID, Desc: p.Desc, CVSS: p.CVSS, Link: p.Link, Proof: strings.Join(display, " · ")})
			for _, l := range links {
				cveRadarLogPoC(p.ID, p.CVSS, "github", l)
			}
		} else {
			keptPending = append(keptPending, p)
		}
	}

	// Late PoCs: feed hits (firehose included) for CVEs this cycle did not
	// otherwise handle — older CVEs or ones the pending queue dropped.
	processed := map[string]bool{}
	for _, it := range fresh {
		processed[it.ID] = true
	}
	for _, p := range pending {
		processed[p.ID] = true
	}
	for _, it := range cveRadarLatePoCs(edb, processed, kwRE, now) {
		cveRadarTrackCVE(it)
		src, link := splitFeedProof(it.Proof)
		cveRadarLogPoC(it.ID, it.CVSS, src, link)
		confirmed = append(confirmed, it)
	}

	// PoC-day: every confirmed CVE goes straight to template resolution and a
	// targeted pass — independent of whether the Discord alert delivers.
	for _, c := range confirmed {
		pocdayEnqueueSeam(c.ID, "radar: "+firstNonEmptyStr(c.Proof, "PoC confirmed"), false)
	}

	if len(confirmed) > 0 {
		if err := cveRadarNotify(confirmed, len(keptPending)); err != nil {
			// Delivery failed: keep every confirmed CVE pending WITH its proof so
			// the next cycle re-alerts (they used to be marked seen and lost).
			logger.GetLogger().Errorf("[CVE-RADAR] alert delivery failed — %d confirmed CVE(s) kept pending for retry: %v", len(confirmed), err)
			firstSeen := map[string]int64{}
			for _, p := range pending {
				firstSeen[p.ID] = p.FirstSeen
			}
			for _, c := range confirmed {
				fs := firstSeen[c.ID]
				if fs == 0 {
					fs = nowUnix
				}
				keptPending = append(keptPending, cveRadarPendingItem{ID: c.ID, Desc: c.Desc, CVSS: c.CVSS, Link: c.Link,
					FirstSeen: fs, LastChecked: nowUnix, Proof: c.Proof})
			}
		}
	}

	// Persist seen + pending FIRST, then advance the watermark: a crash between
	// the two now re-polls the window (harmless, seen-set dedupes) instead of
	// skipping it with the fresh CVEs neither seen nor pending.
	for _, it := range fresh {
		seen[it.ID] = true
	}
	cveRadarSaveSeen(seen)
	cveRadarSavePending(keptPending)
	_ = db.SetSetting(cveRadarWatermarkKey, strconv.FormatInt(now.Unix(), 10))
	logger.GetLogger().Infof("[CVE-RADAR] %d fresh, %d PoC-confirmed alerted, %d pending, %d searches, %d feed hits",
		len(fresh), len(confirmed), len(keptPending), searches, len(edb))
}

// cveRadarDedupePending keeps the first entry per CVE id.
func cveRadarDedupePending(items []cveRadarPendingItem) []cveRadarPendingItem {
	seen := make(map[string]bool, len(items))
	out := items[:0]
	for _, p := range items {
		if p.ID == "" || seen[p.ID] {
			continue
		}
		seen[p.ID] = true
		out = append(out, p)
	}
	return out
}

// cveRadarGitHubToken returns the Authorization header value from the platform
// settings when a GitHub token is configured — raises the search rate limit
// from 10/min (unauthenticated) to 30/min and steadies the API.
func cveRadarGitHubToken() string {
	if tok, _ := db.GetSetting("GITHUB_TOKEN"); strings.TrimSpace(tok) != "" {
		return "Bearer " + strings.TrimSpace(tok)
	}
	return ""
}

// cveRadarExploitDBFeed polls the exploit-database/exploitdb repo commits since
// the last watermark and maps every CVE id mentioned in a commit message to
// that commit's URL. One API call per cycle; failures keep the watermark.
func cveRadarExploitDBFeed() map[string]string {
	out := map[string]string{}
	since := cveRadarParseWatermarkSetting(cveRadarEDBWatermarkKey)
	if since.IsZero() {
		since = time.Now().UTC().Add(-time.Hour) // short silent baseline
	}
	u := "https://api.github.com/repos/exploit-database/exploitdb/commits?per_page=50&since=" +
		url.QueryEscape(since.UTC().Format("2006-01-02T15:04:05Z"))
	body, err := cveRadarGitHubGet(u)
	if err != nil {
		return out
	}
	var commits []struct {
		HTMLURL string `json:"html_url"`
		Commit  struct {
			Message string `json:"message"`
		} `json:"commit"`
	}
	if err := json.Unmarshal(body, &commits); err != nil {
		return out
	}
	for _, c := range commits {
		for _, m := range cveRE.FindAllString(c.Commit.Message, -1) {
			if out[m] == "" {
				out[m] = c.HTMLURL
			}
		}
	}
	// Advance watermark to now regardless of hits (dedup is by CVE map above).
	_ = db.SetSetting(cveRadarEDBWatermarkKey, strconv.FormatInt(time.Now().UTC().Unix(), 10))
	return out
}

// cveRadarGHRepo is the subset of a GitHub repo search item the PoC gate uses.
type cveRadarGHRepo struct {
	FullName    string    `json:"full_name"`
	HTMLURL     string    `json:"html_url"`
	Description string    `json:"description"`
	Fork        bool      `json:"fork"`
	Stars       int       `json:"stargazers_count"`
	CreatedAt   time.Time `json:"created_at"`
	Owner       struct {
		Login string `json:"login"`
	} `json:"owner"`
}

// cveRadarPoCRepoVerdict decides whether a GitHub repo counts as a PoC:
// trusted (curated source / vendor research org), plausible (≥1 star or older
// than cveRadarPoCMinRepoAge — fake-PoC malware repos are typically same-day,
// zero-star drops), or rejected (forks and everything else).
func cveRadarPoCRepoVerdict(r cveRadarGHRepo, now time.Time) (ok, trusted bool) {
	if r.Fork {
		return false, false
	}
	owner := strings.ToLower(r.Owner.Login)
	if owner == "" {
		owner = strings.ToLower(strings.SplitN(r.FullName, "/", 2)[0])
	}
	if cveRadarTrustedPoCOwners[owner] {
		return true, true
	}
	if r.Stars >= 1 || (!r.CreatedAt.IsZero() && now.Sub(r.CreatedAt) > cveRadarPoCMinRepoAge) {
		return true, false
	}
	return false, false
}

// cveRadarSafeLink renders a third-party URL for Discord: http(s) URLs with no
// markdown/whitespace-breaking characters are wrapped in <> (clickable, no
// embed); anything else is escaped as plain text.
func cveRadarSafeLink(u string) string {
	u = strings.TrimSpace(u)
	if cveRadarSafeURLRE.MatchString(u) {
		return "<" + u + ">"
	}
	return utils.DiscordEscapeTrunc(u, 200)
}

// Inside <…> Discord renders no markdown, so only the delimiters and
// whitespace need excluding.
var cveRadarSafeURLRE = regexp.MustCompile("^https?://[^\\s<>\"`]+$")

// cveRadarPocLinks searches GitHub for public PoC repos and returns up to two
// Discord-safe display strings ("owner/repo — <url> — desc (label)") plus the
// raw repo URLs for the PoC log. A non-nil error means the search could not
// run (rate limit, network) — "no PoC" is (nil, nil, nil).
func cveRadarPocLinks(cveID string) ([]string, []string, error) {
	q := url.Values{"q": {`"` + cveID + `"`}, "sort": {"updated"}, "per_page": {"10"}}
	body, err := cveRadarGitHubGet("https://api.github.com/search/repositories?" + q.Encode())
	if err != nil {
		return nil, nil, err
	}
	var res struct {
		TotalCount int              `json:"total_count"`
		Items      []cveRadarGHRepo `json:"items"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, nil, fmt.Errorf("decode github search: %w", err)
	}
	return cveRadarPoCFromRepos(res.Items, time.Now())
}

// cveRadarPoCFromRepos is the pure core of cveRadarPocLinks (unit-testable).
// Trusted repos sort first.
func cveRadarPoCFromRepos(items []cveRadarGHRepo, now time.Time) ([]string, []string, error) {
	type pick struct {
		repo    cveRadarGHRepo
		trusted bool
	}
	var picks []pick
	for _, it := range items {
		if ok, trusted := cveRadarPoCRepoVerdict(it, now); ok {
			picks = append(picks, pick{it, trusted})
		}
	}
	sort.SliceStable(picks, func(i, j int) bool { return picks[i].trusted && !picks[j].trusted })
	var display, links []string
	for _, p := range picks {
		if len(display) >= 2 {
			break
		}
		link := p.repo.HTMLURL
		if !strings.HasPrefix(link, "https://github.com/") {
			link = "https://github.com/" + p.repo.FullName
		}
		label := "unverified PoC — review before running"
		if p.trusted {
			label = "trusted source"
		}
		s := utils.DiscordEscapeTrunc(p.repo.FullName, 80) + " — " + cveRadarSafeLink(link)
		if d := strings.TrimSpace(p.repo.Description); d != "" {
			s += " — " + utils.DiscordEscapeTrunc(strings.ReplaceAll(d, "\n", " "), 80)
		}
		s += fmt.Sprintf(" (★%d, %s)", p.repo.Stars, label)
		display = append(display, s)
		links = append(links, link)
	}
	return display, links, nil
}

// cveRadarLogPoC persists a confirmed PoC to the settings-backed memory
// (cve_radar_poc_log, newest-first, capped) so the platform keeps a durable
// web-searchable record of every PoC link it ever alerted on.
func cveRadarLogPoC(cveID string, cvss float64, source, link string) {
	type pocEntry struct {
		CVE    string  `json:"cve"`
		CVSS   float64 `json:"cvss"`
		Source string  `json:"source"`
		Link   string  `json:"link"`
		SeenAt string  `json:"seen_at"`
	}
	var log []pocEntry
	if v, _ := db.GetSetting(cveRadarPoCLogKey); v != "" {
		_ = json.Unmarshal([]byte(v), &log)
	}
	// dedup on cve+link
	for _, e := range log {
		if e.CVE == cveID && e.Link == link {
			return
		}
	}
	now := time.Now().UTC()
	log = append([]pocEntry{{CVE: cveID, CVSS: cvss, Source: source, Link: link,
		SeenAt: now.Format(time.RFC3339)}}, log...)
	if len(log) > cveRadarPoCLogCap {
		log = log[:cveRadarPoCLogCap]
	}
	if b, err := json.Marshal(log); err == nil {
		_ = db.SetSetting(cveRadarPoCLogKey, string(b))
	}
	_ = db.MarkCVEPoC(cveID, cvss, source, link, now.Unix())
}

// cveRadarTrackCVE upserts a CVE row for the radar page (best-effort: a
// tracking failure must never break the alerting cycle).
func cveRadarTrackCVE(it cveRadarItem) {
	firstSeen := time.Now().UTC().Unix()
	if pub, ok := nvdTime(it.Published); ok {
		firstSeen = pub.Unix()
	}
	if err := db.UpsertCVE(db.CVERecord{
		CVEID:        it.ID,
		Description:  it.Desc,
		CVSSScore:    it.CVSS,
		CVSSVector:   it.Vector,
		AttackVector: db.AttackVectorFromCVSS(it.Vector),
		CWE:          it.CWE,
		PublishedAt:  it.Published,
		FirstSeenAt:  firstSeen,
	}); err != nil {
		logger.GetLogger().Infof("[CVE-RADAR] track %s failed: %v", it.ID, err)
	}
}

// CVERadarBackfill imports the radar's legacy settings-backed state (PoC log
// + pending list) into the cves table once at boot so the page starts
// populated. Best-effort; unknown shapes are skipped.
func CVERadarBackfill() {
	if v, _ := db.GetSetting(cveRadarPoCLogKey); v != "" {
		var log []struct {
			CVE    string  `json:"cve"`
			CVSS   float64 `json:"cvss"`
			Source string  `json:"source"`
			Link   string  `json:"link"`
			SeenAt string  `json:"seen_at"`
		}
		if json.Unmarshal([]byte(v), &log) == nil {
			for _, e := range log {
				ts := time.Now().UTC().Unix()
				if t, err := time.Parse(time.RFC3339, e.SeenAt); err == nil {
					ts = t.Unix()
				}
				_ = db.MarkCVEPoC(e.CVE, e.CVSS, e.Source, e.Link, ts)
			}
		}
	}
	if v, _ := db.GetSetting(cveRadarPendingKey); v != "" {
		var pending []cveRadarPendingItem
		if json.Unmarshal([]byte(v), &pending) == nil {
			for _, p := range pending {
				_ = db.UpsertCVE(db.CVERecord{
					CVEID: p.ID, Description: p.Desc, CVSSScore: p.CVSS,
					CVSSVector: p.Vector, AttackVector: db.AttackVectorFromCVSS(p.Vector),
					CWE: p.CWE, PublishedAt: p.Published, FirstSeenAt: p.FirstSeen,
				})
			}
		}
	}
}

// cveRadarPoll fetches both sources for everything published since `since`.
// It returns an error only when NVD failed (the authoritative feed); a GHSA
// failure degrades to an NVD-only cycle.
func cveRadarPoll(since time.Time, kwRE *regexp.Regexp) ([]cveRadarItem, error) {
	byID := map[string]cveRadarItem{}

	// --- NVD publication feed + late scores --------------------------------
	// Published in the window, plus modified in the window (NVD often
	// publishes a CVE unscored and adds the CVSS hours later — the
	// publication window alone never re-reads it). Both paged to the end.
	nvdStart := since.Add(-5*time.Minute).UTC().Format("2006-01-02T15:04:05.000") + "Z"
	nvdEnd := time.Now().UTC().Add(-time.Minute).Format("2006-01-02T15:04:05.000") + "Z"
	published, err := cveRadarNVDFetch("pub", nvdStart, nvdEnd)
	if err != nil {
		return nil, fmt.Errorf("nvd: %w", err)
	}
	modified, err := cveRadarNVDFetch("lastMod", nvdStart, nvdEnd)
	if err != nil {
		// Late-score pickup is best-effort; the publication feed is the anchor.
		logger.GetLogger().Infof("[CVE-RADAR] NVD lastModified poll failed (publication feed only): %v", err)
	}
	lateCutoff := time.Now().UTC().Add(-cveRadarLateScoreMaxAge)
	for i, c := range append(published, modified...) {
		if c.ID == "" || strings.EqualFold(c.VulnStatus, "Rejected") {
			continue
		}
		if _, dup := byID[c.ID]; dup {
			continue
		}
		if i >= len(published) {
			// Modified-window entry: only recently PUBLISHED CVEs are fresh.
			if pub, ok := nvdTime(c.Published); !ok || pub.Before(lateCutoff) {
				continue
			}
		}
		desc := truncateStr(c.cveRadarDesc(), 600)
		score := c.cveRadarScore()
		if !cveRadarPasses(desc, score, kwRE) {
			continue
		}
		byID[c.ID] = cveRadarItem{
			ID:        c.ID,
			Desc:      desc,
			CVSS:      score,
			Link:      "https://nvd.nist.gov/vuln/detail/" + c.ID,
			Vector:    c.cveRadarVector(),
			CWE:       c.cveRadarCWE(),
			Published: c.Published,
		}
	}

	// --- GitHub advisories (vendor advisories often land before NVD) -------
	// Advisories only become list-visible hours-to-days AFTER their
	// published_at stamp (bulk publication waves), so filtering them on the
	// cycle watermark permanently lost late-visible ones — CVE-2026-107806 was
	// GHSA-published 2026-10-09 20:45Z but only reached the radar 2026-10-14
	// through NVD's late CVSS enrichment. Everything published within the
	// lookback window is re-read each cycle; the cycle-level seen-set dedupes
	// the overlap.
	ghsaFloor := time.Now().UTC().Add(-cveRadarGHSALookback)
	ghsas, ghsaOK := cveRadarGHSAFetch(ghsaFloor)
	if !ghsaOK {
		logger.GetLogger().Infof("[CVE-RADAR] GHSA poll failed (NVD-only cycle)")
	}
	for _, a := range ghsas {
		if !strings.HasPrefix(a.CVEID, "CVE-") {
			continue // the radar keys on CVE ids
		}
		pub, perr := time.Parse(time.RFC3339, a.PublishedAt)
		if perr != nil || !pub.After(ghsaFloor) {
			continue
		}
		if _, dup := byID[a.CVEID]; dup {
			continue
		}
		desc := a.Summary
		if desc == "" {
			desc = a.Description
		}
		score := a.CVSS.Score
		if score == 0 {
			// GHSA without a computed CVSS: map the qualitative severity.
			score = map[string]float64{
				"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0,
			}[strings.ToLower(a.Severity)]
		}
		desc = truncateStr(desc, 600)
		if !cveRadarPasses(desc, score, kwRE) {
			continue
		}
		byID[a.CVEID] = cveRadarItem{
			ID:   a.CVEID,
			Desc: desc,
			CVSS: score,
			Link: a.HTMLURL,
		}
	}

	out := make([]cveRadarItem, 0, len(byID))
	for _, it := range byID {
		out = append(out, it)
	}
	return out, nil
}

// nvdBaseURL / nvdSleep / cveRadarGHSAURL are vars so tests can point the
// pagers at stubs.
var (
	nvdBaseURL      = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
	nvdSleep        = time.Sleep
	cveRadarGHSAURL = "https://api.github.com/advisories"
)

// cveRadarNVDFetch pages one NVD date window (kind "pub" or "lastMod") to the
// end: one page of nvdPageLimit used to be the whole window, then the
// watermark jumped to now and everything past result 200 (a busy publication
// day) was never seen. Requests are spaced nvdRequestGap apart (NVD's public
// rate limit) and capped at nvdMaxPages; any page failure fails the window so
// the caller keeps its watermark.
func cveRadarNVDFetch(kind, start, end string) ([]nvdCVEEntry, error) {
	var out []nvdCVEEntry
	for page, startIndex := 0, 0; page < nvdMaxPages; page++ {
		if page > 0 {
			nvdSleep(nvdRequestGap)
		}
		u := fmt.Sprintf("%s?%sStartDate=%s&%sEndDate=%s&resultsPerPage=%d&startIndex=%d",
			nvdBaseURL, kind, url.QueryEscape(start), kind, url.QueryEscape(end), nvdPageLimit, startIndex)
		body, err := cveRadarHTTP(u)
		if err != nil {
			return nil, err
		}
		var res struct {
			TotalResults    int `json:"totalResults"`
			ResultsPerPage  int `json:"resultsPerPage"`
			Vulnerabilities []struct {
				CVE nvdCVEEntry `json:"cve"`
			} `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(body, &res); err != nil {
			return nil, fmt.Errorf("nvd decode: %w", err)
		}
		for _, v := range res.Vulnerabilities {
			out = append(out, v.CVE)
		}
		startIndex += len(res.Vulnerabilities)
		if len(res.Vulnerabilities) == 0 || startIndex >= res.TotalResults {
			return out, nil
		}
		if page == nvdMaxPages-1 {
			logger.GetLogger().Infof("[CVE-RADAR] NVD %s window has %d results — stopped at the %d-page cap", kind, res.TotalResults, nvdMaxPages)
		}
	}
	return out, nil
}

// cveRadarGHSA is the subset of a GitHub global security advisory the radar
// uses.
type cveRadarGHSA struct {
	CVEID       string `json:"cve_id"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	PublishedAt string `json:"published_at"`
	HTMLURL     string `json:"html_url"`
	CVSS        struct {
		Score float64 `json:"score"`
	} `json:"cvss"`
}

// cveRadarLinkNextRE extracts the rel="next" URL from a GitHub Link header.
var cveRadarLinkNextRE = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// cveRadarLinkNext returns the next-page URL of a GitHub Link header, ""
// when there is no further page.
func cveRadarLinkNext(h http.Header) string {
	if h == nil {
		return ""
	}
	if m := cveRadarLinkNextRE.FindStringSubmatch(strings.Join(h.Values("Link"), ", ")); m != nil {
		return m[1]
	}
	return ""
}

// cveRadarGHSAFetch lists global advisories sorted by published_at desc,
// following the list cursor up to cveRadarGHSAMaxPages and stopping as soon
// as a page dips to the lookback floor. Advisories become list-visible in
// bulk waves hours-to-days after their published_at stamp, so the whole
// lookback window is re-read every cycle and the cycle-level seen-set dedupes
// the overlap. ok=false only when the first page failed; later-page failures
// keep what was already collected (best-effort, like the old single fetch).
func cveRadarGHSAFetch(floor time.Time) ([]cveRadarGHSA, bool) {
	var out []cveRadarGHSA
	next := cveRadarGHSAURL + "?per_page=100&sort=published&direction=desc"
	for page := 0; page < cveRadarGHSAMaxPages && next != ""; page++ {
		body, header, err := cveRadarGitHubGetDo(next)
		if err != nil {
			if page == 0 {
				return nil, false
			}
			logger.GetLogger().Infof("[CVE-RADAR] GHSA page %d fetch failed (keeping earlier pages): %v", page+1, err)
			break
		}
		var batch []cveRadarGHSA
		if err := json.Unmarshal(body, &batch); err != nil {
			if page == 0 {
				return nil, false
			}
			logger.GetLogger().Infof("[CVE-RADAR] GHSA page %d decode failed (keeping earlier pages): %v", page+1, err)
			break
		}
		out = append(out, batch...)
		oldest := time.Time{}
		for _, a := range batch {
			if t, perr := time.Parse(time.RFC3339, a.PublishedAt); perr == nil && (oldest.IsZero() || t.Before(oldest)) {
				oldest = t
			}
		}
		if !oldest.IsZero() && !oldest.After(floor) {
			break // sorted desc: everything past this page predates the floor
		}
		next = cveRadarLinkNext(header)
	}
	return out, true
}

// nvdTime parses NVD timestamps ("2026-10-07T12:15:10.123", no zone = UTC).
func nvdTime(s string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02T15:04:05.999", time.RFC3339Nano} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// cveRadarPasses is the alert bar: CVSS >= critical-min alerts on any product;
// CVSS >= high-min alerts when a watched product is named in the description.
func cveRadarPasses(desc string, score float64, kwRE *regexp.Regexp) bool {
	if score >= cveRadarCriticalMin() {
		return true
	}
	return score >= cveRadarHighMin() && kwRE != nil && kwRE.MatchString(desc)
}

// cveRadarPocLinks replaced cveRadarPocSignal (see above); kept this comment
// block as the search-rate note: GitHub search allows 10/min unauthenticated
// and 30/min with a token — the per-cycle budgets stay well under both.

// cveRadarNotify posts one Discord alert listing PoC-confirmed CVEs and
// returns the delivery error — the caller keeps the CVEs pending on failure
// instead of marking them seen with no alert ever delivered. No webhook
// configured = nothing to deliver (nil).
func cveRadarNotify(confirmed []cveRadarItem, pendingCount int) error {
	if !utils.MonitorWebhookConfigured() {
		return nil
	}
	return utils.SendMonitorWebhookErr(cveRadarAlertText(confirmed, pendingCount))
}

// cveRadarAlertText renders the alert. Descriptions and links are third-party
// text (NVD/GHSA/feeds): escaped, and links wrapped so they can't be
// reshaped into masked links. Proof strings are pre-rendered Discord-safe.
func cveRadarAlertText(confirmed []cveRadarItem, pendingCount int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "🛰️ **%d fresh CVE(s) with public PoC** — actionable now:\n", len(confirmed))
	listed := confirmed
	if len(listed) > cveRadarListLimit {
		listed = listed[:cveRadarListLimit]
	}
	for _, it := range listed {
		fmt.Fprintf(&b, "• **%s** — CVSS **%.1f** — %s", nucleiSafeToken(it.ID), it.CVSS, cveRadarSafeLink(it.Link))
		if it.Proof != "" {
			fmt.Fprintf(&b, " · ⚠️ PoC: %s", it.Proof)
		}
		if ex := utils.DiscordEscapeTrunc(strings.ReplaceAll(it.Desc, "\n", " "), 160); ex != "" {
			fmt.Fprintf(&b, "\n  %s", ex)
		}
		b.WriteString("\n")
	}
	if len(confirmed) > len(listed) {
		fmt.Fprintf(&b, "• …and %d more\n", len(confirmed)-len(listed))
	}
	if pendingCount > 0 {
		fmt.Fprintf(&b, "*%d more awaiting a public PoC (auto re-checked, no alert unless one appears)*\n", pendingCount)
	}
	return b.String()
}

// cveRadarLoadSeen reads the recently-alerted CVE-ID set.
func cveRadarLoadSeen() map[string]bool {
	seen := map[string]bool{}
	if v, _ := db.GetSetting(cveRadarSeenKey); v != "" {
		for _, id := range strings.Split(v, ",") {
			if id = strings.TrimSpace(id); id != "" {
				seen[id] = true
			}
		}
	}
	return seen
}

// cveRadarSaveSeen persists the seen set. The cap is a slice truncation —
// correctness only needs recent IDs present, not exact LRU semantics.
func cveRadarSaveSeen(seen map[string]bool) {
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	if len(ids) > cveRadarSeenCap {
		ids = ids[:cveRadarSeenCap]
	}
	_ = db.SetSetting(cveRadarSeenKey, strings.Join(ids, ","))
}

// cveRadarLoadPending reads the no-PoC-yet re-check queue.
func cveRadarLoadPending() []cveRadarPendingItem {
	var out []cveRadarPendingItem
	v, _ := db.GetSetting(cveRadarPendingKey)
	if v == "" {
		return out
	}
	_ = json.Unmarshal([]byte(v), &out)
	return out
}

// cveRadarSavePending persists the pending queue (capped).
func cveRadarSavePending(items []cveRadarPendingItem) {
	items = cveRadarCapPending(items, cveRadarPendingCap)
	b, err := json.Marshal(items)
	if err != nil {
		return
	}
	_ = db.SetSetting(cveRadarPendingKey, string(b))
}

// cveRadarCapPending keeps at most n items: confirmed-but-undelivered first,
// then highest CVSS, then newest. The old items[:cap] kept the OLDEST entries
// and silently dropped every fresh CVE once the queue filled.
func cveRadarCapPending(items []cveRadarPendingItem, n int) []cveRadarPendingItem {
	if len(items) <= n {
		return items
	}
	sorted := append([]cveRadarPendingItem(nil), items...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if (a.Proof != "") != (b.Proof != "") {
			return a.Proof != ""
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		return a.FirstSeen > b.FirstSeen
	})
	return sorted[:n]
}

func cveRadarParseWatermark() time.Time {
	v, _ := db.GetSetting(cveRadarWatermarkKey)
	if v == "" {
		return time.Time{}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}

// cveRadarHTTP is the shared outbound HTTP helper. A custom User-Agent is
// mandatory: NVD, GitHub, and Discord's edge all reject default client
// fingerprints (Discord 403s python-urllib; NVD wants a descriptive UA).
// cveRadarHTTPWithHeaders is cveRadarHTTP with extra request headers (used to
// attach the GitHub token Authorization header for api.github.com calls).
func cveRadarHTTPWithHeaders(target string, headers map[string]string) ([]byte, error) {
	body, _, err := cveRadarHTTPStatus(target, headers)
	return body, err
}

// cveRadarHTTPStatus is cveRadarHTTPWithHeaders with the response status code
// surfaced so callers can distinguish auth rejections from other failures.
func cveRadarHTTPStatus(target string, headers map[string]string) ([]byte, int, error) {
	body, status, _, err := cveRadarHTTPDo(target, headers)
	return body, status, err
}

// cveRadarHTTPDo is cveRadarHTTPStatus with the response headers (GitHub
// rate-limit state lives in X-RateLimit-* / Retry-After).
func cveRadarHTTPDo(target string, headers map[string]string) ([]byte, int, http.Header, error) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, 0, nil, err
	}
	req.Header.Set("User-Agent", "AutoAR-CVE-Radar/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return nil, resp.StatusCode, resp.Header, err
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, resp.StatusCode, resp.Header, fmt.Errorf("rate limited -> %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, resp.Header, fmt.Errorf("%.60s -> %d", target, resp.StatusCode)
	}
	return body, resp.StatusCode, resp.Header, nil
}

// cveRadarHTTPPostJSON POSTs a JSON body and returns the response on 200. Used
// by feeds whose search endpoint is POST-only (e.g. Sploitus), which the
// GET-only cveRadarHTTPDo cannot reach.
func cveRadarHTTPPostJSON(target string, jsonBody []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", target, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AutoAR-CVE-Radar/1.0")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%.60s -> %d", target, resp.StatusCode)
	}
	return body, nil
}

// cveRadarTokenFails counts consecutive GITHUB_TOKEN rejections across cycles.
var cveRadarTokenFails int32

// errCVERadarRateLimited marks a GitHub rate-limit response (primary or
// secondary) — NOT a dead token.
var errCVERadarRateLimited = errors.New("github rate limited")

// cveRadarGHBackoffUntil (unix seconds) pauses every GitHub API call after a
// rate-limit response until the advertised reset.
var cveRadarGHBackoffUntil atomic.Int64

// cveRadarGitHubRateLimit reports whether a GitHub response is a rate limit
// and until when to back off: 429, or 403 with X-RateLimit-Remaining: 0
// (primary) or a Retry-After header (secondary). Reset comes from Retry-After
// or X-RateLimit-Reset; 60s when neither is usable (capped at 1h).
func cveRadarGitHubRateLimit(status int, h http.Header, now time.Time) (time.Time, bool) {
	if h == nil || (status != http.StatusTooManyRequests && status != http.StatusForbidden) {
		return time.Time{}, false
	}
	retryAfter := strings.TrimSpace(h.Get("Retry-After"))
	if status == http.StatusForbidden && strings.TrimSpace(h.Get("X-RateLimit-Remaining")) != "0" && retryAfter == "" {
		return time.Time{}, false // a real 403 (permissions), not a rate limit
	}
	until := now.Add(time.Minute)
	if secs, err := strconv.Atoi(retryAfter); err == nil && secs > 0 {
		until = now.Add(time.Duration(secs) * time.Second)
	} else if reset, err := strconv.ParseInt(strings.TrimSpace(h.Get("X-RateLimit-Reset")), 10, 64); err == nil && reset > now.Unix() {
		until = time.Unix(reset, 0)
	}
	if max := now.Add(time.Hour); until.After(max) {
		until = max
	}
	return until, true
}

// cveRadarGitHubGet fetches a GitHub API URL with the stored GITHUB_TOKEN when
// present, falling back to an unauthenticated retry when the token is rejected
// (401). A dead token must never blind the PoC search: the CVE-2026-21589
// race was lost exactly this way — every token-authed search 401'd and the
// error path was indistinguishable from "no public PoC" for two days.
// A rate limit (403 + X-RateLimit-Remaining: 0, or 429) is NOT a token
// failure: it backs every GitHub call off until the reset instead of counting
// toward the dead-token alert and burning the far smaller unauthenticated
// quota on an immediate retry.
func cveRadarGitHubGet(target string) ([]byte, error) {
	body, _, err := cveRadarGitHubGetDo(target)
	return body, err
}

// cveRadarGitHubGetDo is cveRadarGitHubGet with the response headers surfaced
// (advisory-list paging reads the Link cursor out of them).
func cveRadarGitHubGetDo(target string) ([]byte, http.Header, error) {
	if until := cveRadarGHBackoffUntil.Load(); time.Now().Unix() < until {
		return nil, nil, fmt.Errorf("%w until %s", errCVERadarRateLimited, time.Unix(until, 0).UTC().Format(time.RFC3339))
	}
	backoff := func(status int, h http.Header) error {
		until, limited := cveRadarGitHubRateLimit(status, h, time.Now())
		if !limited {
			return nil
		}
		cveRadarGHBackoffUntil.Store(until.Unix())
		logger.GetLogger().Infof("[CVE-RADAR] GitHub rate limit hit (%d) — backing off until %s", status, until.UTC().Format(time.RFC3339))
		return fmt.Errorf("%w (status %d) until %s", errCVERadarRateLimited, status, until.UTC().Format(time.RFC3339))
	}
	headers := map[string]string{"Accept": "application/vnd.github+json"}
	if tok := cveRadarGitHubToken(); tok != "" {
		headers["Authorization"] = tok
		body, status, h, err := cveRadarHTTPDo(target, headers)
		if err == nil {
			atomic.StoreInt32(&cveRadarTokenFails, 0)
			return body, h, nil
		}
		if rlErr := backoff(status, h); rlErr != nil {
			return nil, h, rlErr
		}
		if status != http.StatusUnauthorized {
			return nil, h, err
		}
		atomic.AddInt32(&cveRadarTokenFails, 1)
		cveRadarTokenFailAlert()
	}
	delete(headers, "Authorization")
	body, status, h, err := cveRadarHTTPDo(target, headers)
	if err != nil {
		if rlErr := backoff(status, h); rlErr != nil {
			return nil, h, rlErr
		}
	}
	return body, h, err
}

// cveRadarTokenFailAlert pages the monitoring channel while the stored GitHub
// token keeps being rejected — at most once per day. Credential rot must be
// loud, not a silent "no PoC found".
func cveRadarTokenFailAlert() {
	fails := int(atomic.LoadInt32(&cveRadarTokenFails))
	if fails < 3 {
		return
	}
	last := cveRadarParseWatermarkSetting(cveRadarGHAuthAlertKey)
	if !last.IsZero() && time.Since(last) < 24*time.Hour {
		return
	}
	_ = db.SetSetting(cveRadarGHAuthAlertKey, strconv.FormatInt(time.Now().UTC().Unix(), 10))
	msg := fmt.Sprintf("⚠️ **CVE radar: GITHUB_TOKEN rejected %d times in a row (401).** PoC searches are running UNAUTHENTICATED as a fallback (lower rate limits). Rotate GITHUB_TOKEN in Settings — this exact failure class lost the CVE-2026-21589 race (7 public PoC repos existed, every token-authed search failed silently).", fails)
	if err := utils.SendPurposeWebhookErr("monitoring", msg); err != nil {
		logger.GetLogger().Errorf("[CVE-RADAR] token-fail alert send failed: %v", err)
	}
}

// cveRadarParseWatermarkSetting is the generic watermark parser (shared by the
// NVD/GHSA poll watermark and the Exploit-DB feed watermark).
func cveRadarParseWatermarkSetting(key string) time.Time {
	v, _ := db.GetSetting(key)
	if v == "" {
		return time.Time{}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}

func cveRadarHTTP(target string) ([]byte, error) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AutoAR-CVE-Radar/1.0")
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited -> %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%.60s -> %d", target, resp.StatusCode)
	}
	return body, nil
}
