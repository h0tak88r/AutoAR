package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
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
//   2. Exploit-DB feed — commit messages of exploit-database/exploitdb since
//      the last cycle; any CVE id mentioned = curated PoC published, commit
//      URL linked in the alert.
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
// Config:
//   CVE_RADAR=off                     — disable (env or settings-table kill switch)
//   CVE_RADAR_INTERVAL_MINUTES        — poll interval (default 15, min 5)
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
}

// cveRadarPendingItem is a CVE that crossed the alert bar but has no public
// PoC yet; it is re-checked each cycle until one appears or the TTL elapses.
type cveRadarPendingItem struct {
	ID        string  `json:"id"`
	Desc      string  `json:"desc"`
	CVSS      float64 `json:"cvss"`
	Link      string  `json:"link"`
	FirstSeen int64   `json:"first_seen"` // unix seconds
}

// nvdCVEEntry is the subset of an NVD 2.0 CVE record the radar uses. Metrics
// is a generic map because NVD mixes cvssMetricV40/V31/V30/V2 keys.
type nvdCVEEntry struct {
	ID           string `json:"id"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics map[string][]struct {
		CVSSData struct {
			BaseScore float64 `json:"baseScore"`
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
	return 15 * time.Minute
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
func StartCVERadar() {
	cveRadarMu.Lock()
	if cveRadarStarted {
		cveRadarMu.Unlock()
		return
	}
	cveRadarStarted = true
	cveRadarMu.Unlock()

	if !cveRadarEnabled() {
		logger.GetLogger().Infof("[CVE-RADAR] disabled (CVE_RADAR=off or unset)")
		return
	}

	go func() {
		defer utils.RecoverPanic("cve-radar:loop")
		logger.GetLogger().Infof("[CVE-RADAR] started (interval %s, critical>=%.1f, high+keyword>=%.1f)",
			cveRadarInterval(), cveRadarCriticalMin(), cveRadarHighMin())
		// First tick shortly after boot (baseline seed or catch-up).
		time.Sleep(45 * time.Second)
		cveRadarCycle()
		ticker := time.NewTicker(cveRadarInterval())
		defer ticker.Stop()
		for range ticker.C {
			cveRadarCycle()
		}
	}()
}

// cveRadarCycle runs one poll: NVD publication feed + GitHub advisories since
// the watermark, filters, alerts, advances the watermark. The watermark only
// advances after both sources are polled — a failed NVD call retries the same
// window next tick, and the seen-set makes the overlap harmless.
func cveRadarCycle() {
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

	// Always advance the watermark once both sources answered — seen-IDs carry
	// dedup, so an unalerted-but-seen CVE is correctly silent forever.
	_ = db.SetSetting(cveRadarWatermarkKey, strconv.FormatInt(now.Unix(), 10))

	pending := cveRadarLoadPending()
	nowUnix := now.Unix()

	// Exploit-DB commit feed: one curated web-wide PoC source. Parsed BEFORE
	// gating so both fresh and pending CVEs can confirm from it without
	// spending GitHub search budget.
	edb := cveRadarExploitDBFeed()

	// PoC gate: a fresh CVE only alerts once a public PoC exists. PoCs usually
	// appear hours after publication, so unproven CVEs wait in the pending list
	// and are re-checked every cycle until the TTL elapses (then silent drop).
	// Highest CVSS first so the search budget favors the worst candidates.
	for i := 1; i < len(fresh); i++ {
		for j := i; j > 0 && fresh[j].CVSS > fresh[j-1].CVSS; j-- {
			fresh[j], fresh[j-1] = fresh[j-1], fresh[j]
		}
	}
	var confirmed []cveRadarItem
	searches := 0
	for _, it := range fresh {
		edbLink := edb[it.ID]
		if edbLink != "" {
			it.Proof = "Exploit-DB commit: " + edbLink
			confirmed = append(confirmed, it)
			cveRadarLogPoC(it.ID, it.CVSS, "exploitdb", edbLink)
			continue
		}
		if searches >= pocSearchMaxPerCycle {
			pending = append(pending, cveRadarPendingItem{ID: it.ID, Desc: it.Desc, CVSS: it.CVSS, Link: it.Link, FirstSeen: nowUnix})
			continue
		}
		searches++
		if links := cveRadarPocLinks(it.ID); len(links) > 0 {
			it.Proof = strings.Join(links, " · ")
			confirmed = append(confirmed, it)
			for _, l := range links {
				cveRadarLogPoC(it.ID, it.CVSS, "github", l)
			}
		} else {
			pending = append(pending, cveRadarPendingItem{ID: it.ID, Desc: it.Desc, CVSS: it.CVSS, Link: it.Link, FirstSeen: nowUnix})
		}
	}

	// Re-check pending oldest-first: alert on PoC appearance, drop past TTL.
	var keptPending []cveRadarPendingItem
	for _, p := range pending {
		if nowUnix-p.FirstSeen > int64(cveRadarPendingTTL/time.Second) {
			continue // no public PoC within the TTL — silent drop
		}
		edbLink := edb[p.ID]
		if edbLink != "" {
			confirmed = append(confirmed, cveRadarItem{ID: p.ID, Desc: p.Desc, CVSS: p.CVSS, Link: p.Link, Proof: "Exploit-DB commit: " + edbLink})
			cveRadarLogPoC(p.ID, p.CVSS, "exploitdb", edbLink)
			continue
		}
		if searches >= 2*pocSearchMaxPerCycle {
			keptPending = append(keptPending, p)
			continue
		}
		searches++
		if links := cveRadarPocLinks(p.ID); len(links) > 0 {
			confirmed = append(confirmed, cveRadarItem{ID: p.ID, Desc: p.Desc, CVSS: p.CVSS, Link: p.Link, Proof: strings.Join(links, " · ")})
			for _, l := range links {
				cveRadarLogPoC(p.ID, p.CVSS, "github", l)
			}
		} else {
			keptPending = append(keptPending, p)
		}
	}

	if len(confirmed) > 0 {
		cveRadarNotify(confirmed, len(keptPending))
	}

	for _, it := range fresh {
		seen[it.ID] = true
	}
	cveRadarSaveSeen(seen)
	cveRadarSavePending(keptPending)
	logger.GetLogger().Infof("[CVE-RADAR] %d fresh, %d PoC-confirmed alerted, %d pending, %d searches, %d edb hits",
		len(fresh), len(confirmed), len(keptPending), searches, len(edb))
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
	headers := map[string]string{}
	if tok := cveRadarGitHubToken(); tok != "" {
		headers["Authorization"] = tok
	}
	body, err := cveRadarHTTPWithHeaders(u, headers)
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

// cveRadarPocLinks searches GitHub for public PoC repos and returns up to two
// display strings with clickable links ("owner/repo — <url> — desc").
func cveRadarPocLinks(cveID string) []string {
	q := url.Values{"q": {`"` + cveID + `"`}, "sort": {"updated"}, "per_page": {"5"}}
	headers := map[string]string{"Accept": "application/vnd.github+json"}
	if tok := cveRadarGitHubToken(); tok != "" {
		headers["Authorization"] = tok
	}
	body, err := cveRadarHTTPWithHeaders("https://api.github.com/search/repositories?"+q.Encode(), headers)
	if err != nil {
		return nil
	}
	var res struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			FullName    string `json:"full_name"`
			HTMLURL     string `json:"html_url"`
			Description string `json:"description"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &res); err != nil || res.TotalCount == 0 {
		return nil
	}
	links := make([]string, 0, 2)
	for _, it := range res.Items {
		if len(links) >= 2 {
			break
		}
		s := it.FullName + " — " + it.HTMLURL
		if d := truncateStr(it.Description, 80); d != "" {
			s += " — " + d
		}
		links = append(links, s)
	}
	if len(links) == 0 {
		links = append(links, fmt.Sprintf("%d repo(s) reference it", res.TotalCount))
	}
	return links
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
	log = append([]pocEntry{{CVE: cveID, CVSS: cvss, Source: source, Link: link,
		SeenAt: time.Now().UTC().Format(time.RFC3339)}}, log...)
	if len(log) > cveRadarPoCLogCap {
		log = log[:cveRadarPoCLogCap]
	}
	if b, err := json.Marshal(log); err == nil {
		_ = db.SetSetting(cveRadarPoCLogKey, string(b))
	}
}

// cveRadarPoll fetches both sources for everything published since `since`.
// It returns an error only when NVD failed (the authoritative feed); a GHSA
// failure degrades to an NVD-only cycle.
func cveRadarPoll(since time.Time, kwRE *regexp.Regexp) ([]cveRadarItem, error) {
	byID := map[string]cveRadarItem{}

	// --- NVD publication feed --------------------------------------------
	nvdStart := since.Add(-5*time.Minute).UTC().Format("2006-01-02T15:04:05.000") + "Z"
	nvdEnd := time.Now().UTC().Add(-time.Minute).Format("2006-01-02T15:04:05.000") + "Z"
	nvdURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate=%s&pubEndDate=%s&resultsPerPage=%d",
		url.QueryEscape(nvdStart), url.QueryEscape(nvdEnd), nvdPageLimit)
	body, err := cveRadarHTTP(nvdURL)
	if err != nil {
		return nil, fmt.Errorf("nvd: %w", err)
	}
	var nvd struct {
		Vulnerabilities []struct {
			CVE nvdCVEEntry `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &nvd); err != nil {
		return nil, fmt.Errorf("nvd decode: %w", err)
	}
	for _, v := range nvd.Vulnerabilities {
		c := v.CVE
		if c.ID == "" || strings.EqualFold(c.VulnStatus, "Rejected") {
			continue
		}
		desc := truncateStr(c.cveRadarDesc(), 600)
		score := c.cveRadarScore()
		if !cveRadarPasses(desc, score, kwRE) {
			continue
		}
		byID[c.ID] = cveRadarItem{
			ID:   c.ID,
			Desc: desc,
			CVSS: score,
			Link: "https://nvd.nist.gov/vuln/detail/" + c.ID,
		}
	}

	// --- GitHub advisories (vendor advisories often land before NVD) -------
	ghBody, err := cveRadarHTTP("https://api.github.com/advisories?per_page=100&sort=published&direction=desc")
	if err != nil {
		logger.GetLogger().Infof("[CVE-RADAR] GHSA poll failed (NVD-only cycle): %v", err)
	}
	if ghBody != nil {
		var ghsas []struct {
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
		if err := json.Unmarshal(ghBody, &ghsas); err != nil {
			logger.GetLogger().Infof("[CVE-RADAR] GHSA decode failed: %v", err)
		} else {
			for _, a := range ghsas {
				if !strings.HasPrefix(a.CVEID, "CVE-") {
					continue // the radar keys on CVE ids
				}
				pub, perr := time.Parse(time.RFC3339, a.PublishedAt)
				if perr != nil || !pub.After(since) {
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
		}
	}

	out := make([]cveRadarItem, 0, len(byID))
	for _, it := range byID {
		out = append(out, it)
	}
	return out, nil
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

// cveRadarNotify posts one Discord alert listing PoC-confirmed CVEs.
func cveRadarNotify(confirmed []cveRadarItem, pendingCount int) {
	if !utils.MonitorWebhookConfigured() {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "🛰️ **%d fresh CVE(s) with public PoC** — actionable now:\n", len(confirmed))
	listed := confirmed
	if len(listed) > cveRadarListLimit {
		listed = listed[:cveRadarListLimit]
	}
	for _, it := range listed {
		fmt.Fprintf(&b, "• **%s** — CVSS **%.1f** — <%s>", it.ID, it.CVSS, it.Link)
		if it.Proof != "" {
			fmt.Fprintf(&b, " · ⚠️ PoC: %s", it.Proof)
		}
		if ex := truncateStr(strings.ReplaceAll(it.Desc, "\n", " "), 160); ex != "" {
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
	utils.SendMonitorWebhook(b.String())
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
	if len(items) > cveRadarPendingCap {
		items = items[:cveRadarPendingCap]
	}
	b, err := json.Marshal(items)
	if err != nil {
		return
	}
	_ = db.SetSetting(cveRadarPendingKey, string(b))
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
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AutoAR-CVE-Radar/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
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
