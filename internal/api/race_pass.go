package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// ─── Race pass ────────────────────────────────────────────────────────────────
// When the template watch picks up a HIGH/CRITICAL CVE template, run it
// IMMEDIATELY against only the hosts fingerprinted as that technology —
// subdomains.techs plus hosts that historically matched templates of the same
// tech — instead of waiting for the full ~430K-host auto-run behind it. On a
// fresh 0-day this is the difference between filing in minutes and filing
// hours later (the Krafton GitLab duplicate was lost by ~23h this way).
//
// HARD RULE: a race pass NEVER submits anything to any platform. Matches are
// turned into local draft reports plus one Discord alert naming the owning
// programs and their scope status — every filing waits for explicit owner
// approval. Out-of-scope/unsure hosts are drafted exactly the same way; the
// alert only annotates what the catalog knows.
//
// The fast pass is deliberately tiny (host cap below) so it may run even while
// a global sweep is in flight; anything bigger falls back to the normal
// full-host auto-run path.
//
// Config:
//   RACE_PASS=off            — disable (settings-table kill switch wins too)
//   RACE_PASS_HOST_CAP       — max fingerprinted hosts for a pass (default 250)

const (
	racePassHostCap   = 250
	racePassTimeout   = 10 * time.Minute
	racePassThreads   = 10
	racePassIndexTTL  = 6 * time.Hour
	racePassMaxFileMB = 64
	racePassSweepMax  = 45 * time.Second

	// Max race passes queued per watch cycle: passes run one at a time (≤10 min
	// each), so a bulk template drop can't build an hours-long backlog ahead of
	// the full auto-run; the rest are logged as skipped.
	racePassMaxScansPerCycle = 2
	// How long a template revision stays in the race-pass dedupe set.
	racePassDedupeTTL = 7 * 24 * time.Hour
)

// racePassStopTags are template tags that identify a vulnerability CLASS, not a
// technology — never useful for fingerprinting hosts.
var racePassStopTags = map[string]bool{
	"cve": true, "rce": true, "lfi": true, "xss": true, "sqli": true,
	"ssrf": true, "xxe": true, "tech": true, "http": true, "file": true,
	"word": true, "default-login": true, "misconfig": true, "panel": true,
	"detect": true, "detection": true, "intrusive": true, "sane": true,
	"unauth": true, "authenticated": true, "exposure": true, "disclosure": true,
	"bypass": true, "traversal": true, "upload": true, "config": true,
	"generic": true, "packetstorm": true, "exploit": true, "edb": true,
}

var (
	racePassMu       sync.Mutex
	racePassInFlight bool

	// Race-pass queue: eligible templates run SEQUENTIALLY on one worker. Two
	// bare `go runRacePass` calls per cycle used to race the single-flight
	// flag — the second returned silently while being counted "launched".
	racePassQueueMu  sync.Mutex
	racePassQueue    []pdcpTemplate
	racePassWorkerOn bool
	// racePassQueued dedupes by revision key: a batch deferred behind a busy
	// global sweep is re-discovered every tick, and must not re-run its passes.
	racePassQueued = map[string]time.Time{}

	raceIdxMu     sync.Mutex
	raceIdxBuilt  time.Time
	raceIdxByTech = map[string]map[string]bool{} // tech kw -> set of hosts
)

// racePassEnabled reports whether the fast pass is active.
func racePassEnabled() bool {
	if v, _ := db.GetSetting("RACE_PASS"); strings.EqualFold(strings.TrimSpace(v), "off") {
		return false
	}
	return !strings.EqualFold(strings.TrimSpace(os.Getenv("RACE_PASS")), "off")
}

func racePassHostCapSetting() int {
	if v := strings.TrimSpace(os.Getenv("RACE_PASS_HOST_CAP")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return racePassHostCap
}

// racePassEligible reports whether a freshly watched template should get the
// fast-pass treatment: exploitable severity and a CVE anchor. The CVE anchor
// comes from the PDCP classification field when present, with a fallback to
// the template ID/URI — PDCP's classification index often lags the template
// itself by hours (exactly the window the race pass exists for). Like the
// full auto-run, only merged, statically safe templates qualify — an
// unreviewed PR draft never runs automatically.
func racePassEligible(t pdcpTemplate) bool {
	if racePassCVE(t) == "" || nucleiWatchAutoRunBlock(t) != "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(t.Severity)) {
	case "high", "critical":
		return strings.TrimSpace(t.Raw) != ""
	}
	return false
}

// racePassCVE resolves the CVE a template targets: classification first, then
// the template ID, then the repo URI (http/cves/2026/CVE-2026-1234.yaml).
func racePassCVE(t pdcpTemplate) string {
	if len(t.Class.CVEs) > 0 && strings.HasPrefix(t.Class.CVEs[0], "CVE-") {
		return t.Class.CVEs[0]
	}
	cveRe := regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	if m := cveRe.FindString(t.ID); m != "" {
		return m
	}
	return cveRe.FindString(t.URI)
}

// raceTechKeywords extracts the technology-identifying tags from a template,
// dropping the vulnerability-class noise.
func raceTechKeywords(t pdcpTemplate) []string {
	var out []string
	seen := map[string]bool{}
	for _, tag := range t.Tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" || racePassStopTags[tag] || seen[tag] {
			continue
		}
		seen[tag] = true
		out = append(out, tag)
	}
	return out
}

// raceFingerprintedHosts unions every host whose stored fingerprint (tech
// stack, title, server header) or historical nuclei matches mention one of
// the keywords. Second return is the
// keyword that produced each host (for the alert).
func raceFingerprintedHosts(keywords []string) (map[string]string, error) {
	hostSrc := map[string]string{}
	for _, kw := range keywords {
		// 1. Stored fingerprints: httpx tech stack, page title, server header.
		matched, _, err := db.MatchHostsByFingerprint([]string{kw}, racePassHostCapSetting()*2+1)
		if err != nil {
			return hostSrc, err
		}
		for _, h := range matched {
			if h.URL == "" {
				continue
			}
			if _, dup := hostSrc[h.URL]; !dup {
				hostSrc[h.URL] = firstNonEmptyStr(h.Via, "techs:"+kw)
			}
		}
		// 2. Historical nuclei hits on same-tech templates (cached index) —
		// only hosts that are STILL live subdomains in the DB. The index is
		// built from old result files on disk, which outlive deleted domains
		// (ended programs) and hosts that went dark; those must never be
		// scanned again.
		for _, host := range raceLiveHistoricalHosts(raceHistoricalHosts(kw)) {
			if _, dup := hostSrc[host]; !dup {
				hostSrc[host] = "hist:" + kw
			}
		}
		if len(hostSrc) > racePassHostCapSetting()*2 {
			break // plenty of signal; more keywords won't change the verdict
		}
	}
	return hostSrc, nil
}

// raceLiveHistoricalHosts keeps the historical hosts whose bare hostname is
// still a live subdomain in the DB. Fails closed: if the DB can't answer, no
// historical host is used (the stored-techs hosts still are).
func raceLiveHistoricalHosts(hist map[string]bool) []string {
	if len(hist) == 0 {
		return nil
	}
	bare := make(map[string]string, len(hist)) // historical host -> bare hostname
	names := make([]string, 0, len(hist))
	for h := range hist {
		b := strings.ToLower(raceHostOf(h))
		if b == "" {
			continue
		}
		bare[h] = b
		names = append(names, b)
	}
	live, err := db.FilterLiveSubdomains(names)
	if err != nil {
		logger.GetLogger().Infof("[RACE-PASS] live check of %d historical host(s) failed — skipping them: %v", len(names), err)
		return nil
	}
	out := make([]string, 0, len(live))
	for h, b := range bare {
		if live[b] {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

// raceHistoricalHosts returns hosts that ever matched a nuclei template whose
// ID contains the keyword, from the cached result-file index.
func raceHistoricalHosts(kw string) map[string]bool {
	raceIdxMu.Lock()
	defer raceIdxMu.Unlock()
	if time.Since(raceIdxBuilt) > racePassIndexTTL {
		raceIdxByTech = map[string]map[string]bool{}
		raceIdxBuilt = time.Now()
		raceBuildIndex()
	}
	return raceIdxByTech[kw]
}

// raceBuildIndex sweeps historical nuclei result JSONL for (template-id, host)
// pairs. Bounded: files over racePassMaxFileMB are skipped and the whole sweep
// is time-budgeted so a huge results dir can't stall the watch cycle. Must be
// called with raceIdxMu held.
func raceBuildIndex() {
	deadline := time.Now().Add(racePassSweepMax)
	roots := []string{
		filepath.Join(utils.GetResultsDir(), "global-subdomains", "vulnerabilities"),
	}
	for _, root := range roots {
		files, err := filepath.Glob(filepath.Join(root, "*.json"))
		if err != nil {
			continue
		}
		for _, f := range files {
			if time.Now().After(deadline) {
				logger.GetLogger().Infof("[RACE-PASS] history index hit its time budget — partial index in use")
				return
			}
			st, err := os.Stat(f)
			if err != nil || st.IsDir() || st.Size() > racePassMaxFileMB*1024*1024 {
				continue
			}
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "{") {
					continue
				}
				var ev struct {
					TemplateID string `json:"template-id"`
					Host       string `json:"host"`
				}
				if json.Unmarshal([]byte(line), &ev) != nil || ev.TemplateID == "" || ev.Host == "" {
					continue
				}
				id := strings.ToLower(ev.TemplateID)
				for _, kw := range raceIndexKeywordsFor(id) {
					if raceIdxByTech[kw] == nil {
						raceIdxByTech[kw] = map[string]bool{}
					}
					raceIdxByTech[kw][ev.Host] = true
				}
			}
		}
	}
}

// raceIndexKeywordsFor derives tech keywords from a historical template ID by
// splitting on non-alphanumerics and dropping short/generic tokens.
var raceIndexTokenDrop = map[string]bool{
	"cve": true, "default": true, "login": true, "exposure": true,
	"detect": true, "panel": true, "unauth": true, "rce": true, "lfi": true,
	"xss": true, "sqli": true, "ssrf": true, "http": true, "file": true,
	"read": true, "missing": true, "patch": true,
}

func raceIndexKeywordsFor(templateID string) []string {
	tokens := strings.FieldsFunc(templateID, func(r rune) bool {
		return !('a' <= r && r <= 'z') && !('0' <= r && r <= '9')
	})
	var out []string
	for _, tok := range tokens {
		if len(tok) < 4 || raceIndexTokenDrop[tok] {
			continue
		}
		out = append(out, tok)
	}
	return out
}

// racePassEnqueue queues the race-eligible templates of a watch batch (at
// most racePassMaxScansPerCycle new ones) for the single sequential worker.
// Revisions already queued/passed are skipped, and every skip is logged.
func racePassEnqueue(batch []pdcpTemplate) {
	now := time.Now()
	eligible, queued := 0, 0
	racePassQueueMu.Lock()
	for k, at := range racePassQueued {
		if now.Sub(at) > racePassDedupeTTL {
			delete(racePassQueued, k)
		}
	}
	for _, t := range batch {
		if !racePassEligible(t) {
			continue
		}
		eligible++
		key := nucleiTemplateRevKey(t.ID, t.Raw)
		if _, dup := racePassQueued[key]; dup {
			continue // same revision already queued/passed (deferred batch re-discovered)
		}
		if queued >= racePassMaxScansPerCycle {
			logger.GetLogger().Infof("[RACE-PASS] %s (%s) skipped — %d fast pass(es) already queued this cycle; the full auto-run covers it",
				racePassCVE(t), t.ID, racePassMaxScansPerCycle)
			continue
		}
		racePassQueued[key] = now
		racePassQueue = append(racePassQueue, t)
		queued++
		logger.GetLogger().Infof("[RACE-PASS] %s (%s, %s) is race-eligible — fast pass queued (%d in queue)",
			racePassCVE(t), t.ID, t.Severity, len(racePassQueue))
	}
	start := len(racePassQueue) > 0 && !racePassWorkerOn
	if start {
		racePassWorkerOn = true
	}
	racePassQueueMu.Unlock()
	if eligible > 0 {
		logger.GetLogger().Infof("[RACE-PASS] %d race-eligible template(s) in batch, %d newly queued", eligible, queued)
	}
	if start {
		utils.SafeGo("race-pass:worker", racePassWorker)
	}
}

// racePassWorker drains the queue one pass at a time, then exits; the next
// enqueue starts a new worker (racePassWorkerOn is only flipped under the
// queue lock, so no enqueue is ever stranded).
func racePassWorker() {
	defer func() {
		if r := recover(); r != nil {
			racePassQueueMu.Lock()
			racePassWorkerOn = false
			racePassQueueMu.Unlock()
			panic(r) // re-raised into SafeGo's recovery for the stack log
		}
	}()
	for {
		racePassQueueMu.Lock()
		if len(racePassQueue) == 0 {
			racePassWorkerOn = false
			racePassQueueMu.Unlock()
			return
		}
		t := racePassQueue[0]
		racePassQueue = racePassQueue[1:]
		racePassQueueMu.Unlock()
		utils.GuardedRun("race-pass:"+racePassCVE(t), func() { runRacePass(t) })
	}
}

// runRacePass executes one fast pass for an eligible template. Called by the
// sequential racePassWorker; the single-flight guard stays as a backstop.
func runRacePass(t pdcpTemplate) {
	defer utils.RecoverPanic("race-pass:" + racePassCVE(t))
	racePassMu.Lock()
	if racePassInFlight {
		racePassMu.Unlock()
		logger.GetLogger().Infof("[RACE-PASS] %s (%s) skipped — another race pass is in flight", racePassCVE(t), t.ID)
		return
	}
	racePassInFlight = true
	racePassMu.Unlock()
	defer func() {
		racePassMu.Lock()
		racePassInFlight = false
		racePassMu.Unlock()
	}()

	cve := racePassCVE(t)
	keywords := raceTechKeywords(t)
	if len(keywords) == 0 {
		logger.GetLogger().Infof("[RACE-PASS] %s (%s): no technology tags to fingerprint hosts by (tags %v) — skipped; full auto-run covers it", cve, t.ID, t.Tags)
		return
	}
	hosts, err := raceFingerprintedHosts(keywords)
	if err != nil {
		logger.GetLogger().Infof("[RACE-PASS] %s fingerprint lookup failed: %v", cve, err)
		return
	}
	hostCap := racePassHostCapSetting()
	if len(hosts) == 0 {
		logger.GetLogger().Infof("[RACE-PASS] %s: no fingerprinted hosts for %v — full auto-run covers it", cve, keywords)
		return
	}
	if len(hosts) > hostCap {
		logger.GetLogger().Infof("[RACE-PASS] %s: %d fingerprinted hosts exceeds cap %d — skipping fast pass", cve, len(hosts), hostCap)
		return
	}

	scanID := "race-" + strings.ToLower(strings.ReplaceAll(cve, "CVE-", "cve-")) + "-" + time.Now().Format("20060102150405")
	hostList := make([]string, 0, len(hosts))
	for host := range hosts {
		hostList = append(hostList, host)
	}
	sort.Strings(hostList)
	logger.GetLogger().Infof("[RACE-PASS] %s: running %s against %d fingerprinted host(s) (scan %s)",
		cve, t.ID, len(hosts), scanID)
	utils.SendMonitorWebhook(fmt.Sprintf(
		"⚡ **Race pass** — `%s` (%s) against **%d** fingerprinted host(s) (scan `%s`) — full auto-run continues independently.",
		cve, nucleiSafeToken(t.ID), len(hosts), scanID))
	res := runTargetedPassFn(targetedPassSpec{
		ScanID: scanID, CVE: cve, Raw: t.Raw, FileName: strings.ToLower(cve) + ".yaml",
		Hosts: hostList, Threads: racePassThreads, Timeout: racePassTimeout, Actor: "system",
	})
	matches, runErr, fnRan := res.Matches, res.Err, res.Ran

	// Never report "done — 0 matches" for a pass that didn't (fully) run: the
	// scan record failing, a template that didn't compile, or the 10-minute
	// budget all used to look exactly like a clean miss.
	if !fnRan {
		utils.SendMonitorWebhook(fmt.Sprintf(
			"⚠️ **Race pass did not run** — `%s`: the scan record could not be created (scan `%s`). The full auto-run still covers it.", cve, scanID))
		return
	}
	if runErr != nil {
		status := "FAILED"
		if len(matches) > 0 || errors.Is(runErr, context.DeadlineExceeded) || errors.Is(runErr, context.Canceled) {
			status = "PARTIAL"
		}
		utils.SendMonitorWebhook(fmt.Sprintf(
			"⚠️ **Race pass %s** — `%s`: %s — %d match(es) before it stopped, %d fingerprinted host(s) (scan `%s`). The full auto-run still covers it.",
			status, cve, utils.DiscordEscapeTrunc(runErr.Error(), 300), len(matches), len(hosts), scanID))
		if len(matches) > 0 {
			raceNotifyMatches(cve, t.ID, scanID, matches)
		}
		return
	}
	if len(matches) == 0 {
		utils.SendMonitorWebhook(fmt.Sprintf(
			"🏁 **Race pass done** — `%s`: 0 matches on %d fingerprinted host(s) (scan `%s`).", cve, len(hosts), scanID))
		return
	}
	raceNotifyMatches(cve, t.ID, scanID, matches)
}

// raceMatch is one nuclei hit from a race pass.
type raceMatch struct {
	TemplateID, Matched, Curl, Severity string
}

// raceNotifyMatches turns every match into a local draft + one Discord alert
// naming the owning programs. It NEVER submits anything anywhere.
func raceNotifyMatches(cve, templateID, scanID string, matches []raceMatch) {
	draftDir := filepath.Join(utils.GetResultsDir(), "race-drafts", strings.ToLower(cve))
	os.MkdirAll(draftDir, 0o755)

	var b strings.Builder
	fmt.Fprintf(&b, "🚨 **RACE PASS MATCHES — `%s`** (%s, scan `%s`)\n", cve, nucleiSafeToken(templateID), scanID)
	fmt.Fprintf(&b, "⏸ **NOTHING will be submitted — drafts staged, awaiting owner approval**\n")
	for _, m := range matches {
		host := raceHostOf(m.Matched)
		programs := raceProgramsForHost(host)
		verdict := "no catalog match — unsure scope"
		progLine := ""
		if len(programs) > 0 {
			p := programs[0]
			switch {
			case !p.InScope:
				verdict = "catalog-listed OUT of scope"
			case catalogProgramInactive(programPauseStates(), p) != "":
				verdict = "program " + catalogProgramInactive(programPauseStates(), p) + " — not accepting submissions"
			default:
				verdict = "IN SCOPE"
			}
			progLine = fmt.Sprintf(" — %s `%s`", discordSpanText(p.Source, 20), discordSpanText(p.Handle, 80))
		}
		draftPath := raceStageDraft(cve, templateID, host, m, programs, draftDir)
		fmt.Fprintf(&b, "• %s — %s%s\n  📄 draft: `%s`\n", discordCode(m.Matched, 300), verdict, progLine, draftPath)
	}
	utils.SendMonitorWebhook(b.String())
	logger.GetLogger().Infof("[RACE-PASS] %s: %d match(es) drafted to %s", cve, len(matches), draftDir)
}

// raceStageDraft writes the pre-filled report draft for one match and returns
// its path. The draft is deliberately complete: owner approval is the only
// remaining step before filing.
func raceStageDraft(cve, templateID, host string, m raceMatch, programs []db.CatalogDomainMatch, draftDir string) string {
	safe := regexp.MustCompile(`[^a-zA-Z0-9._-]`).ReplaceAllString(host, "_")
	path := filepath.Join(draftDir, safe+".md")
	var b strings.Builder
	b.WriteString("# DRAFT — NOT SUBMITTED — awaiting owner approval\n\n")
	b.WriteString("**Auto-staged by the race pass. No platform submission happens without explicit owner approval.**\n\n")
	fmt.Fprintf(&b, "**CVE:** %s\n**Template:** %s\n**Host:** %s\n**Severity reported by template:** %s\n\n",
		cve, templateID, host, m.Severity)
	if len(programs) > 0 {
		b.WriteString("**Catalog program matches:**\n")
		for _, p := range programs {
			state := "in_scope"
			if !p.InScope {
				state = "OUT of scope"
			}
			fmt.Fprintf(&b, "- %s `%s` — matched domain `%s` (%s)\n", p.Source, p.Handle, p.MatchedDomain, state)
		}
	} else {
		b.WriteString("**Catalog program matches:** none — unsure scope, choose a channel manually.\n")
	}
	b.WriteString("\n## Evidence\n\n```bash\n")
	b.WriteString(m.Curl)
	b.WriteString("\n```\n\nMatched-At: `")
	b.WriteString(m.Matched)
	b.WriteString("`\n\n## Next steps (owner)\n\n1. Validate live with the curl above (benign replay).\n")
	b.WriteString("2. Check scope wording in the matched program (wildcards, exclusions, <30d-CVE rules).\n")
	b.WriteString("3. Approve filing — then submit manually or ask the automation with an explicit instruction.\n")
	_ = os.WriteFile(path, []byte(b.String()), 0o644)
	return path
}

// raceProgramsForHost resolves the catalog programs whose scope COVERS a
// matched host: an exact host entry or a "*." wildcard over one of its
// parents, out-of-scope entries taking precedence (db.SearchCatalogByDomain).
// Programs that merely list a parent host are dropped — app.acme.com in scope
// says nothing about x.acme.com. Order: in scope and accepting submissions,
// then in scope but paused/closed, then out of scope.
func raceProgramsForHost(host string) []db.CatalogDomainMatch {
	matches, err := db.SearchCatalogByDomain(host, 20)
	if err != nil {
		return nil
	}
	var live, paused, oos []db.CatalogDomainMatch
	var states map[string]string
	for _, m := range matches {
		switch {
		case m.MatchKind == db.CatalogMatchRelated:
			continue
		case !m.InScope:
			oos = append(oos, m)
		default:
			if states == nil {
				states = programPauseStates()
			}
			if catalogProgramInactive(states, m) != "" {
				paused = append(paused, m)
			} else {
				live = append(live, m)
			}
		}
	}
	return append(append(live, paused...), oos...)
}

// catalogProgramInactive returns "paused"/"closed" when the program-watch
// pause map (fed by the platforms' submission state) says the catalog
// program is not accepting submissions, "" otherwise.
func catalogProgramInactive(states map[string]string, m db.CatalogDomainMatch) string {
	switch st := states[strings.ToLower(m.Source+"|"+m.Handle)]; st {
	case "paused", "closed":
		return st
	}
	return ""
}

// raceHostOf reduces a matched-at URL to its bare host (port stripped when a
// numeric port suffix is present; bare IPv6 literals may lose their tail — a
// harmless edge for catalog lookups).
func raceHostOf(matched string) string {
	h := matched
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		suffix := h[i+1:]
		port := suffix != ""
		for j := 0; j < len(suffix) && port; j++ {
			if suffix[j] < '0' || suffix[j] > '9' {
				port = false
			}
		}
		if port {
			h = h[:i]
		}
	}
	return h
}

// raceScopeTag renders the catalog verdict for a hit's host as one webhook
// line: 🟢 in-scope program, ⏸ in scope but the program is paused/closed,
// 🔴 catalog-listed but out of scope, ⚪ no covering program at all. Shared by
// the per-hit webhook in runGlobalNucleiScan so reportable hits are
// distinguishable from unreportable ones without opening the dashboard.
// programs comes from raceProgramsForHost (covering matches only, best first).
func raceScopeTag(programs []db.CatalogDomainMatch) string {
	if len(programs) == 0 {
		return "⚪ no program match"
	}
	p := programs[0]
	if p.InScope {
		if st := catalogProgramInactive(programPauseStates(), p); st != "" {
			return fmt.Sprintf("⏸ program %s — %s `%s` (in scope, not accepting submissions)", st, p.Source, discordSpanText(p.Handle, 80))
		}
		return fmt.Sprintf("🟢 IN SCOPE — %s `%s`", p.Source, discordSpanText(p.Handle, 80))
	}
	return fmt.Sprintf("🔴 catalog OOS — %s `%s`", p.Source, discordSpanText(p.Handle, 80))
}
