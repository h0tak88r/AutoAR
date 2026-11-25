package api

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/utils"
	"github.com/tidwall/gjson"
)

// ─── Passive program-scope watch ───────────────────────────────────────────────
// Instead of polling each program's full scope on a rolling schedule, this watch
// piggybacks on the data the fetchers already return. Every refresh it looks at
// programs[*].LatestTargetUpdatedAt — the most recent in-scope target update
// time — and:
//
//   * On the first refresh of this process: sends a "📌 Most recent scope update"
//     intro to the Discord webhook so the operator immediately sees the watch is
//     alive (and what the current freshest update is).
//   * Whenever a program's LatestTargetUpdatedAt is newer than the value last
//     processed FOR THAT PROGRAM, classifies the change against the program's
//     scope fingerprint and posts a Discord alert.
//
// The state is PER PROGRAM (settings key programWatchLastSeenKey). It used to be
// one global watermark = the freshest timestamp of any program: the 5-minute
// loop (HA/YWH/IT list timestamps, ~now) kept pushing it forward, so when the
// 2h warmer finally carried an H1/BC scope timestamp T it was already below the
// watermark and the addition was silently never alerted.

const (
	// programWatchWatermarkKey is informational only now (status UI): the
	// freshest timestamp the watch has processed.
	programWatchWatermarkKey = "program_watch_latest_seen"
	// programWatchLastSeenKey holds watchLastSeen (per-program last-processed
	// timestamps + per-platform baseline times).
	programWatchLastSeenKey  = "PROGRAM_WATCH_LAST_SEEN"
	programWatchMaxAlertsCyc = 10 // cap on SENT scope alerts per refresh so a one-time corpus shift can't flood
	// programWatchPruneAfter drops per-program state for programs absent from
	// every snapshot this long (left the platform / lost access).
	programWatchPruneAfter = 30 * 24 * time.Hour
)

var (
	programWatchMu        sync.Mutex
	programWatchIntroSent bool      // process-local: send intro once per boot
	programWatchSessionN  int       // alerts fired since process start
	programWatchLastAt    time.Time // last refresh tick
	// programWatchSend delivers one watch message (swapped out in tests).
	programWatchSend = utils.SendScopeWebhookErr
)

// programWatchEnabled returns whether the watch should act on a refresh. It's a
// no-op when no webhook is configured or PROGRAM_MONITOR=off.
func programWatchEnabled() bool {
	if !utils.MonitorWebhookConfigured() {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("PROGRAM_MONITOR")), "off") {
		return false
	}
	return true
}

// canonicalWatchPlatform maps platform names/aliases to the ProgramSummary
// platform codes.
func canonicalWatchPlatform(s string) string {
	switch s = strings.ToLower(strings.TrimSpace(s)); s {
	case "h1", "hackerone":
		return "h1"
	case "bc", "bugcrowd":
		return "bc"
	case "it", "intigriti":
		return "it"
	case "ywh", "yeswehack":
		return "ywh"
	case "ha", "hackadvisor", "external":
		return "ha"
	}
	return s
}

// programWatchPlatformAllowed filters by PROGRAM_MONITOR_PLATFORMS (csv of
// h1,bc,it,ywh,ha — full names accepted). Empty allows all. Whole tokens, not
// substrings.
func programWatchPlatformAllowed(platform string) bool {
	allow := strings.TrimSpace(os.Getenv("PROGRAM_MONITOR_PLATFORMS"))
	if allow == "" {
		return true
	}
	want := canonicalWatchPlatform(platform)
	for _, tok := range strings.FieldsFunc(allow, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		if canonicalWatchPlatform(tok) == want {
			return true
		}
	}
	return false
}

// StartProgramWatchFastLoop feeds the watch from lightweight program-LIST
// fetches (no per-program scope enrichment), independent of the full cache
// refresh. The full refresh is expensive (~20 min: it pulls every program's
// scope) and rests 2h between runs, which made watch alerts lag by hours. This
// loop runs the cheap list fetch every PROGRAM_WATCH_INTERVAL (default 5m,
// minimum 1m) and owns the pause/return/new-program diff (its submission
// states are minutes old, the warmer's ~20).
func StartProgramWatchFastLoop() {
	go func() {
		defer utils.RecoverPanic("program-watch-fast")
		for {
			utils.GuardedRun("program-watch-fast:tick", func() {
				if programWatchEnabled() {
					start := time.Now()
					progs := fetchProgramsLight()
					if len(progs) > 0 {
						programWatchFastCheck(progs)
						logger.GetLogger().Infof("[PROGRAM-WATCH] fast check: %d programs in %s", len(progs), time.Since(start).Round(time.Second))
					}
				}
			})
			time.Sleep(programWatchFastInterval())
		}
	}()
}

// programWatchFastInterval resolves the fast-loop period from
// PROGRAM_WATCH_INTERVAL (e.g. "90s", "5m", "10m"). Floor of one minute so a
// typo can't turn this into a platform-API hammer.
func programWatchFastInterval() time.Duration {
	if d, err := time.ParseDuration(strings.TrimSpace(os.Getenv("PROGRAM_WATCH_INTERVAL"))); err == nil && d >= time.Minute {
		return d
	}
	return 5 * time.Minute
}

// fetchProgramsLight fetches every platform's program list WITHOUT scope
// enrichment — a handful of paginated list calls total instead of thousands of
// per-program scope requests.
func fetchProgramsLight() []ProgramSummary {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var all []ProgramSummary
	add := func(progs []ProgramSummary, err error, platform string) {
		if err != nil {
			logger.GetLogger().Infof("[PROGRAM-WATCH] light %s fetch failed: %v", platform, err)
			return
		}
		if platform == "it" {
			// The IT list's lastUpdatedAt is PROGRAM-level (bounty bump, text
			// edit) and has no asset list behind it; feeding it to the scope
			// watch would advance IT programs past their real asset-level scope
			// timestamps (warmer) and swallow genuine additions. IT scope
			// changes are judged on the warmer's asset-level timestamps.
			for i := range progs {
				progs[i].LatestTargetUpdatedAt = ""
			}
		}
		mu.Lock()
		all = append(all, progs...)
		mu.Unlock()
	}

	fetchers := []struct {
		platform string
		fetch    func(bool, bool) ([]ProgramSummary, error)
	}{
		{"h1", fetchH1Programs}, {"bc", fetchBCPrograms}, {"it", fetchITPrograms}, {"ywh", fetchYWHPrograms},
	}
	for _, f := range fetchers {
		f := f
		wg.Add(1)
		utils.SafeGo("program-watch-light:"+f.platform, func() {
			defer wg.Done()
			p, e := f.fetch(true, false)
			add(p, e, f.platform)
		})
	}
	wg.Wait()

	// HackAdvisor: single-arg fetch, list already carries scope timestamps.
	utils.GuardedRun("program-watch-light:hackadvisor", func() {
		progs, err := fetchHackAdvisorPrograms(true)
		add(progs, err, "hackadvisor")
	})

	return all
}

// programWatchFastCheck is the fast loop's entry: pause/return/new-program
// diff plus the scope watch.
func programWatchFastCheck(programs []ProgramSummary) {
	programWatchMu.Lock()
	defer programWatchMu.Unlock()
	programWatchLastAt = time.Now()
	if !programWatchEnabled() {
		return
	}
	// Pause/return detection runs on the FULL program list (not just scope
	// candidates) and regardless of scope timestamps — a program that pauses
	// without touching its scope must still announce.
	programWatchPauseDiff(programs, time.Now())
	programWatchScope(programs, time.Now())
}

// ProgramWatchOnRefresh is called by the warmer after every cache rebuild. It
// runs the scope watch only: the warmer's submission states are ~20 minutes
// old by the time it finishes, and diffing them against the fast loop's
// fresher states made ⏸/▶️ alerts flap. Safe to call with an empty slice.
func ProgramWatchOnRefresh(programs []ProgramSummary) {
	programWatchMu.Lock()
	defer programWatchMu.Unlock()
	programWatchLastAt = time.Now()
	if !programWatchEnabled() {
		return
	}
	programWatchScope(programs, time.Now())
}

// ─── Per-program scope watch state ─────────────────────────────────────────────

// watchSeenEntry is one program's last processed LatestTargetUpdatedAt (U)
// and when the program was last present in a snapshot (S, unix; refreshed at
// most daily so the settings row doesn't churn every cycle).
type watchSeenEntry struct {
	U string `json:"u"`
	S int64  `json:"s"`
}

type watchLastSeen struct {
	Programs map[string]watchSeenEntry `json:"programs"`
	// Baselines: platform → unix time its programs were first recorded. A
	// program first seen later on a baselined platform alerts only when its
	// timestamp is after that time (a change made while we were watching).
	Baselines map[string]int64 `json:"baselines"`
}

func loadWatchLastSeen() *watchLastSeen {
	st := &watchLastSeen{}
	if v, _ := db.GetSetting(programWatchLastSeenKey); v != "" {
		_ = json.Unmarshal([]byte(v), st)
	}
	if st.Programs == nil {
		st.Programs = map[string]watchSeenEntry{}
	}
	if st.Baselines == nil {
		st.Baselines = map[string]int64{}
	}
	return st
}

func saveWatchLastSeen(st *watchLastSeen, now time.Time) {
	cutoff := now.Add(-programWatchPruneAfter).Unix()
	for k, e := range st.Programs {
		if e.S < cutoff {
			delete(st.Programs, k)
		}
	}
	if b, err := json.Marshal(st); err == nil {
		_ = db.SetSetting(programWatchLastSeenKey, string(b))
	}
}

// programTimeAfter reports whether an ISO timestamp is after a unix time.
func programTimeAfter(iso string, unix int64) bool {
	t, ok := parseProgramTime(iso)
	return ok && t.Unix() > unix
}

type watchCandidate struct {
	p       ProgramSummary
	key     string
	verdict watchVerdict
	fp      string
	seen    bool // the watch had a fingerprint for this program before
}

// programWatchScope is the scope-update core shared by both loops (caller
// holds programWatchMu). Every program is compared against ITS OWN last
// processed timestamp; all updates are classified BEFORE the alert cap is
// applied, and a program is only advanced once it was announced or judged
// not worth announcing — capped or undecidable ones stay pending for the next
// cycle instead of being silently skipped.
func programWatchScope(programs []ProgramSummary, now time.Time) {
	st := loadWatchLastSeen()
	fps := programWatchLoadFPs()
	stChanged, fpChanged := false, false
	nowUnix := now.Unix()

	// A platform's first snapshot with usable timestamps baselines silently.
	newlyBaselined := map[string]bool{}
	for _, p := range programs {
		if p.LatestTargetUpdatedAt == "" || !programWatchPlatformAllowed(p.Platform) {
			continue
		}
		if _, ok := st.Baselines[p.Platform]; !ok && !newlyBaselined[p.Platform] {
			st.Baselines[p.Platform] = nowUnix
			newlyBaselined[p.Platform] = true
			stChanged = true
		}
	}

	var updates []watchCandidate
	var freshest *ProgramSummary
	for i := range programs {
		p := programs[i]
		if !programWatchPlatformAllowed(p.Platform) || p.Handle == "" {
			continue
		}
		key := p.Platform + "|" + p.Handle
		prev, known := st.Programs[key]
		isUpdate := false
		if p.LatestTargetUpdatedAt != "" {
			if freshest == nil || isNewerProgramTime(p.LatestTargetUpdatedAt, freshest.LatestTargetUpdatedAt) {
				freshest = &programs[i]
			}
			switch {
			case known:
				isUpdate = isNewerProgramTime(p.LatestTargetUpdatedAt, prev.U)
			case newlyBaselined[p.Platform]:
			default:
				isUpdate = programTimeAfter(p.LatestTargetUpdatedAt, st.Baselines[p.Platform])
			}
		}
		if isUpdate {
			prevFP, seen := fps[key]
			v, fp := classifyWatch(p, prevFP, seen)
			updates = append(updates, watchCandidate{p: p, key: key, verdict: v, fp: fp, seen: seen})
			continue
		}
		// Not an update: record presence/timestamp and keep the fingerprint in
		// step with the current asset set (an asset removed without a timestamp
		// bump must not make the next real edit look like a new scope).
		if p.LatestTargetUpdatedAt != "" {
			e := prev
			if !known || isNewerProgramTime(p.LatestTargetUpdatedAt, e.U) {
				e.U = p.LatestTargetUpdatedAt
			}
			if nowUnix-e.S > 86400 {
				e.S = nowUnix
			}
			if !known || e != prev {
				st.Programs[key] = e
				stChanged = true
			}
		}
		if fp := mergeWatchFP(fps[key], p); fp != "" && fp != fps[key] {
			fps[key] = fp
			fpChanged = true
		}
		// Scope autopilot: keep this program's asset snapshot current so the
		// next real update diffs against it.
		scopeAutopilotObserveSeam(p, false, true)
	}

	// Boot intro: one message per process so the operator sees the watch is alive
	// right after every container rebuild.
	if !programWatchIntroSent && freshest != nil {
		programWatchIntroSent = true
		sendProgramIntroDiscord(*freshest)
	}

	// 🆕 before ✏️, freshest first within each, so the capped alerts are the
	// most important ones; the rest stay pending for the next cycle.
	sort.SliceStable(updates, func(i, j int) bool {
		if ni, nj := updates[i].verdict == watchNewScope, updates[j].verdict == watchNewScope; ni != nj {
			return ni
		}
		return isNewerProgramTime(updates[i].p.LatestTargetUpdatedAt, updates[j].p.LatestTargetUpdatedAt)
	})
	advance := func(u watchCandidate) {
		st.Programs[u.key] = watchSeenEntry{U: u.p.LatestTargetUpdatedAt, S: nowUnix}
		stChanged = true
		if u.fp != "" && u.fp != fps[u.key] {
			fps[u.key] = u.fp
			fpChanged = true
		}
	}
	sent, suppressed, deferred, capped := 0, 0, 0, 0
	for _, u := range updates {
		switch u.verdict {
		case watchDefer:
			deferred++ // left pending for the loop that carries the asset list
			continue
		case watchSkip:
			suppressed++
			advance(u)
			scopeAutopilotObserveSeam(u.p, false, u.seen)
			continue
		case watchAssetTouched:
			if !programWatchAssetTouchEnabled() {
				suppressed++
				advance(u)
				scopeAutopilotObserveSeam(u.p, false, u.seen)
				continue
			}
		}
		if sent >= programWatchMaxAlertsCyc {
			capped++ // not advanced: announced on a later cycle
			continue
		}
		if u.verdict == watchNewScope {
			sendProgramUpdateDiscord(u.p)
		} else {
			sendAssetTouchDiscord(u.p)
		}
		sent++
		advance(u)
		// New scope: the assets added since the last snapshot go to the
		// autopilot (it diffs, plans and launches on its own loop).
		scopeAutopilotObserveSeam(u.p, u.verdict == watchNewScope, u.seen)
	}
	if suppressed > 0 || deferred > 0 || capped > 0 {
		logger.GetLogger().Infof("[PROGRAM-WATCH] %d scope update(s): %d alerted, %d suppressed (no real change / closed / empty), %d deferred to the asset-carrying refresh, %d capped to a later cycle",
			len(updates), sent, suppressed, deferred, capped)
	}

	if stChanged {
		saveWatchLastSeen(st, now)
	}
	if fpChanged {
		programWatchSaveFPs(fps, st)
	}
	// Informational watermark for the status UI.
	if freshest != nil {
		if wm, _ := db.GetSetting(programWatchWatermarkKey); isNewerProgramTime(freshest.LatestTargetUpdatedAt, wm) {
			_ = db.SetSetting(programWatchWatermarkKey, freshest.LatestTargetUpdatedAt)
		}
	}
}

// ProgramWatchCheckProgram fires the watch for a SINGLE program — used when a
// force-refreshed scope summary comes back (e.g. user searched the Programs page
// for "ryan-bbp"). If the program's latest_target_updated_at is newer than the
// value last processed for THAT program, alert immediately and advance only
// that program — other programs' state is untouched (it used to jump the one
// global watermark to this program's time). Bypasses the boot intro and the
// per-cycle cap.
func ProgramWatchCheckProgram(p ProgramSummary) {
	if !programWatchEnabled() || !programWatchPlatformAllowed(p.Platform) {
		return
	}
	if p.LatestTargetUpdatedAt == "" || p.Handle == "" {
		return
	}
	programWatchMu.Lock()
	defer programWatchMu.Unlock()
	st := loadWatchLastSeen()
	base, baselined := st.Baselines[p.Platform]
	if !baselined {
		// No baseline yet — let the regular refresh path establish it silently
		// (otherwise the first search after a fresh install would alert on
		// whatever happened to be cached).
		return
	}
	key := p.Platform + "|" + p.Handle
	now := time.Now()
	prev, known := st.Programs[key]
	if (known && !isNewerProgramTime(p.LatestTargetUpdatedAt, prev.U)) || (!known && !programTimeAfter(p.LatestTargetUpdatedAt, base)) {
		if !known {
			st.Programs[key] = watchSeenEntry{U: p.LatestTargetUpdatedAt, S: now.Unix()}
			saveWatchLastSeen(st, now)
		}
		return
	}
	fps := programWatchLoadFPs()
	prevFP, seen := fps[key]
	v, fp := classifyWatch(p, prevFP, seen)
	switch v {
	case watchDefer:
		return // the next asset-carrying refresh decides
	case watchNewScope:
		sendProgramUpdateDiscord(p)
	case watchAssetTouched:
		if programWatchAssetTouchEnabled() {
			sendAssetTouchDiscord(p)
		}
	}
	scopeAutopilotObserveSeam(p, v == watchNewScope, seen)
	st.Programs[key] = watchSeenEntry{U: p.LatestTargetUpdatedAt, S: now.Unix()}
	saveWatchLastSeen(st, now)
	if fp != "" && fp != prevFP {
		fps[key] = fp
		programWatchSaveFPs(fps, st)
	}
}

// programWatchFPKey is the settings key holding per-program scope fingerprints
// (platform|handle -> see watchFP). A timestamp bump with an unchanged
// fingerprint is churn (ended Standoff programs do this constantly) and must
// not be announced as a new scope.
const programWatchFPKey = "PROGRAM_WATCH_FP"

// ─── Pause / return detection ─────────────────────────────────────────────────
// Owner directive 2026-09-29: alert when a program pauses AND when it comes
// back. SubmissionState is already fetched for h1 (submission_state: open /
// paused / closed), bc (accessStatus), and ywh (status "V" → open, else
// closed); the fast loop diffs each program's state against the persisted
// previous and announces the transition on the new-scopes channel. First
// sighting of a program on an already-baselined platform/account is a 🆕 new
// program; a platform or account seen for the first time baselines silently.

const (
	programWatchPauseKey   = "PROGRAM_WATCH_PAUSE_STATE"    // legacy v1: {platform|handle: state}
	programWatchPauseKeyV2 = "PROGRAM_WATCH_PAUSE_STATE_V2" // pauseStore
	programWatchPauseAlert = 12                             // max pause/return/new-program alerts per refresh cycle
	programWatchPauseCap   = 20000                          // hard cap on remembered programs (oldest evicted first)
)

// pauseEntry is one program's last submission state and when it was last
// present in a snapshot (unix).
type pauseEntry struct {
	S string `json:"s"`
	T int64  `json:"t"`
}

type pauseStore struct {
	Programs map[string]pauseEntry `json:"programs"`
	// Baselined holds "platform|account-label" pairs whose program list has
	// been recorded at least once ("platform|" for unlabeled sources,
	// "platform|*" = migrated from v1, any label).
	Baselined map[string]bool `json:"baselined"`
}

func loadPauseStore(now time.Time) *pauseStore {
	st := &pauseStore{}
	if v, _ := db.GetSetting(programWatchPauseKeyV2); v != "" {
		_ = json.Unmarshal([]byte(v), st)
	} else if v1, _ := db.GetSetting(programWatchPauseKey); v1 != "" {
		// One-time migration from the v1 map: keep states, mark the platforms
		// it covered as baselined for any account.
		old := map[string]string{}
		_ = json.Unmarshal([]byte(v1), &old)
		st.Programs = map[string]pauseEntry{}
		st.Baselined = map[string]bool{}
		for k, s := range old {
			st.Programs[k] = pauseEntry{S: s, T: now.Unix()}
			if i := strings.Index(k, "|"); i > 0 {
				st.Baselined[k[:i]+"|*"] = true
			}
		}
	}
	if st.Programs == nil {
		st.Programs = map[string]pauseEntry{}
	}
	if st.Baselined == nil {
		st.Baselined = map[string]bool{}
	}
	return st
}

func savePauseStore(st *pauseStore, now time.Time) {
	cutoff := now.Add(-programWatchPruneAfter).Unix()
	for k, e := range st.Programs {
		if e.T < cutoff {
			delete(st.Programs, k)
		}
	}
	if over := len(st.Programs) - programWatchPauseCap; over > 0 {
		keys := make([]string, 0, len(st.Programs))
		for k := range st.Programs {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return st.Programs[keys[i]].T < st.Programs[keys[j]].T })
		for _, k := range keys[:over] {
			delete(st.Programs, k)
		}
	}
	if b, err := json.Marshal(st); err == nil {
		_ = db.SetSetting(programWatchPauseKeyV2, string(b))
		programPauseStatesInvalidate()
	}
}

func splitWatchTokens(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return !(r >= 'a' && r <= 'z') })
}

// pauseNormalize reduces a platform's raw state string to open/paused/closed.
// Unknown or empty states return "" — programs whose platform doesn't report a
// state never enter (or churn) the pause map. Matching is on whole tokens (or
// token prefixes), so "pending" no longer reads as "end" → closed.
func pauseNormalize(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return ""
	}
	toks := splitWatchTokens(s)
	for _, t := range toks {
		if strings.HasPrefix(t, "paus") || strings.HasPrefix(t, "suspend") || strings.HasPrefix(t, "tempor") {
			return "paused"
		}
	}
	for _, t := range toks {
		// "closed"/"ended"/"archived"/"out_of_verification"/"disabled"... all
		// non-actionable states.
		if strings.HasPrefix(t, "clos") || t == "end" || t == "ended" || strings.HasPrefix(t, "archiv") ||
			strings.HasPrefix(t, "verif") || strings.HasPrefix(t, "disabl") {
			return "closed"
		}
	}
	return "open"
}

// pauseTransition classifies a state change for a program already in the map:
// "" (no alert), "paused", or "returned". open→closed counts as paused (the
// program stopped accepting submissions either way); paused/closed→open is the
// return the owner asked for.
func pauseTransition(prev, cur string) string {
	switch {
	case prev == cur || prev == "" || cur == "":
		return ""
	case cur == "paused" && prev == "open":
		return "paused"
	case cur == "closed" && prev == "open":
		return "paused"
	case cur == "open" && prev != "open":
		return "returned"
	default:
		// paused<->closed wobbles and any other pair: record, don't alert.
		return ""
	}
}

// programSourceLabels returns the account labels a program was seen through
// ("" for unlabeled sources such as HackAdvisor or the public H1 listing).
func programSourceLabels(p ProgramSummary) []string {
	if len(p.Sources) == 0 {
		return []string{""}
	}
	return p.Sources
}

// visibleAccountsLine renders "• Visible to: `label1`, `label2`" for the
// account labels a program is reachable through. Bugcrowd engagement links
// (and other private programs) 404 under a login that lacks access — the
// label tells the owner which account to switch to before opening the link.
// Empty for public/unlabeled sources, where the link works for anyone.
func visibleAccountsLine(p ProgramSummary) string {
	var labels []string
	for _, s := range p.Sources {
		if s = strings.TrimSpace(s); s != "" {
			labels = append(labels, "`"+strings.ReplaceAll(s, "`", "'")+"`")
		}
	}
	if len(labels) == 0 {
		return ""
	}
	return "\n• Visible to: " + strings.Join(labels, ", ")
}

// programWatchPauseDiff compares every program's submission state against the
// persisted previous state, alerts on paused/returned transitions and brand-new
// programs (capped per cycle), and persists the new map. Absent programs keep
// their previous state — a partial/failed fetch can never fabricate
// transitions — and are pruned only after programWatchPruneAfter of absence.
// A program whose alert was dropped by the cap is NOT recorded, so it is
// announced on a later cycle instead of being baselined silently.
func programWatchPauseDiff(programs []ProgramSummary, now time.Time) {
	st := loadPauseStore(now)
	nowUnix := now.Unix()
	seenPairs := map[string]bool{}

	var alerts []string
	dropped := 0
	for i := range programs {
		p := programs[i]
		if !programWatchPlatformAllowed(p.Platform) || p.Handle == "" {
			continue
		}
		cur := pauseNormalize(p.SubmissionState)
		if cur == "" {
			continue
		}
		labels := programSourceLabels(p)
		for _, l := range labels {
			seenPairs[p.Platform+"|"+l] = true
		}
		key := p.Platform + "|" + p.Handle
		prev, known := st.Programs[key]
		if !known {
			// First sighting: announce only when an account/platform that could
			// already see it had been baselined — a newly added account or a
			// platform's first successful fetch baselines its programs silently.
			announce := st.Baselined[p.Platform+"|*"]
			for _, l := range labels {
				announce = announce || st.Baselined[p.Platform+"|"+l]
			}
			if announce {
				if len(alerts) >= programWatchPauseAlert {
					dropped++
					continue // not recorded: announced next cycle
				}
				kind := "Response"
				if p.OffersBounties {
					kind = "Bounty"
				}
				msg := fmt.Sprintf("🆕 **New program** — %s (`%s` · %s) — %s, submissions %s",
					discordName(p), discordSpanText(p.Handle, 80), strings.ToUpper(p.Platform), kind, cur)
				msg += visibleAccountsLine(p)
				if u := discordSafeURL(p.URL); u != "" {
					msg += "\n" + u
				}
				alerts = append(alerts, msg)
			}
			st.Programs[key] = pauseEntry{S: cur, T: nowUnix}
			continue
		}
		if kind := pauseTransition(prev.S, cur); kind != "" {
			if len(alerts) >= programWatchPauseAlert {
				dropped++
				st.Programs[key] = pauseEntry{S: prev.S, T: nowUnix} // keep old state → re-detected next cycle
				continue
			}
			var msg string
			if kind == "paused" {
				msg = fmt.Sprintf("⏸ **Program paused** — %s (`%s` · %s)", discordName(p), discordSpanText(p.Handle, 80), strings.ToUpper(p.Platform))
			} else {
				msg = fmt.Sprintf("▶️ **Program returned** — %s (`%s` · %s) — accepting submissions again", discordName(p), discordSpanText(p.Handle, 80), strings.ToUpper(p.Platform))
			}
			msg += visibleAccountsLine(p)
			if u := discordSafeURL(p.URL); u != "" {
				msg += "\n" + u
			}
			alerts = append(alerts, msg)
		}
		st.Programs[key] = pauseEntry{S: cur, T: nowUnix}
	}

	for k := range seenPairs {
		st.Baselined[k] = true
	}
	// A v1-migration wildcard lasts until the platform shows up with concrete
	// account labels; after that, a newly added account baselines silently.
	for k := range st.Baselined {
		if pl, ok := strings.CutSuffix(k, "|*"); ok {
			for sp := range seenPairs {
				if strings.HasPrefix(sp, pl+"|") {
					delete(st.Baselined, k)
					break
				}
			}
		}
	}

	if len(alerts) > 0 {
		for _, msg := range alerts {
			if err := programWatchSend(msg); err != nil {
				logger.GetLogger().Infof("[PROGRAM-WATCH] pause-alert send failed: %v", err)
			}
		}
		logger.GetLogger().Infof("[PROGRAM-WATCH] %d new-program/pause/return alert(s) sent", len(alerts))
	}
	if dropped > 0 {
		logger.GetLogger().Infof("[PROGRAM-WATCH] %d new-program/pause/return alert(s) over the per-cycle cap — deferred to the next cycle", dropped)
	}
	savePauseStore(st, now)
}

var (
	programPauseStatesMu   sync.Mutex
	programPauseStatesMemo map[string]string
	programPauseStatesAt   time.Time
)

// programPauseStates returns the last known submission state per program
// ("platform|handle", lowercase → open/paused/closed) from the pause map,
// memoized for a minute. Used by the race/scope tags to say "⏸ program
// paused" instead of "IN SCOPE" for programs not accepting submissions.
func programPauseStates() map[string]string {
	programPauseStatesMu.Lock()
	defer programPauseStatesMu.Unlock()
	if programPauseStatesMemo != nil && time.Since(programPauseStatesAt) < time.Minute {
		return programPauseStatesMemo
	}
	out := map[string]string{}
	if v, _ := db.GetSetting(programWatchPauseKeyV2); v != "" {
		var st pauseStore
		if json.Unmarshal([]byte(v), &st) == nil {
			for k, e := range st.Programs {
				out[strings.ToLower(k)] = e.S
			}
		}
	}
	programPauseStatesMemo, programPauseStatesAt = out, time.Now()
	return out
}

func programPauseStatesInvalidate() {
	programPauseStatesMu.Lock()
	programPauseStatesMemo = nil
	programPauseStatesMu.Unlock()
}

// ─── Scope fingerprints ───────────────────────────────────────────────────────

// watchFP is a program's scope fingerprint, serialized "v2|count|assets|latest":
// the in-scope count, an md5 of the SORTED in-scope asset set ("" when the
// snapshot carries no asset list — the fast loop's list fetches) and an md5 of
// the representative latest target ("" when none). Asset sets are compared
// when both sides have one; otherwise counts (and latest targets when both
// sides have one). The sorted set makes the YesWeHack fast loop (no assets,
// LatestTarget "") and warmer (assets[0]) agree instead of flip-flopping.
type watchFP struct {
	Count          int
	Assets, Latest string
}

func (f watchFP) String() string {
	return "v2|" + strconv.Itoa(f.Count) + "|" + f.Assets + "|" + f.Latest
}

func parseWatchFP(s string) (watchFP, bool) {
	parts := strings.Split(s, "|")
	if len(parts) != 4 || parts[0] != "v2" {
		return watchFP{}, false
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil {
		return watchFP{}, false
	}
	return watchFP{Count: n, Assets: parts[2], Latest: parts[3]}, true
}

func md5Hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func watchFPOf(p ProgramSummary) watchFP {
	f := watchFP{Count: p.ScopeTargets}
	if len(p.Assets) > 0 {
		set := map[string]bool{}
		for _, a := range p.Assets {
			if a = strings.ToLower(strings.TrimSpace(a)); a != "" {
				set[a] = true
			}
		}
		sorted := make([]string, 0, len(set))
		for a := range set {
			sorted = append(sorted, a)
		}
		sort.Strings(sorted)
		f.Assets = md5Hex(strings.Join(sorted, "\n"))
	}
	if t := strings.ToLower(strings.TrimSpace(p.LatestTarget)); t != "" {
		f.Latest = md5Hex(t)
	}
	return f
}

func programWatchFingerprint(p ProgramSummary) string { return watchFPOf(p).String() }

// legacyWatchFingerprint is the pre-v2 format (md5 of
// platform|handle|latest|count), still accepted from the settings row once.
func legacyWatchFingerprint(p ProgramSummary) string {
	return md5Hex(p.Platform + "|" + p.Handle + "|" + p.LatestTarget + "|" + strconv.Itoa(p.ScopeTargets))
}

// programWatchAssetLevel reports whether a platform's LatestTargetUpdatedAt is
// an ASSET-level timestamp (h1/bc/it scope enrichment, HackAdvisor's
// scope_updated_at). YesWeHack's is program-level: it moves on any program
// edit, so "same asset set, timestamp moved" is no evidence an asset was
// touched there — no ✏️ notice.
func programWatchAssetLevel(platform string) bool { return platform != "ywh" }

// programWatchDefersWithoutAssets: platforms whose list timestamp also feeds
// the fast loop WITHOUT an asset list, but whose warmer carries one. A
// same-count bump there can't be judged from the list alone.
func programWatchDefersWithoutAssets(platform string) bool { return platform == "ywh" }

// mergeWatchFP returns the fingerprint to store for p given the stored one:
// the current values, keeping the stored asset/latest hash when this snapshot
// lacks one and the count is unchanged. "" when p carries no substance.
func mergeWatchFP(prevFP string, p ProgramSummary) string {
	if strings.TrimSpace(p.LatestTarget) == "" && p.ScopeTargets == 0 && len(p.Assets) == 0 {
		return ""
	}
	cur := watchFPOf(p)
	if prev, ok := parseWatchFP(prevFP); ok && prev.Count == cur.Count {
		if cur.Assets == "" {
			cur.Assets = prev.Assets
		}
		if cur.Latest == "" {
			cur.Latest = prev.Latest
		}
	}
	return cur.String()
}

// programWatchLoadFPs loads the fingerprint map (empty on any parse error —
// worst case we re-alert once, same as a fresh install).
func programWatchLoadFPs() map[string]string {
	m := map[string]string{}
	if v, _ := db.GetSetting(programWatchFPKey); v != "" {
		_ = json.Unmarshal([]byte(v), &m)
	}
	return m
}

// programWatchSaveFPs persists the fingerprint map, dropping programs the
// watch no longer tracks (pruned from the last-seen state) instead of
// evicting arbitrary — possibly live — entries.
func programWatchSaveFPs(m map[string]string, st *watchLastSeen) {
	if len(m) == 0 {
		return
	}
	if st != nil && len(st.Programs) > 0 && len(m) > 2*len(st.Programs)+1000 {
		for k := range m {
			if _, ok := st.Programs[k]; !ok {
				delete(m, k)
			}
		}
	}
	if b, err := json.Marshal(m); err == nil {
		_ = db.SetSetting(programWatchFPKey, string(b))
	}
}

// watchVerdict classifies a timestamp-bumped program against its stored scope
// fingerprint.
type watchVerdict int

const (
	watchSkip         watchVerdict = iota // closed/paused or zero-substance: never announce
	watchNewScope                         // fingerprint changed or first sight: 🆕 Scope updated
	watchAssetTouched                     // same asset set, timestamp moved: ✏️ asset updated
	watchDefer                            // this snapshot can't tell (no asset list): leave pending
)

// classifyWatch is the pure decision core of the announce paths. prevFP/seen
// come from the persisted fingerprint map; the returned string is the
// fingerprint to persist when the update is processed (prevFP for skips).
func classifyWatch(p ProgramSummary, prevFP string, seen bool) (watchVerdict, string) {
	switch pauseNormalize(p.SubmissionState) {
	case "paused", "closed":
		return watchSkip, prevFP
	}
	if strings.TrimSpace(p.LatestTarget) == "" && p.ScopeTargets == 0 && len(p.Assets) == 0 {
		return watchSkip, prevFP
	}
	cur := watchFPOf(p)
	if !seen {
		return watchNewScope, cur.String()
	}
	merged := mergeWatchFP(prevFP, p)
	same, decided := sameWatchScope(prevFP, cur, p)
	switch {
	case !decided:
		return watchDefer, prevFP
	case !same:
		return watchNewScope, merged
	case programWatchAssetLevel(p.Platform):
		return watchAssetTouched, merged
	default:
		return watchSkip, merged
	}
}

// sameWatchScope compares a stored fingerprint with the current snapshot.
// decided is false when the snapshot lacks the asset list needed to tell.
func sameWatchScope(prevFP string, cur watchFP, p ProgramSummary) (same, decided bool) {
	prev, ok := parseWatchFP(prevFP)
	if !ok {
		// Legacy md5 fingerprint: equal legacy hash means unchanged.
		if prevFP == legacyWatchFingerprint(p) {
			return true, true
		}
		if cur.Assets == "" && programWatchDefersWithoutAssets(p.Platform) {
			return false, false
		}
		return false, true
	}
	if prev.Assets != "" && cur.Assets != "" {
		return prev.Assets == cur.Assets, true
	}
	if prev.Count != cur.Count {
		return false, true
	}
	if prev.Latest != "" && cur.Latest != "" && prev.Latest != cur.Latest {
		return false, true
	}
	if cur.Assets == "" && programWatchDefersWithoutAssets(p.Platform) {
		return false, false
	}
	return true, true
}

// programWatchAssetTouchEnabled gates the ✏️ asset-updated notices. Set
// PROGRAM_WATCH_ASSET_TOUCH=off to silence them — the 🆕 new-scope alerts are
// unaffected either way.
func programWatchAssetTouchEnabled() bool {
	return !strings.EqualFold(strings.TrimSpace(os.Getenv("PROGRAM_WATCH_ASSET_TOUCH")), "off")
}

// ─── Discord rendering ────────────────────────────────────────────────────────
// Every field below comes from platform/aggregator data (program names, asset
// strings, briefs, links) and is untrusted: it must not be able to inject
// mentions, masked links or break out of its code span.

// discordName is the escaped display name of a program.
func discordName(p ProgramSummary) string {
	return utils.DiscordEscapeTrunc(programWatchName(p), 120)
}

// discordSpanText makes s safe inside a `code span` the caller writes: no
// backticks or newlines (markdown does not render inside the span, so no other
// escaping), capped at n runes. Unlike discordCode it adds no backticks.
func discordSpanText(s string, n int) string {
	s = strings.NewReplacer("`", "'", "\n", " ", "\r", " ").Replace(s)
	if r := []rune(s); n > 0 && len(r) > n {
		s = string(r[:n]) + "…"
	}
	return s
}

// discordSafeURL returns u when it is a plain http(s) URL that can't carry
// markdown/mention syntax, "" otherwise (aggregator links are untrusted).
func discordSafeURL(u string) string {
	u = strings.TrimSpace(u)
	if u == "" || len(u) > 500 || strings.ContainsAny(u, " \t\r\n<>`|*~[]()@\\") {
		return ""
	}
	pu, err := url.Parse(u)
	if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
		return ""
	}
	return u
}

func sendProgramIntroDiscord(p ProgramSummary) {
	msg := fmt.Sprintf("📌 **Scope watch ready** — most recent update: **%s** (`%s` · %s)\n• Latest asset: `%s`\n• Updated: %s",
		discordName(p), discordSpanText(p.Handle, 80), strings.ToUpper(p.Platform),
		discordSpanText(nonEmpty(p.LatestTarget, "—"), 200), humanizeTime(p.LatestTargetUpdatedAt))
	msg += visibleAccountsLine(p)
	if u := discordSafeURL(p.URL); u != "" {
		msg += "\n" + u
	}
	if err := programWatchSend(msg); err != nil {
		logger.GetLogger().Infof("[PROGRAM-WATCH] intro send failed: %v", err)
		return
	}
	programWatchSessionN++
}

func sendProgramUpdateDiscord(p ProgramSummary) {
	msg := fmt.Sprintf("🆕 **Scope updated** — %s (`%s` · %s)\n• Latest asset: `%s`\n• Updated: %s",
		discordName(p), discordSpanText(p.Handle, 80), strings.ToUpper(p.Platform),
		discordSpanText(nonEmpty(p.LatestTarget, "—"), 200), humanizeTime(p.LatestTargetUpdatedAt))
	if p.LatestTargetBrief != "" && len(p.LatestTargetBrief) <= 140 {
		msg += "\n• Note: " + utils.DiscordEscape(strings.ReplaceAll(p.LatestTargetBrief, "\n", " "))
	}
	msg += visibleAccountsLine(p)
	if u := discordSafeURL(p.URL); u != "" {
		msg += "\n" + u
	}
	if err := programWatchSend(msg); err != nil {
		logger.GetLogger().Infof("[PROGRAM-WATCH] update send failed for %s: %v", p.Handle, err)
		return
	}
	programWatchSessionN++
}

// sendAssetTouchDiscord announces an edit to EXISTING scope — asset set
// unchanged, LatestTargetUpdatedAt moved (the "program edited an
// already-in-scope asset" class the fingerprint gate used to suppress
// silently). The ✏️ label distinguishes it from 🆕 Scope updated at a glance.
func sendAssetTouchDiscord(p ProgramSummary) {
	msg := fmt.Sprintf("✏️ **Asset updated (existing scope)** — %s (`%s` · %s)\n• Latest asset: `%s`\n• Updated: %s",
		discordName(p), discordSpanText(p.Handle, 80), strings.ToUpper(p.Platform),
		discordSpanText(nonEmpty(p.LatestTarget, "—"), 200), humanizeTime(p.LatestTargetUpdatedAt))
	if p.LatestTargetBrief != "" && len(p.LatestTargetBrief) <= 140 {
		msg += "\n• Note: " + utils.DiscordEscape(strings.ReplaceAll(p.LatestTargetBrief, "\n", " "))
	}
	msg += visibleAccountsLine(p)
	if u := discordSafeURL(p.URL); u != "" {
		msg += "\n" + u
	}
	if err := programWatchSend(msg); err != nil {
		logger.GetLogger().Infof("[PROGRAM-WATCH] asset-touch send failed for %s: %v", p.Handle, err)
		return
	}
	programWatchSessionN++
}

func programWatchName(p ProgramSummary) string {
	return nonEmpty(p.Name, p.Handle)
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

// humanizeTime returns a short relative form ("3h ago", "2d ago") for an ISO 8601
// time string, falling back to the raw string when it can't parse.
func humanizeTime(iso string) string {
	if iso == "" {
		return "unknown"
	}
	t, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		// Try a couple of common variants.
		if t2, err2 := time.Parse("2006-01-02T15:04:05Z", iso); err2 == nil {
			t = t2
		} else {
			return iso
		}
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// ProgramWatchStatus is a snapshot returned by the status API.
type ProgramWatchStatus struct {
	WebhookConfigured bool      `json:"webhook_configured"`
	Enabled           bool      `json:"enabled"`
	IntroSent         bool      `json:"intro_sent"`
	AlertsThisSession int       `json:"alerts_this_session"`
	WatermarkISO      string    `json:"watermark_iso"`
	WatermarkHuman    string    `json:"watermark_human"`
	LastRefreshAt     time.Time `json:"last_refresh_at"`
	LastRefreshHuman  string    `json:"last_refresh_human"`
	FreshestProgram   string    `json:"freshest_program"`
	FreshestAsset     string    `json:"freshest_asset"`
	FreshestUpdatedAt string    `json:"freshest_updated_at"`
}

// CurrentProgramWatchStatus assembles the live status for the dashboard. It reads
// the cached programs payload to find the current freshest update.
func CurrentProgramWatchStatus() ProgramWatchStatus {
	programWatchMu.Lock()
	sessionN := programWatchSessionN
	introSent := programWatchIntroSent
	lastAt := programWatchLastAt
	programWatchMu.Unlock()

	watermark, _ := db.GetSetting(programWatchWatermarkKey)
	st := ProgramWatchStatus{
		WebhookConfigured: utils.MonitorWebhookConfigured(),
		Enabled:           programWatchEnabled(),
		IntroSent:         introSent,
		AlertsThisSession: sessionN,
		WatermarkISO:      watermark,
		WatermarkHuman:    humanizeTime(watermark),
		LastRefreshAt:     lastAt,
		LastRefreshHuman:  humanizeTime(lastAt.Format(time.RFC3339)),
	}
	if payload, ok := loadProgramsCache(); ok {
		var freshest *ProgramSummary
		for i := range payload.Programs {
			p := payload.Programs[i]
			if p.LatestTargetUpdatedAt == "" {
				continue
			}
			if freshest == nil || isNewerProgramTime(p.LatestTargetUpdatedAt, freshest.LatestTargetUpdatedAt) {
				freshest = &payload.Programs[i]
			}
		}
		if freshest != nil {
			st.FreshestProgram = programWatchName(*freshest)
			st.FreshestAsset = freshest.LatestTarget
			st.FreshestUpdatedAt = freshest.LatestTargetUpdatedAt
		}
	}
	return st
}

// GET /api/scope/watch-status — current scope-watch state for the Programs page.
func apiProgramWatchStatus(c *gin.Context) {
	c.JSON(http.StatusOK, CurrentProgramWatchStatus())
}

// POST /api/scope/watch-test — send an immediate test message to MONITOR_WEBHOOK_URL
// so the operator can confirm Discord delivery without waiting for the next refresh.
func apiProgramWatchTest(c *gin.Context) {
	if !utils.MonitorWebhookConfigured() {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "MONITOR_WEBHOOK_URL is not set"})
		return
	}
	msg := fmt.Sprintf("✅ **AutoAR scope-watch test** — webhook is reachable. Sent at %s.",
		time.Now().UTC().Format(time.RFC3339))
	if err := programWatchSend(msg); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"ok": false, "error": err.Error()})
		return
	}
	programWatchMu.Lock()
	programWatchSessionN++
	programWatchMu.Unlock()
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// GET /api/scope/debug?platform=h1&handle=dialogue
// Fetches a single program's scope live and returns BOTH the raw H1 response
// (first 10 scope entries) AND what our parser extracts, so a "we're missing
// the new assets" report can be diagnosed without guessing — you can see at a
// glance whether H1 is rate-limiting, whether the assets are there but under
// unexpected field names, or whether our parser is dropping them.
func apiProgramScopeDebug(c *gin.Context) {
	platform := strings.ToLower(strings.TrimSpace(c.Query("platform")))
	handle := strings.TrimSpace(c.Query("handle"))
	if handle == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "handle query param required"})
		return
	}
	// The handle is interpolated into an upstream API path sent with the
	// operator's credentials: "../me/reports#" would turn this into a proxy
	// for arbitrary authenticated H1/HA API reads.
	if !validProgramHandle(handle) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid handle (allowed: letters, digits, '_', '.', '-')"})
		return
	}
	if platform == "" {
		platform = "h1"
	}
	// HackAdvisor: reuse the same fetcher the catalogue/force-fetch use.
	if platform == "ha" || platform == "hackadvisor" {
		if !hasHackAdvisorToken() {
			c.JSON(http.StatusBadRequest, gin.H{"error": "HACKADVISOR_TOKEN not set"})
			return
		}
		if !validHAHandle(handle) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "HackAdvisor handles are numeric program ids"})
			return
		}
		summary, ok := fetchHAScopeSummary(handle)
		c.JSON(http.StatusOK, gin.H{
			"platform":  "ha",
			"handle":    handle,
			"scope_url": fmt.Sprintf("%s/programs/%s/scope/", hackAdvisorBase, handle),
			"parser_output": gin.H{
				"ok":                       ok,
				"scope_targets":            summary.ScopeTargets,
				"latest_target":            summary.LatestTarget,
				"latest_target_updated_at": summary.LatestTargetUpdatedAt,
				"all_assets_count":         len(summary.Assets),
				"assets_sample":            firstN(summary.Assets, 15),
			},
		})
		return
	}
	if platform != "h1" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only platform=h1 or ha supported currently"})
		return
	}

	u, t := os.Getenv("H1_USERNAME"), os.Getenv("H1_TOKEN")
	if u == "" || t == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "H1_USERNAME / H1_TOKEN not set"})
		return
	}
	auth := base64.StdEncoding.EncodeToString([]byte(u + ":" + t))

	reqURL := h1StructuredScopesURL(handle)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Basic "+auth)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	out := gin.H{
		"request_url": reqURL,
		"status_code": resp.StatusCode,
		"headers": gin.H{
			"retry_after":         resp.Header.Get("Retry-After"),
			"ratelimit_remaining": resp.Header.Get("X-Rate-Limit-Remaining"),
			"ratelimit_reset":     resp.Header.Get("X-Rate-Limit-Reset"),
		},
	}

	// Capture the first 10 raw scope entries so we can see what field names
	// (and values) H1 is actually sending for this program.
	var rawScopes []any
	data := gjson.GetBytes(body, "data").Array()
	out["scope_entries_returned"] = len(data)
	for i, s := range data {
		if i >= 10 {
			break
		}
		var entry any
		if err := json.Unmarshal([]byte(s.Raw), &entry); err == nil {
			rawScopes = append(rawScopes, entry)
		}
	}
	out["raw_scope_entries_sample"] = rawScopes

	// What our parser would extract (or skip, if H1 returned non-200).
	parsed, ok := fetchH1ScopeSummary(handle, auth)
	out["parser_output"] = gin.H{
		"ok":                       ok,
		"scope_targets":            parsed.ScopeTargets,
		"latest_target":            parsed.LatestTarget,
		"latest_target_updated_at": parsed.LatestTargetUpdatedAt,
		"all_assets_count":         len(parsed.Assets),
	}

	c.JSON(http.StatusOK, out)
}
