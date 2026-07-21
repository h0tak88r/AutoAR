package api

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/accounts"
	"github.com/h0tak88r/AutoAR/internal/db"
)

// ─────────────────────────────────────────────────────────────────────────────
// Programs cache + background warmer
//
// The Programs page used to fetch the full H1 + Bugcrowd catalogue (and one
// scope call per program — ~1000 upstream requests) on every visit, so the page
// took ~minute to fully populate. Instead we keep the whole assembled payload
// (programs + scope) as a single JSON blob in the settings KV table and refresh
// it in the background. Page loads then serve straight from the cache and are
// already fully populated; a stale cache is served immediately and refreshed
// behind the request (stale-while-revalidate).
//
// Stored in `settings` (TEXT, both Postgres and SQLite) — no schema changes.
// ─────────────────────────────────────────────────────────────────────────────

const (
	programsCacheSettingKey = "programs_cache_v1"
	// programsCacheTTL is how long a cached payload is considered fresh. Past it,
	// the cache is still served but a background refresh is triggered.
	programsCacheTTL = 10 * time.Minute
	// programsWarmInterval is the background refresh cadence.
	programsWarmInterval = 10 * time.Minute
)

// programsCachePayload is the full assembled program list persisted as one JSON
// blob. Scope counts and latest-target fields are baked in so the UI needs no
// per-program follow-up calls.
type programsCachePayload struct {
	Programs    []ProgramSummary `json:"programs"`
	HasH1Token  bool             `json:"has_h1_token"`
	HasBCToken  bool             `json:"has_bc_token"`
	HasITToken  bool             `json:"has_it_token"`
	HasYWHToken bool             `json:"has_ywh_token"`
	HasHAToken  bool             `json:"has_ha_token"`
	GeneratedAt time.Time        `json:"generated_at"`
}

var (
	programsRefreshMu  sync.Mutex
	programsRefreshing bool
)

// programsCacheEnabled reports whether the DB-backed cache should be used at all.
// Without a DB configured there is nowhere to persist the payload, so the cache
// (and its background refresh) is disabled — the handler then just does a live
// fetch, exactly as it did before this cache existed. This prevents a DB-less
// deployment from triggering an endless loop of expensive upstream rebuilds that
// can never be saved.
func programsCacheEnabled() bool {
	return strings.TrimSpace(os.Getenv("DB_HOST")) != ""
}

// loadProgramsCache reads and unmarshals the persisted payload.
// ok is false when the cache is absent or unreadable.
func loadProgramsCache() (programsCachePayload, bool) {
	raw, err := db.GetSetting(programsCacheSettingKey)
	if err != nil || raw == "" {
		return programsCachePayload{}, false
	}
	var payload programsCachePayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return programsCachePayload{}, false
	}
	return payload, true
}

// saveProgramsCache marshals and persists the payload.
func saveProgramsCache(payload programsCachePayload) {
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[PROGRAMS] cache marshal failed: %v", err)
		return
	}
	if err := db.SetSetting(programsCacheSettingKey, string(data)); err != nil {
		log.Printf("[PROGRAMS] cache save failed: %v", err)
	}
}

// buildProgramsPayload performs the full upstream fetch (H1 + BC) WITH scope.
// H1 and BC run concurrently; each platform enriches scope internally.
func buildProgramsPayload() programsCachePayload {
	var all []ProgramSummary
	var mu sync.Mutex
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		progs, err := fetchH1Programs(true, true) // bbpOnly, includeScope
		if err != nil {
			log.Printf("[PROGRAMS] H1 fetch failed: %v", err)
			return
		}
		mu.Lock()
		all = append(all, progs...)
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		progs, err := fetchBCPrograms(true, true)
		if err != nil {
			log.Printf("[PROGRAMS] BC fetch failed: %v", err)
			return
		}
		mu.Lock()
		all = append(all, progs...)
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		progs, err := fetchITPrograms(true, true)
		if err != nil {
			log.Printf("[PROGRAMS] Intigriti fetch failed: %v", err)
			return
		}
		mu.Lock()
		all = append(all, progs...)
		mu.Unlock()
	}()

	// YesWeHack — native fetch across every configured YWH account (bbscope). No-op
	// unless a YWH account/token is configured.
	wg.Add(1)
	go func() {
		defer wg.Done()
		progs, err := fetchYWHPrograms(true, true)
		if err != nil {
			log.Printf("[PROGRAMS] YesWeHack fetch failed: %v", err)
			return
		}
		mu.Lock()
		all = append(all, progs...)
		mu.Unlock()
	}()

	// HackAdvisor — external targets aggregator (Immunefi, Standoff365, BI.ZONE,
	// YesWeHack, self-hosted, …). No-op unless HACKADVISOR_TOKEN is set. The list
	// already carries scope_count + scope_updated_at, so no per-program enrichment.
	wg.Add(1)
	go func() {
		defer wg.Done()
		progs, err := fetchHackAdvisorPrograms(true)
		if err != nil {
			log.Printf("[PROGRAMS] HackAdvisor fetch failed: %v", err)
			return
		}
		mu.Lock()
		all = append(all, progs...)
		mu.Unlock()
	}()

	wg.Wait()

	// Overlay last-known-good scope from the program_scope DB table. This is the
	// key persistence guarantee: a program previously fetched successfully keeps
	// its real values on the dashboard even when this refresh's enrichment came
	// back empty (e.g. rate-limited). The enrich functions ONLY upsert on success,
	// so anything in the DB is real data — never an empty value masquerading.
	overlayPersistedProgramScope(all)

	return programsCachePayload{
		Programs:    all,
		HasH1Token:  accounts.Count("h1") > 0,
		HasBCToken:  accounts.Count("bc") > 0,
		HasITToken:  hasIntigritiToken(),
		HasYWHToken: accounts.Count("ywh") > 0,
		HasHAToken:  hasHackAdvisorToken(),
		GeneratedAt: time.Now().UTC(),
	}
}

// overlayPersistedProgramScope fills any program row whose fresh enrichment left
// scope empty (ScopeTargets==0 AND no LatestTarget) from the program_scope DB
// table. Rows where this refresh DID get fresh scope are left alone — the latest
// successful fetch always wins. Mutates in place.
func overlayPersistedProgramScope(programs []ProgramSummary) {
	persisted, err := db.LoadProgramScopes()
	if err != nil || len(persisted) == 0 {
		return
	}
	restored := 0
	for i := range programs {
		p := &programs[i]
		// Only treat scope as "fresh this refresh" when we actually got a target
		// or a count. LatestTargetUpdatedAt can be populated from the program-list
		// API (e.g. IT's program-level lastUpdatedAt) even when scope enrich
		// returned nothing — checking it here would suppress the overlay and
		// leave the dashboard showing "—".
		if p.ScopeTargets > 0 || p.LatestTarget != "" {
			continue // this refresh enriched scope — keep the fresh value
		}
		key := strings.ToLower(p.Platform) + ":" + p.Handle
		s, ok := persisted[key]
		if !ok || (s.ScopeTargets == 0 && s.LatestTarget == "") {
			continue
		}
		p.ScopeTargets = s.ScopeTargets
		p.LatestTarget = s.LatestTarget
		p.LatestTargetUpdatedAt = s.LatestTargetUpdatedAt
		p.LatestTargetBrief = s.LatestTargetBrief
		restored++
	}
	if restored > 0 {
		log.Printf("[PROGRAMS] preserved last-known-good scope for %d program(s) where this refresh came back empty", restored)
	}
}

// refreshProgramsCache rebuilds and persists the cache. It is single-flight:
// if a refresh is already running, it returns false immediately instead of
// launching a second concurrent fetch. Returns true when it persisted a build.
func refreshProgramsCache() bool {
	programsRefreshMu.Lock()
	if programsRefreshing {
		programsRefreshMu.Unlock()
		return false
	}
	programsRefreshing = true
	programsRefreshMu.Unlock()
	defer func() {
		programsRefreshMu.Lock()
		programsRefreshing = false
		programsRefreshMu.Unlock()
	}()

	start := time.Now()
	payload := buildProgramsPayload()

	// Never clobber a good cache with an empty result (e.g. tokens missing or
	// upstream errored) — keep serving the last good payload.
	if len(payload.Programs) == 0 {
		if _, ok := loadProgramsCache(); ok {
			log.Printf("[PROGRAMS] refresh produced 0 programs; keeping previous cache")
			return false
		}
	}

	saveProgramsCache(payload)
	log.Printf("[PROGRAMS] cache refreshed: %d programs in %s", len(payload.Programs), time.Since(start).Round(time.Second))

	// Scope-update watch: detect programs whose latest_target_updated_at moved past
	// the persisted watermark and post a Discord alert for each. Passive — reuses
	// the data we just fetched, no extra API calls. No-op without a webhook.
	ProgramWatchOnRefresh(payload.Programs)
	return true
}

// refreshProgramsCacheAsync triggers a non-blocking refresh (deduped by the
// single-flight guard in refreshProgramsCache).
func refreshProgramsCacheAsync() {
	go refreshProgramsCache()
}

// StartProgramsWarmer pre-warms the cache on boot (if empty or stale) and then
// refreshes it on a ticker. Call once from the API server start path.
func StartProgramsWarmer() {
	go func() {
		if payload, ok := loadProgramsCache(); !ok || time.Since(payload.GeneratedAt) > programsCacheTTL {
			refreshProgramsCache()
		}
		ticker := time.NewTicker(programsWarmInterval)
		defer ticker.Stop()
		for range ticker.C {
			refreshProgramsCache()
		}
	}()
}
