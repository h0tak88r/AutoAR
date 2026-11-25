package bbcatalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/accounts"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
	scopemod "github.com/h0tak88r/AutoAR/internal/scanner/scope"
	"github.com/h0tak88r/AutoAR/internal/utils"
	bbscope "github.com/sw33tLie/bbscope/pkg/scope"
)

// SyncResult summarises a catalog sync.
type SyncResult struct {
	Programs int            `json:"programs"`
	Domains  int            `json:"domains"`
	Sources  map[string]int `json:"sources"`
	Errors   []string       `json:"errors,omitempty"`
}

const (
	// syncChildTimeout bounds one catalog-sync child (a full H1+BC+IT+YWH
	// scope pull is ~30 min on a big account set).
	syncChildTimeout = 45 * time.Minute
	// catalogLockTTL is the SQLite lease length; it outlives the child
	// timeout so a live sync never loses its lock (Postgres uses a session
	// advisory lock that needs no expiry).
	catalogLockTTL = 50 * time.Minute
)

var syncMu sync.Mutex

var (
	syncStateMu sync.Mutex
	syncRunning bool
	lastSync    SyncResult
	lastSyncAt  time.Time
)

// SyncAsync kicks off a catalog sync in the background, in a disposable
// child process (see RunSyncChild). Returns false if one is already running
// in this process. Safe to call from request handlers.
func SyncAsync() bool {
	if !beginSync() {
		return false
	}
	utils.SafeGo("catalog-sync:async", runChildSync)
	return true
}

// RunSyncChild runs one catalog sync in a disposable `catalog-sync` child
// process and blocks until it ends. It shares SyncAsync's single-flight
// guard (returns false, doing nothing, when a sync is already running) and
// the result feeds SyncStatus.
//
// The sync NEVER runs inside the API process: bbscope (used by every
// platform fetch in Sync) calls log.Fatal on HTTP errors, which os.Exit(1)s
// whatever process loads it. A fatal in the child costs one sync; in the API
// it killed every running scan.
func RunSyncChild() bool {
	if !beginSync() {
		return false
	}
	runChildSync()
	return true
}

func beginSync() bool {
	syncStateMu.Lock()
	defer syncStateMu.Unlock()
	if syncRunning {
		return false
	}
	syncRunning = true
	return true
}

func runChildSync() {
	res := SyncResult{Sources: map[string]int{}}
	// Deferred so a panic anywhere below can never leave syncRunning stuck
	// true (which would block every later sync until a restart).
	defer func() {
		if r := recover(); r != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("panic: %v", r))
			logger.GetLogger().Errorf("[CATALOG-SYNC] panic: %v", r)
		}
		syncStateMu.Lock()
		lastSync = res
		lastSyncAt = time.Now()
		syncRunning = false
		syncStateMu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), syncChildTimeout)
	defer cancel()
	out, tail, err := RunChild(ctx, []string{"catalog-sync"}, nil)
	if len(out) > 0 {
		var parsed SyncResult
		if json.Unmarshal(out, &parsed) == nil {
			res = parsed
			if res.Sources == nil {
				res.Sources = map[string]int{}
			}
		}
	}
	if err != nil {
		res.Errors = append(res.Errors, "child: "+err.Error()+": "+LastLine(tail, 300))
		logger.GetLogger().Infof("[CATALOG-SYNC] child failed (bbscope fatal? retrying next tick): %v\n--- child output tail ---\n%s", err, tail)
		return
	}
	logger.GetLogger().Infof("[CATALOG-SYNC] child ok: %d programs, %d domains, sources=%v, %d error(s)",
		res.Programs, res.Domains, res.Sources, len(res.Errors))
}

// SyncStatus reports whether a sync is running plus the last result/time.
func SyncStatus() (running bool, last SyncResult, at time.Time) {
	syncStateMu.Lock()
	defer syncStateMu.Unlock()
	return syncRunning, lastSync, lastSyncAt
}

// Sync rebuilds the catalog: as93 (public/external, bounty-only, no domains) plus
// every authenticated platform account (programs + host-level in/out-of-scope
// entries). It loads bbscope — call it only from the `catalog-sync` child
// (RunSyncChild), never from the API process.
//
// Safety rails: one sync at a time across processes (DB lock); each source is
// replaced in a single transaction; a source is never replaced by an empty
// result or by one under half its previous size (expired tokens make bbscope
// return nil without an error — that used to wipe e.g. all ~217 YWH programs).
func Sync() (SyncResult, error) {
	syncMu.Lock()
	defer syncMu.Unlock()
	res := SyncResult{Sources: map[string]int{}}

	release, ok, err := db.TryCatalogSyncLock(catalogLockTTL)
	if err != nil {
		return res, fmt.Errorf("catalog sync lock: %w", err)
	}
	if !ok {
		return res, errors.New("another catalog sync is running (lock held)")
	}
	defer release()

	// 1. as93 aggregator — keyword source, real company names, no scope.
	if progs, err := As93Programs(); err != nil {
		res.Errors = append(res.Errors, "as93: "+err.Error())
	} else {
		var list []db.CatalogSourceProgram
		seen := map[string]bool{}
		for _, p := range progs {
			handle := p.Slug
			if handle == "" {
				handle = slugify(p.Company)
			}
			if handle == "" || seen[handle] {
				continue
			}
			seen[handle] = true
			list = append(list, db.CatalogSourceProgram{Program: db.CatalogProgram{
				Company: p.Company, Handle: handle, URL: p.URL,
				Rewards: strings.Join(p.Rewards, ","), SafeHarbor: p.SafeHarbor, OffersBounty: true,
			}})
		}
		replaceSource("as93", list, &res)
	}

	// 2. authenticated platforms — programs + in/out entries from every account.
	plats := []struct {
		code string
		plat scopemod.Platform
	}{
		{"h1", scopemod.PlatformHackerOne},
		{"bc", scopemod.PlatformBugcrowd},
		{"it", scopemod.PlatformIntigriti},
		{"ywh", scopemod.PlatformYesWeHack},
	}
	visByPlatform := map[string]map[string][]string{} // source -> handle -> account labels that can see it
	for _, pl := range plats {
		accts := accounts.For(pl.code)
		if len(accts) == 0 {
			continue
		}
		// Buffer every account's fetch; only a source with real data is
		// replaced, so a fully-expired platform keeps its last-known-good rows.
		var buffered []bbscope.ProgramData
		vis := map[string]map[string]bool{} // handle -> set of labels
		for _, a := range accts {
			if pl.code == "bc" {
				// bbscope's Bugcrowd sign-in is outdated: hand it a session
				// AutoAR keeps alive (signing in again when it expires).
				token, _, detail := accounts.BugcrowdSession(a, false)
				if token == "" {
					res.Errors = append(res.Errors, "bc/"+a.Label+": "+detail)
					continue
				}
				a.Token, a.Email, a.Password = token, "", ""
			}
			progs, err := scopemod.FetchScope(scopemod.Options{
				Platform: pl.plat, Username: a.Username, Token: a.Token, Email: a.Email, Password: a.Password,
				Categories: "all", Concurrency: 5, BBPOnly: true, IncludeOOS: true,
			})
			if err != nil {
				res.Errors = append(res.Errors, pl.code+"/"+a.Label+": "+err.Error())
				continue
			}
			if len(progs) == 0 {
				// bbscope's YWH/IT clients return nil,nil on a 401.
				res.Errors = append(res.Errors, pl.code+"/"+a.Label+": 0 programs returned (expired token?)")
				continue
			}
			buffered = append(buffered, progs...)
			// Each account's fetch uses its own creds, so the programs it got
			// back are exactly the ones that account can see (private included).
			for _, pd := range progs {
				if h := handleFromURL(pd.Url); h != "" && a.Label != "" {
					if vis[h] == nil {
						vis[h] = map[string]bool{}
					}
					vis[h][a.Label] = true
				}
			}
		}
		if len(buffered) == 0 {
			continue
		}
		replaceSource(pl.code, platformCatalogPrograms(buffered), &res)
		visByPlatform[pl.code] = sortedVisibility(vis)
	}
	persistProgramAccounts(visByPlatform, &res)
	return res, nil
}

// platformCatalogPrograms turns bbscope programs into catalog rows, merging
// duplicates (the same program seen by several accounts) by handle.
func platformCatalogPrograms(buffered []bbscope.ProgramData) []db.CatalogSourceProgram {
	idx := map[string]int{}
	var list []db.CatalogSourceProgram
	for _, pd := range buffered {
		handle := handleFromURL(pd.Url)
		if handle == "" {
			continue
		}
		var doms []db.CatalogDomain
		for _, e := range scopemod.CatalogEntries(pd) {
			doms = append(doms, db.CatalogDomain{Domain: e.Domain, InScope: e.InScope})
		}
		if i, ok := idx[handle]; ok {
			list[i].Domains = mergeCatalogDomains(list[i].Domains, doms)
			continue
		}
		idx[handle] = len(list)
		list = append(list, db.CatalogSourceProgram{
			Program: db.CatalogProgram{Company: titleize(handle), Handle: handle, URL: scopemod.PublicProgramURL(pd.Url), OffersBounty: true},
			Domains: doms,
		})
	}
	return list
}

// mergeCatalogDomains unions two entry lists; out-of-scope wins on conflict.
func mergeCatalogDomains(a, b []db.CatalogDomain) []db.CatalogDomain {
	pos := map[string]int{}
	for i, d := range a {
		pos[d.Domain] = i
	}
	for _, d := range b {
		if i, ok := pos[d.Domain]; ok {
			a[i].InScope = a[i].InScope && d.InScope
			continue
		}
		pos[d.Domain] = len(a)
		a = append(a, d)
	}
	return a
}

// replaceAllowed is the shrink guard: never replace a source with nothing,
// and never with fewer than half its current programs (partial fetch,
// expired account) unless CATALOG_SYNC_FORCE=true.
func replaceAllowed(prev, next int) bool {
	if next == 0 {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("CATALOG_SYNC_FORCE")), "true") {
		return true
	}
	return prev == 0 || next*2 >= prev
}

func replaceSource(code string, list []db.CatalogSourceProgram, res *SyncResult) {
	prev, err := db.CatalogSourceCount(code)
	if err != nil {
		res.Errors = append(res.Errors, code+": count: "+err.Error())
		return
	}
	if !replaceAllowed(prev, len(list)) {
		msg := fmt.Sprintf("%s: kept %d existing program(s) — new fetch had %d (empty or <50%% of previous; CATALOG_SYNC_FORCE=true overrides)", code, prev, len(list))
		res.Errors = append(res.Errors, msg)
		logger.GetLogger().Infof("[CATALOG-SYNC] %s", msg)
		return
	}
	if err := db.ReplaceCatalogSource(code, list); err != nil {
		res.Errors = append(res.Errors, code+": replace: "+err.Error())
		return
	}
	res.Sources[code] = len(list)
	res.Programs += len(list)
	for _, p := range list {
		res.Domains += len(p.Domains)
	}
}

// handleFromURL derives a program handle from its platform URL: the last
// path segment, ignoring a trailing "detail" segment — Intigriti program URLs
// end in /programs/<company>/<handle>/detail, and taking "detail" collapsed
// every IT program into one catalog row.
func handleFromURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	parts := strings.FieldsFunc(parsed.Path, func(r rune) bool { return r == '/' })
	if len(parts) > 1 && strings.EqualFold(parts[len(parts)-1], "detail") {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 {
		return strings.TrimPrefix(parsed.Host, "www.")
	}
	return parts[len(parts)-1]
}

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func titleize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ProgramAccountsKey is the settings key holding, as JSON, which account labels
// can see each program: "<source>|<handle>" -> ["label", ...]. Built at sync
// time (each account's fetch returns only what it can see), read by the API to
// show, on a finding, which account to submit from.
const ProgramAccountsKey = "bbp_program_accounts"

// sortedVisibility flattens handle -> label-set into handle -> sorted labels.
func sortedVisibility(vis map[string]map[string]bool) map[string][]string {
	out := make(map[string][]string, len(vis))
	for h, set := range vis {
		labels := make([]string, 0, len(set))
		for l := range set {
			labels = append(labels, l)
		}
		sort.Strings(labels)
		out[h] = labels
	}
	return out
}

// persistProgramAccounts merges this sync's per-source visibility into the
// stored blob, replacing only the sources that actually returned data (a
// platform whose accounts all failed keeps its last-known-good labels).
func persistProgramAccounts(byPlatform map[string]map[string][]string, res *SyncResult) {
	if len(byPlatform) == 0 {
		return
	}
	existing := map[string][]string{}
	if raw, _ := db.GetSetting(ProgramAccountsKey); raw != "" {
		_ = json.Unmarshal([]byte(raw), &existing)
	}
	for src := range byPlatform {
		for k := range existing {
			if strings.HasPrefix(k, src+"|") {
				delete(existing, k)
			}
		}
	}
	for src, m := range byPlatform {
		for h, labels := range m {
			if len(labels) > 0 {
				existing[src+"|"+h] = labels
			}
		}
	}
	b, err := json.Marshal(existing)
	if err != nil {
		res.Errors = append(res.Errors, "program-accounts: "+err.Error())
		return
	}
	if err := db.SetSetting(ProgramAccountsKey, string(b)); err != nil {
		res.Errors = append(res.Errors, "program-accounts save: "+err.Error())
	}
}
