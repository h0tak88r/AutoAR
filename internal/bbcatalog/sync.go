package bbcatalog

import (
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/accounts"
	"github.com/h0tak88r/AutoAR/internal/db"
	scopemod "github.com/h0tak88r/AutoAR/internal/scanner/scope"
)

// SyncResult summarises a catalog sync.
type SyncResult struct {
	Programs int            `json:"programs"`
	Domains  int            `json:"domains"`
	Sources  map[string]int `json:"sources"`
	Errors   []string       `json:"errors,omitempty"`
}

var syncMu sync.Mutex

var (
	syncStateMu sync.Mutex
	syncRunning bool
	lastSync    SyncResult
	lastSyncAt  time.Time
)

// SyncAsync kicks off a sync in the background. Returns false if one is already
// running (only one sync at a time).
func SyncAsync() bool {
	syncStateMu.Lock()
	if syncRunning {
		syncStateMu.Unlock()
		return false
	}
	syncRunning = true
	syncStateMu.Unlock()
	go func() {
		res, _ := Sync()
		syncStateMu.Lock()
		lastSync = res
		lastSyncAt = time.Now()
		syncRunning = false
		syncStateMu.Unlock()
	}()
	return true
}

// SyncStatus reports whether a sync is running plus the last result/time.
func SyncStatus() (running bool, last SyncResult, at time.Time) {
	syncStateMu.Lock()
	defer syncStateMu.Unlock()
	return syncRunning, lastSync, lastSyncAt
}

// Sync rebuilds the catalog: as93 (public/external, bounty-only, no domains) plus
// every authenticated platform account (programs + in/out-of-scope domains).
func Sync() (SyncResult, error) {
	syncMu.Lock()
	defer syncMu.Unlock()
	res := SyncResult{Sources: map[string]int{}}

	// 1. as93 aggregator — keyword source, real company names, no scope.
	if progs, err := As93Programs(); err != nil {
		res.Errors = append(res.Errors, "as93: "+err.Error())
	} else {
		_ = db.ClearCatalogSource("as93")
		for _, p := range progs {
			handle := p.Slug
			if handle == "" {
				handle = slugify(p.Company)
			}
			if handle == "" {
				continue
			}
			if _, err := db.UpsertCatalogProgram(db.CatalogProgram{
				Source: "as93", Company: p.Company, Handle: handle, URL: p.URL,
				Rewards: strings.Join(p.Rewards, ","), SafeHarbor: p.SafeHarbor, OffersBounty: true,
			}); err == nil {
				res.Sources["as93"]++
				res.Programs++
			}
		}
	}

	// 2. authenticated platforms — programs + in/out domains from every account.
	plats := map[string]scopemod.Platform{
		"h1":  scopemod.PlatformHackerOne,
		"bc":  scopemod.PlatformBugcrowd,
		"it":  scopemod.PlatformIntigriti,
		"ywh": scopemod.PlatformYesWeHack,
	}
	for code, plat := range plats {
		for _, a := range accounts.For(code) {
			progs, err := scopemod.FetchScope(scopemod.Options{
				Platform: plat, Username: a.Username, Token: a.Token, Email: a.Email, Password: a.Password,
				Categories: "all", Concurrency: 5, BBPOnly: true, IncludeOOS: true,
			})
			if err != nil {
				res.Errors = append(res.Errors, code+"/"+a.Label+": "+err.Error())
				continue
			}
			for _, pd := range progs {
				handle := handleFromURL(pd.Url)
				if handle == "" {
					continue
				}
				id, err := db.UpsertCatalogProgram(db.CatalogProgram{
					Source: code, Company: titleize(handle), Handle: handle, URL: pd.Url, OffersBounty: true,
				})
				if err != nil {
					continue
				}
				// In-scope wins when a root appears in both lists.
				domMap := map[string]bool{}
				for _, r := range scopemod.OutScopeRoots(pd) {
					domMap[r] = false
				}
				for _, r := range scopemod.InScopeRoots(pd) {
					domMap[r] = true
				}
				doms := make([]db.CatalogDomain, 0, len(domMap))
				for d, in := range domMap {
					doms = append(doms, db.CatalogDomain{Domain: d, InScope: in})
				}
				if err := db.ReplaceCatalogDomains(id, doms); err == nil {
					res.Domains += len(doms)
				}
				res.Sources[code]++
				res.Programs++
			}
		}
	}
	return res, nil
}

// handleFromURL derives a program handle from its platform URL (the last path segment).
func handleFromURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	parts := strings.FieldsFunc(parsed.Path, func(r rune) bool { return r == '/' })
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
