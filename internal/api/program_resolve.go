package api

// Which bug-bounty program a host belongs to — for Findings and the Program
// Lookup tool. The catalog keys on exact hosts and "*." wildcards, so a hit
// on 888kiss.aliexpress.com found nothing unless a program listed that host
// or *.aliexpress.com; 2,577 of 2,590 findings had no program. The resolver
// walks down to the registrable root:
//
//	in / out / paused — the catalog lists the host or a covering wildcard
//	                    (the only scope verdicts)
//	related           — a program lists only the root (or a parent): it owns
//	                    the domain, but the host is not explicitly in scope
//	guess             — no catalog entry; a program named like the root
//	                    domain ("aliexpress" for aliexpress.com)
//
// related and guess name the likely program; they never say "in scope".

import (
	"encoding/json"
	"fmt"
	urlpkg "net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/bbcatalog"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
	scopemod "github.com/h0tak88r/AutoAR/internal/scanner/scope"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// hostProgram is a resolved program for one host.
type hostProgram struct {
	Platform string // h1 | bc | ywh | it | bizone | source as stored
	Program  string // handle
	Company  string
	Match    string // in | out | paused | related | guess | "" (none)
	Via      string // catalog entry or root name it came from
}

// Label is "platform handle", the form Findings and triage use.
func (p hostProgram) Label() string { return strings.TrimSpace(p.Platform + " " + p.Program) }

// Seams for tests.
var (
	catalogByDomain  = db.SearchCatalogByDomain
	catalogByKeyword = db.SearchCatalogByKeyword
)

// resolveHostProgram finds the program a host most likely belongs to.
func resolveHostProgram(host string) hostProgram {
	host = db.NormalizeCatalogHost(host)
	if host == "" {
		return hostProgram{}
	}
	matches, _ := catalogByDomain(host, 20)
	var related *db.CatalogDomainMatch
	var live, paused, oos []db.CatalogDomainMatch
	var states map[string]string
	for i, m := range matches {
		switch {
		case m.MatchKind == db.CatalogMatchRelated:
			if related == nil {
				related = &matches[i] // most specific first (ClassifyCatalogMatches order)
			}
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
	from := func(m db.CatalogDomainMatch, match string) hostProgram {
		platform, program := catalogPlatform(m.Source, m.Handle, m.URL)
		return hostProgram{Platform: platform, Program: program, Company: m.Company, Match: match, Via: m.MatchedDomain}
	}
	switch {
	case len(live) > 0:
		return from(live[0], "in")
	case len(paused) > 0:
		return from(paused[0], "paused")
	case len(oos) > 0:
		return from(oos[0], "out")
	case related != nil:
		return from(*related, "related")
	}
	return guessProgramByRoot(host)
}

var nonAlnumRE = regexp.MustCompile(`[^a-z0-9]+`)

func normName(s string) string { return nonAlnumRE.ReplaceAllString(strings.ToLower(s), "") }

// rootName is the registrable domain's own label: 888kiss.aliexpress.com →
// aliexpress, spike-app.originenergy.com.au → originenergy.
func rootName(host string) (root, name string) {
	reg, ok := scopemod.RegistrableDomain(host)
	if !ok {
		return "", ""
	}
	name, _, _ = strings.Cut(reg, ".")
	return reg, name
}

// rootNamePrograms returns the catalog programs named like host's root
// domain. Only a whole-name match counts (company or handle equal to the
// name, or a handle that starts with it followed by a separator, e.g.
// "aliexpress-vdp"), so short or generic names can't latch onto unrelated
// programs. Bounty programs first.
func rootNamePrograms(host string) (root string, out []db.CatalogProgram) {
	root, name := rootName(host)
	if len(name) < 4 {
		return root, nil
	}
	progs, err := catalogByKeyword(name, 25)
	if err != nil {
		return root, nil
	}
	for _, p := range progs {
		handle := strings.ToLower(p.Handle)
		ok := normName(p.Company) == name || normName(p.Handle) == name
		if !ok && strings.HasPrefix(handle, name) && len(handle) > len(name) {
			next := handle[len(name)]
			ok = !(next >= 'a' && next <= 'z') && !(next >= '0' && next <= '9')
		}
		if ok {
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].OffersBounty && !out[j].OffersBounty })
	return root, out
}

// guessProgramByRoot is the best program named like the root domain.
func guessProgramByRoot(host string) hostProgram {
	root, progs := rootNamePrograms(host)
	if len(progs) == 0 {
		return hostProgram{}
	}
	best := progs[0]
	platform, program := catalogPlatform(best.Source, best.Handle, best.URL)
	return hostProgram{Platform: platform, Program: program, Company: best.Company, Match: "guess", Via: root}
}

// catalogPlatform maps a catalog row to Findings' platform + handle. The
// aggregator source (as93) carries the real platform only in its URL.
func catalogPlatform(source, handle, url string) (string, string) {
	platform, program := db.ProgramOf(source + " " + handle)
	if platform != "other" {
		return platform, program
	}
	u := strings.ToLower(url)
	for host, p := range map[string]string{"hackerone.com": "h1", "bugcrowd.com": "bc", "yeswehack.com": "ywh",
		"intigriti.com": "it", "bi.zone": "bizone", "immunefi.com": "immunefi"} {
		if strings.Contains(u, host) {
			return p, handle
		}
	}
	return "other", handle
}

// programPageURL is a platform's page for a handle, used ONLY when the handle
// IS the URL slug — HackerOne (hackerone.com/<handle>), YesWeHack and Immunefi.
// Bugcrowd and Intigriti are deliberately absent: a Bugcrowd engagement slug
// ("epam-mbb-og") is not the program handle ("epam"), so a fabricated
// engagements/<handle> link is wrong — those only link when the catalog has
// the real URL.
var programPageURL = map[string]string{
	"h1":       "https://hackerone.com/%s",
	"ywh":      "https://yeswehack.com/programs/%s",
	"immunefi": "https://immunefi.com/bug-bounty/%s/",
}

// attachProgramURLs links each finding's program to its real page. A finding
// without a program uses the AI review's scope_program ("h1 sea").
func attachProgramURLs(rows ...*db.Finding) {
	type key struct{ platform, program string }
	want := map[*db.Finding]key{}
	need := map[key]bool{}
	var handles []string
	for _, f := range rows {
		if f == nil {
			continue
		}
		k := key{f.Platform, f.Program}
		if k.program == "" && f.AI != nil && f.AI.ScopeProgram != "" {
			k.platform, k.program = db.ProgramOf(f.AI.ScopeProgram)
		}
		if k.program == "" {
			continue
		}
		want[f] = k
		if !need[k] {
			need[k] = true
			handles = append(handles, k.program)
		}
	}
	if len(want) == 0 {
		return
	}
	catalog, _ := db.CatalogProgramsByHandle(handles)
	accts := programAccountsMap()
	type res struct {
		url      string
		accounts []string
	}
	resFor := make(map[key]res, len(need))
	for k := range need {
		u, srcKey := resolveProgramURL(k.platform, k.program, catalog)
		// Visibility is keyed <platform>|<handle>. The catalog key handles a
		// near match (short "epam" → "bc|epam-mbb-og"); the direct key handles
		// the common case where the handle is already the catalog handle (and
		// programs not in the catalog, e.g. public ones).
		labels := accts[srcKey]
		if len(labels) == 0 {
			labels = accts[k.platform+"|"+k.program]
		}
		resFor[k] = res{url: u, accounts: labels}
	}
	for f, k := range want {
		r := resFor[k]
		f.ProgramURL = r.url
		f.ProgramAccounts = r.accounts
	}
}

// resolveProgramURL finds a program's real page and the catalog key
// ("<source>|<handle>") it matched. The URL is the catalog's stored URL (exact
// handle, then a near name match so "epam" resolves the "epam-mbb-og"
// engagement), else the platform's slug URL where the handle IS the slug (no
// key — a fabricated URL has no catalog row to read account visibility from).
func resolveProgramURL(platform, program string, exact map[string][]db.CatalogProgram) (url, key string) {
	for _, c := range exact[strings.ToLower(program)] {
		if p, _ := catalogPlatform(c.Source, c.Handle, c.URL); (p == platform || platform == "") && isHTTPURL(c.URL) {
			return scopemod.PublicProgramURL(c.URL), c.Source + "|" + c.Handle
		}
	}
	if u, k := catalogNearURL(platform, program); u != "" {
		return u, k
	}
	if tpl := programPageURL[platform]; tpl != "" {
		return fmt.Sprintf(tpl, urlpkg.PathEscape(program)), ""
	}
	return "", ""
}

// catalogNearURL finds a catalog program on the same platform whose handle or
// company matches the program name, or whose handle is the name plus a
// separator ("epam" → "epam-mbb-og"), and returns its real URL and catalog key.
func catalogNearURL(platform, program string) (url, key string) {
	name := normName(program)
	if len(name) < 3 {
		return "", ""
	}
	progs, err := catalogByKeyword(program, 25)
	if err != nil {
		return "", ""
	}
	lp := strings.ToLower(program)
	var fbURL, fbKey string
	for i := range progs {
		c := progs[i]
		if p, _ := catalogPlatform(c.Source, c.Handle, c.URL); platform != "" && p != platform {
			continue
		}
		if !isHTTPURL(c.URL) {
			continue
		}
		if normName(c.Handle) == name || normName(c.Company) == name {
			return scopemod.PublicProgramURL(c.URL), c.Source + "|" + c.Handle // whole-name match wins
		}
		h := strings.ToLower(c.Handle)
		if fbURL == "" && strings.HasPrefix(h, lp) && len(h) > len(lp) {
			if next := h[len(lp)]; !(next >= 'a' && next <= 'z') && !(next >= '0' && next <= '9') {
				fbURL, fbKey = scopemod.PublicProgramURL(c.URL), c.Source+"|"+c.Handle
			}
		}
	}
	return fbURL, fbKey
}

// programAccountsMap caches bbp_program_accounts (which account labels can see
// each program, built at catalog sync) for a few minutes.
var (
	progAcctMu    sync.Mutex
	progAcctCache map[string][]string
	progAcctAt    time.Time
)

const progAcctTTL = 5 * time.Minute

func programAccountsMap() map[string][]string {
	progAcctMu.Lock()
	defer progAcctMu.Unlock()
	if progAcctCache != nil && time.Since(progAcctAt) < progAcctTTL {
		return progAcctCache
	}
	m := map[string][]string{}
	if raw, _ := db.GetSetting(bbcatalog.ProgramAccountsKey); raw != "" {
		_ = json.Unmarshal([]byte(raw), &m)
	}
	progAcctCache, progAcctAt = m, time.Now()
	return m
}

func isHTTPURL(s string) bool {
	u, err := urlpkg.Parse(strings.TrimSpace(s))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// Hosts repeat a lot in one scan (and roots far more); resolutions are
// cached for a while so ingesting 20k hits costs a few hundred lookups.
var (
	hostProgramMu    sync.Mutex
	hostProgramCache = map[string]hostProgramEntry{}
	hostProgramTTL   = 30 * time.Minute
)

type hostProgramEntry struct {
	p  hostProgram
	at time.Time
}

func resolveHostProgramCached(host string) hostProgram {
	key := db.NormalizeCatalogHost(host)
	hostProgramMu.Lock()
	if e, ok := hostProgramCache[key]; ok && time.Since(e.at) < hostProgramTTL {
		hostProgramMu.Unlock()
		return e.p
	}
	hostProgramMu.Unlock()
	p := resolveHostProgram(key)
	hostProgramMu.Lock()
	if len(hostProgramCache) > 20000 {
		hostProgramCache = map[string]hostProgramEntry{}
	}
	hostProgramCache[key] = hostProgramEntry{p: p, at: time.Now()}
	hostProgramMu.Unlock()
	return p
}

// StartFindingProgramBackfill fills the program of findings that have none,
// shortly after boot and then daily (the catalog grows; a host unknown today
// may be listed tomorrow). Programs set by hand are never touched.
func StartFindingProgramBackfill() {
	utils.SafeGo("findings:program-backfill", func() {
		time.Sleep(90 * time.Second)
		for {
			filled, checked := backfillFindingPrograms()
			if checked > 0 {
				logger.GetLogger().Infof("[findings] program backfill: %d of %d finding(s) without a program resolved", filled, checked)
			}
			time.Sleep(24 * time.Hour)
		}
	})
}

// backfillFindingPrograms resolves every finding without a program once.
func backfillFindingPrograms() (filled, checked int) {
	var after int64
	for {
		rows, err := db.FindingsMissingProgram(after, 500)
		if err != nil || len(rows) == 0 {
			return
		}
		for _, g := range rows {
			after = g.ID
			checked++
			hp := resolveHostProgramCached(g.Host)
			if hp.Match == "" || hp.Program == "" {
				continue
			}
			if db.SetFindingProgram(g.ID, hp.Platform, hp.Program, hp.Match) == nil {
				filled++
			}
		}
	}
}
