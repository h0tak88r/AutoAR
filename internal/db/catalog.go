package db

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Package-level wrappers for the bug-bounty program catalog.

func UpsertCatalogProgram(c CatalogProgram) (int64, error) {
	if err := Init(); err != nil {
		return 0, err
	}
	return dbInstance.UpsertCatalogProgram(c)
}

func ReplaceCatalogDomains(programID int64, domains []CatalogDomain) error {
	if err := Init(); err != nil {
		return err
	}
	return dbInstance.ReplaceCatalogDomains(programID, domains)
}

func ClearCatalogSource(source string) error {
	if err := Init(); err != nil {
		return err
	}
	return dbInstance.ClearCatalogSource(source)
}

func SearchCatalogByKeyword(q string, limit int) ([]CatalogProgram, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	return dbInstance.SearchCatalogByKeyword(q, limit)
}

// SearchCatalogByDomain resolves which catalog programs concern a host. The
// catalog stores exact hosts ("app.acme.com") and wildcards ("*.acme.com");
// the lookup is an exact-key match over the host and its parents (no LIKE —
// example.com must never match notexample.com or example.com.evil.io), and
// every result carries a per-program verdict: exact/wildcard coverage with
// out-of-scope entries taking precedence, or "related" when the program only
// lists a parent host. See ClassifyCatalogMatches.
func SearchCatalogByDomain(q string, limit int) ([]CatalogDomainMatch, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	host := NormalizeCatalogHost(q)
	if host == "" {
		return nil, nil
	}
	// One program can match through several rows (exact + wildcard + parent),
	// so over-fetch before collapsing to one verdict per program.
	rows, err := dbInstance.SearchCatalogByDomain(host, limit*8+20)
	if err != nil {
		return nil, err
	}
	return ClassifyCatalogMatches(host, rows, limit), nil
}

func CatalogCounts() (int, int, error) {
	if err := Init(); err != nil {
		return 0, 0, err
	}
	return dbInstance.CatalogCounts()
}

// Catalog match kinds (CatalogDomainMatch.MatchKind).
const (
	CatalogMatchExact    = "exact"    // the catalog lists this exact host
	CatalogMatchWildcard = "wildcard" // a "*.parent" entry covers the host
	CatalogMatchRelated  = "related"  // only a parent host (or "*.host" itself) is listed: same org, host NOT covered
)

// NormalizeCatalogHost reduces a lookup query (URL, host:port, mixed case)
// to the bare lowercase host the catalog keys on. "" when nothing usable.
func NormalizeCatalogHost(q string) string {
	h := strings.ToLower(strings.TrimSpace(q))
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	if strings.Count(h, ":") == 1 {
		h = h[:strings.Index(h, ":")]
	}
	h = strings.TrimPrefix(strings.Trim(h, "."), "*.")
	if h == "" || !strings.Contains(h, ".") || strings.ContainsAny(h, " \t\r\n*%") {
		return ""
	}
	return h
}

// catalogDomainCandidates lists every catalog key that can concern host:
// the host and each parent with at least two labels, both as an exact entry
// and as a "*." wildcard. api.example.com → [api.example.com,
// *.api.example.com, example.com, *.example.com].
func catalogDomainCandidates(host string) []string {
	labels := strings.Split(host, ".")
	var out []string
	for i := 0; i+2 <= len(labels); i++ {
		s := strings.Join(labels[i:], ".")
		out = append(out, s, "*."+s)
	}
	return out
}

// catalogMatchKind classifies one catalog entry against host ("" = unrelated).
func catalogMatchKind(host, entry string) string {
	entry = strings.ToLower(strings.TrimSpace(entry))
	switch {
	case entry == host:
		return CatalogMatchExact
	case strings.HasPrefix(entry, "*."):
		base := entry[2:]
		if base == host {
			// "*.acme.com" vs acme.com: whether the apex is included depends on
			// the program's wording — report the relation, not coverage.
			return CatalogMatchRelated
		}
		if strings.HasSuffix(host, "."+base) {
			return CatalogMatchWildcard
		}
	case strings.HasSuffix(host, "."+entry):
		return CatalogMatchRelated
	}
	return ""
}

// ClassifyCatalogMatches collapses raw catalog rows (one per matching entry)
// into one verdict per program for host, sorted in-scope → out-of-scope →
// related, most specific entry first:
//   - any covering (exact/wildcard) OUT-of-scope entry wins → InScope=false;
//   - else the most specific covering in-scope entry → InScope=true;
//   - else the program only lists a parent → MatchKind=related, InScope=false.
func ClassifyCatalogMatches(host string, rows []CatalogDomainMatch, limit int) []CatalogDomainMatch {
	type verdict struct {
		in, oos, rel *CatalogDomainMatch
	}
	specificity := func(m *CatalogDomainMatch) int {
		n := len(strings.TrimPrefix(m.MatchedDomain, "*."))
		if m.MatchKind == CatalogMatchExact {
			n += 1000
		}
		return n
	}
	better := func(cur, cand *CatalogDomainMatch) bool {
		return cur == nil || specificity(cand) > specificity(cur)
	}
	byProgram := map[int64]*verdict{}
	var order []int64
	for i := range rows {
		m := rows[i]
		m.MatchKind = catalogMatchKind(host, m.MatchedDomain)
		if m.MatchKind == "" {
			continue
		}
		v := byProgram[m.ID]
		if v == nil {
			v = &verdict{}
			byProgram[m.ID] = v
			order = append(order, m.ID)
		}
		switch {
		case m.MatchKind == CatalogMatchRelated:
			if better(v.rel, &m) {
				v.rel = &m
			}
		case !m.InScope:
			if better(v.oos, &m) {
				v.oos = &m
			}
		default:
			if better(v.in, &m) {
				v.in = &m
			}
		}
	}
	out := make([]CatalogDomainMatch, 0, len(order))
	rank := map[int64]int{}
	for _, id := range order {
		v := byProgram[id]
		var m CatalogDomainMatch
		switch {
		case v.oos != nil:
			m = *v.oos
			m.InScope = false
			rank[id] = 1
		case v.in != nil:
			m = *v.in
			m.InScope = true
			rank[id] = 0
		default:
			m = *v.rel
			m.InScope = false
			rank[id] = 2
		}
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := rank[out[i].ID], rank[out[j].ID]
		if ri != rj {
			return ri < rj
		}
		if si, sj := specificity(&out[i]), specificity(&out[j]); si != sj {
			return si > sj
		}
		return strings.ToLower(out[i].Company) < strings.ToLower(out[j].Company)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// escapeLike escapes LIKE/ILIKE metacharacters so a user query matches
// literally (used with ESCAPE '\').
func escapeLike(q string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q)
}

// CatalogSourceProgram is one program plus its host-level scope rows, the
// unit ReplaceCatalogSource writes.
type CatalogSourceProgram struct {
	Program CatalogProgram
	Domains []CatalogDomain
}

var (
	_ catalogSourceStore = (*SQLiteDB)(nil)
	_ catalogSourceStore = (*PostgresDB)(nil)
)

// catalogSourceStore is implemented by the SQLite and Postgres backends: an
// atomic per-source replace, the per-source program count, and a
// cross-process sync lock.
type catalogSourceStore interface {
	replaceCatalogSource(source string, progs []CatalogSourceProgram) error
	catalogSourceCount(source string) (int, error)
	tryCatalogSyncLock(owner string, ttl time.Duration) (release func(), ok bool, err error)
}

// ReplaceCatalogSource atomically swaps every row of one catalog source
// (programs + their domains) for progs, inside one transaction — a crash or
// SIGKILL mid-sync leaves the previous catalog intact instead of a half-empty
// one.
func ReplaceCatalogSource(source string, progs []CatalogSourceProgram) error {
	if err := Init(); err != nil {
		return err
	}
	if s, ok := dbInstance.(catalogSourceStore); ok {
		return s.replaceCatalogSource(source, progs)
	}
	// Non-transactional fallback for other DB implementations (tests/mocks).
	if err := dbInstance.ClearCatalogSource(source); err != nil {
		return err
	}
	for _, p := range progs {
		c := p.Program
		c.Source = source
		id, err := dbInstance.UpsertCatalogProgram(c)
		if err != nil {
			return err
		}
		if err := dbInstance.ReplaceCatalogDomains(id, p.Domains); err != nil {
			return err
		}
	}
	return nil
}

// CatalogSourceCount returns how many programs a source currently holds.
func CatalogSourceCount(source string) (int, error) {
	if err := Init(); err != nil {
		return 0, err
	}
	if s, ok := dbInstance.(catalogSourceStore); ok {
		return s.catalogSourceCount(source)
	}
	return 0, nil
}

const catalogSyncLockKey = "catalog_sync_lock"

// TryCatalogSyncLock takes the cross-process catalog-sync lock: a session
// advisory lock on Postgres (released automatically if the holder dies), a
// settings-row lease expiring after ttl on SQLite. ok=false means another
// process is syncing. release must be called when done.
func TryCatalogSyncLock(ttl time.Duration) (release func(), ok bool, err error) {
	if err := Init(); err != nil {
		return nil, false, err
	}
	if s, isStore := dbInstance.(catalogSourceStore); isStore {
		host, _ := os.Hostname()
		owner := host + ":" + strconv.Itoa(os.Getpid()) + ":" + strconv.FormatInt(time.Now().UnixNano(), 10)
		return s.tryCatalogSyncLock(owner, ttl)
	}
	return func() {}, true, nil
}
