package api

// Fingerprint-targeted nuclei: instead of running a template against every live
// host (~600k), derive the technology it targets from its tags and run it only
// against hosts whose stored fingerprint (tech stack / title / server) matches.
// A WordPress CVE then hits the WordPress hosts, not the whole fleet.
//
// It reuses the race-pass machinery: raceTechKeywords' stop-list for tags and
// db.MatchHostsByFingerprint for the host lookup.

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// targetedHostCap bounds a targeted run; past this it's not really "targeted"
// and the full sweep is the better tool. MatchHostsByFingerprint caps at 20000.
const targetedHostCap = 20000

var (
	tplTagsRE = regexp.MustCompile(`(?mi)^\s*tags:\s*(.+)$`)
	// cve2026, 2026, cwe-79, kev2026 … are class/year noise, not technologies.
	genericTagRE = regexp.MustCompile(`^(cve|cwe|kev|wpscan|edb|osvdb|packetstorm)?[-_]?\d+$`)
)

// templateTechKeywords reads the template (a file or a dir of templates) and
// returns the technology-identifying tags across all of them, dropping the
// vulnerability-class noise (racePassStopTags).
func templateTechKeywords(path string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(raw string) {
		for _, tag := range splitTags(raw) {
			tag = strings.ToLower(strings.TrimSpace(tag))
			if tag == "" || racePassStopTags[tag] || seen[tag] || len(tag) < 3 || genericTagRE.MatchString(tag) {
				continue
			}
			seen[tag] = true
			out = append(out, tag)
		}
	}
	// Raw YAML passed straight through (not a path on disk).
	if strings.Contains(path, "\n") || strings.HasPrefix(path, "id:") {
		for _, m := range tplTagsRE.FindAllStringSubmatch(path, -1) {
			add(m[1])
		}
		return out
	}
	st, err := os.Stat(path)
	if err != nil {
		return out
	}
	readFile := func(p string) {
		raw, err := os.ReadFile(p)
		if err != nil {
			return
		}
		for _, m := range tplTagsRE.FindAllStringSubmatch(string(raw), -1) {
			add(m[1])
		}
	}
	if !st.IsDir() {
		readFile(path)
		return out
	}
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if n := strings.ToLower(d.Name()); strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml") {
			readFile(p)
		}
		return nil
	})
	return out
}

// splitTags splits a nuclei `tags:` value: comma or space separated, with
// optional [brackets] / quotes.
func splitTags(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	s = strings.ReplaceAll(s, "\"", "")
	s = strings.ReplaceAll(s, "'", "")
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
}

// fingerprintedHostURLs returns the live host URLs whose fingerprint matches
// any keyword, deduped and sorted (stable order). Empty when nothing matches.
func fingerprintedHostURLs(keywords []string, cap int) ([]string, error) {
	if len(keywords) == 0 {
		return nil, nil
	}
	if cap <= 0 || cap > targetedHostCap {
		cap = targetedHostCap
	}
	matched, _, err := db.MatchHostsByFingerprint(keywords, cap)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var urls []string
	for _, h := range matched {
		u := h.URL
		if u == "" {
			u = h.Subdomain
		}
		if u != "" && !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}
	sort.Strings(urls)
	return urls, nil
}

// batchesFromHosts writes a pre-resolved host list into batch files of at most
// batchMax each, matching what dumpLiveHostBatches produces (so the sweep's
// batch loop is identical). ends is unused for a targeted run (no id cursor).
func batchesFromHosts(hosts []string, batchMax int) (*hostBatches, error) {
	b := &hostBatches{}
	var cur *os.File
	n := 0
	newBatch := func() error {
		f, err := os.CreateTemp("", "nuclei-targeted-*.txt")
		if err != nil {
			return err
		}
		b.files = append(b.files, f.Name())
		cur, n = f, 0
		return nil
	}
	if err := newBatch(); err != nil {
		return nil, err
	}
	for _, h := range hosts {
		if n >= batchMax {
			cur.Close()
			b.ends, b.hosts = append(b.ends, 0), append(b.hosts, n)
			if err := newBatch(); err != nil {
				b.remove()
				return nil, err
			}
		}
		cur.WriteString(h + "\n")
		n++
		b.total++
	}
	cur.Close()
	b.ends, b.hosts = append(b.ends, 0), append(b.hosts, n)
	return b, nil
}
