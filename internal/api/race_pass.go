package api

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/scanner/nuclei"
	"github.com/h0tak88r/AutoAR/internal/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
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

	// Max race passes launched per watch cycle: a bulk template drop can't
	// stampede the box with parallel fast passes.
	racePassMaxScansPerCycle = 2
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
	racePassLaunched int // per watch cycle, reset by the caller

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
// itself by hours (exactly the window the race pass exists for).
func racePassEligible(t pdcpTemplate) bool {
	if racePassCVE(t) == "" {
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

// raceFingerprintedHosts unions every host whose stored tech stack or
// historical nuclei matches mention one of the keywords. Second return is the
// keyword that produced each host (for the alert).
func raceFingerprintedHosts(keywords []string) (map[string]string, error) {
	hostSrc := map[string]string{}
	for _, kw := range keywords {
		// 1. Stored tech stacks (httpx -tech output, comma-separated products).
		limit, offset := 1000, 0
		for {
			subs, _, err := db.ListAllSubdomainsPaginated("", kw, "", 0, true, limit, offset)
			if err != nil {
				return hostSrc, err
			}
			for _, s := range subs {
				target := s.BestURL()
				if target == "" {
					target = s.Subdomain
				}
				if target != "" {
					if _, dup := hostSrc[target]; !dup {
						hostSrc[target] = "techs:" + kw
					}
				}
			}
			if len(subs) < limit {
				break
			}
			offset += limit
		}
		// 2. Historical nuclei hits on same-tech templates (cached index).
		for host := range raceHistoricalHosts(kw) {
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

// runRacePass executes one fast pass for an eligible template. Safe to call as
// a goroutine; single-flight so overlapping watch cycles can't stack passes.
func runRacePass(t pdcpTemplate) {
	racePassMu.Lock()
	if racePassInFlight {
		racePassMu.Unlock()
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

	// Durable per-scan template dir (same pattern as the watch staging): the
	// exact template a race pass ran stays retrievable and rescanable.
	tplDir := filepath.Join(utils.GetResultsDir(), "global-subdomains", "templates", scanID)
	if err := os.MkdirAll(tplDir, 0o755); err != nil {
		logger.GetLogger().Infof("[RACE-PASS] template dir failed: %v", err)
		return
	}
	tplPath := filepath.Join(tplDir, strings.ToLower(cve)+".yaml")
	if err := os.WriteFile(tplPath, []byte(t.Raw), 0o600); err != nil {
		logger.GetLogger().Infof("[RACE-PASS] template write failed: %v", err)
		return
	}

	targets, err := os.CreateTemp("", "race-targets-*.txt")
	if err != nil {
		return
	}
	for host := range hosts {
		target := host
		if !strings.Contains(target, "://") {
			target = "https://" + target
		}
		targets.WriteString(target + "\n")
	}
	targets.Close()
	defer os.Remove(targets.Name())

	outDir := filepath.Join(utils.GetResultsDir(), "global-subdomains", "vulnerabilities")
	os.MkdirAll(outDir, 0o755)
	outPath := filepath.Join(outDir, "nuclei-"+scanID+".json")

	var (
		mu      sync.Mutex
		matches []raceMatch
	)
	onResult := func(event *output.ResultEvent) {
		if event == nil || event.TemplateID == "" {
			return
		}
		matched := event.Matched
		if matched == "" {
			matched = event.URL
		}
		mu.Lock()
		matches = append(matches, raceMatch{
			TemplateID: event.TemplateID,
			Matched:    matched,
			Curl:       strings.TrimSpace(event.CURLCommand),
			Severity:   event.Info.SeverityHolder.Severity.String(),
		})
		mu.Unlock()
	}

	recordScanInitiator(scanID, "system")
	command := fmt.Sprintf("inprocess:nuclei target=race-pass template=%s", tplDir)
	logger.GetLogger().Infof("[RACE-PASS] %s: running %s against %d fingerprinted host(s) (scan %s)",
		cve, t.ID, len(hosts), scanID)
	utils.SendMonitorWebhook(fmt.Sprintf(
		"⚡ **Race pass** — `%s` (%s) against **%d** fingerprinted host(s) (scan `%s`) — full auto-run continues independently.",
		cve, t.ID, len(hosts), scanID))

	RunScanInProcessWithCommand(scanID, "nuclei", "race-pass", command, func() error {
		ctx, cancel := context.WithTimeout(scanContext(scanID), racePassTimeout)
		defer cancel()
		return nuclei.RunGlobalTemplate(ctx, targets.Name(), tplPath, outPath, racePassThreads, onResult)
	})

	mu.Lock()
	defer mu.Unlock()
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
	fmt.Fprintf(&b, "🚨 **RACE PASS MATCHES — `%s`** (%s, scan `%s`)\n", cve, templateID, scanID)
	fmt.Fprintf(&b, "⏸ **NOTHING will be submitted — drafts staged, awaiting owner approval**\n")
	for _, m := range matches {
		host := raceHostOf(m.Matched)
		programs := raceProgramsForHost(host)
		verdict := "no catalog match — unsure scope"
		progLine := ""
		if len(programs) > 0 {
			p := programs[0]
			if p.InScope {
				verdict = "IN SCOPE"
			} else {
				verdict = "catalog-listed OUT of scope"
			}
			progLine = fmt.Sprintf(" — %s `%s`", p.Source, p.Handle)
		}
		draftPath := raceStageDraft(cve, templateID, host, m, programs, draftDir)
		fmt.Fprintf(&b, "• `%s` — %s%s\n  📄 draft: `%s`\n", m.Matched, verdict, progLine, draftPath)
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

// raceProgramsForHost resolves the owning catalog programs for a matched host
// by walking the host's parent domains and keeping exact in-catalog matches.
func raceProgramsForHost(host string) []db.CatalogDomainMatch {
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	labels := strings.Split(host, ".")
	seen := map[string]bool{}
	var out []db.CatalogDomainMatch
	for i := 0; i < len(labels)-1; i++ {
		cand := strings.Join(labels[i:], ".")
		if seen[cand] {
			continue
		}
		seen[cand] = true
		matches, err := db.SearchCatalogByDomain(cand, 20)
		if err != nil {
			continue
		}
		for _, m := range matches {
			// Exact-only: partial ILIKE hits on subdomain strings would
			// misattribute hosts to unrelated programs.
			if !strings.EqualFold(m.MatchedDomain, cand) {
				continue
			}
			dup := false
			for _, e := range out {
				if e.Source == m.Source && e.Handle == m.Handle {
					dup = true
					break
				}
			}
			if !dup {
				out = append(out, m)
			}
		}
	}
	return out
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
