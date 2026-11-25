package db

// The merged Findings pipeline: scan hits become findings (keyed by fkey),
// the AI review lives in ai_triage under the same key and is joined on read.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// RecordScanFinding stores a scan-sourced finding keyed by f.FKey. A hit seen
// before only refreshes last_seen and the latest scan id; the operator's
// status, notes and report are never touched by a re-scan.
func RecordScanFinding(f *Finding) (created bool, err error) {
	if strings.TrimSpace(f.FKey) == "" {
		return false, fmt.Errorf("scan finding needs an fkey")
	}
	c, _, err := findingDB()
	if err != nil {
		return false, err
	}
	var id int64
	if err := c.query(`SELECT id FROM findings WHERE fkey = ? LIMIT 1`, func(r rowScanner) error {
		return r.Scan(&id)
	}, f.FKey); err != nil {
		return false, err
	}
	now := time.Now().UTC().Unix()
	if id != 0 {
		f.ID = id
		// A hit seen again fills a program that is still missing (the
		// catalog grows); a program already set — by hand or earlier — stays.
		return false, c.exec(`UPDATE findings SET last_seen = ?, scan_id = ?,
			platform = CASE WHEN program = '' THEN ? ELSE platform END,
			program_match = CASE WHEN program = '' THEN ? ELSE program_match END,
			program = CASE WHEN program = '' THEN ? ELSE program END
			WHERE id = ?`, now, f.ScanID, f.Platform, f.ProgramMatch, f.Program, id)
	}
	if f.FirstSeen == 0 {
		f.FirstSeen = now
	}
	f.LastSeen = now
	return true, CreateFinding(f)
}

// ValidReportRef accepts a platform report id ("H1#2401337") or an http(s)
// URL. The dashboard renders links, so no other URL scheme may be stored.
func ValidReportRef(ref string) error {
	low := strings.ToLower(strings.TrimSpace(ref))
	bad := fmt.Errorf("report link must be an http(s) URL or a platform report id")
	if i := strings.Index(low, "://"); i >= 0 {
		if scheme := low[:i]; scheme != "http" && scheme != "https" {
			return bad
		}
		return nil
	}
	for _, scheme := range []string{"javascript:", "data:", "vbscript:", "file:"} {
		if strings.HasPrefix(low, scheme) {
			return bad
		}
	}
	return nil
}

// FindingProgramGap is a finding without a program (backfill input).
type FindingProgramGap struct {
	ID   int64
	Host string
}

// FindingsMissingProgram returns up to limit findings with no program and a
// host, id > afterID, oldest first.
func FindingsMissingProgram(afterID int64, limit int) ([]FindingProgramGap, error) {
	c, _, err := findingDB()
	if err != nil {
		return nil, err
	}
	var out []FindingProgramGap
	err = c.query(`SELECT id, host FROM findings WHERE program = '' AND host <> '' AND id > ? ORDER BY id LIMIT ?`,
		func(r rowScanner) error {
			var g FindingProgramGap
			if err := r.Scan(&g.ID, &g.Host); err != nil {
				return err
			}
			out = append(out, g)
			return nil
		}, afterID, limit)
	return out, err
}

// SetFindingProgram stores a resolved program on a finding that has none
// (a program set meanwhile, e.g. by hand, is never overwritten).
func SetFindingProgram(id int64, platform, program, match string) error {
	c, _, err := findingDB()
	if err != nil {
		return err
	}
	return c.exec(`UPDATE findings SET platform = ?, program = ?, program_match = ? WHERE id = ? AND program = ''`,
		platform, truncateRunes(program, 200), match, id)
}

// CatalogProgramsByHandle returns the catalog programs with these handles
// (case-insensitive), keyed by lower-case handle — for linking Findings'
// program chips to the program page.
func CatalogProgramsByHandle(handles []string) (map[string][]CatalogProgram, error) {
	out := map[string][]CatalogProgram{}
	var args []any
	seen := map[string]bool{}
	for _, h := range handles {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" && !seen[h] {
			seen[h] = true
			args = append(args, h)
		}
	}
	if len(args) == 0 {
		return out, nil
	}
	c, _, err := findingDB()
	if err != nil {
		return out, err
	}
	err = c.query(`SELECT source, handle, company, url FROM bbp_catalog_programs WHERE lower(handle) IN (?`+
		strings.Repeat(",?", len(args)-1)+`) ORDER BY id`, func(r rowScanner) error {
		var p CatalogProgram
		if err := r.Scan(&p.Source, &p.Handle, &p.Company, &p.URL); err != nil {
			return err
		}
		k := strings.ToLower(p.Handle)
		out[k] = append(out[k], p)
		return nil
	}, args...)
	return out, err
}

// SetFindingReminder sets (or clears, at=0) the time to resurface a finding.
// updated_at is untouched so setting a reminder doesn't reorder the list.
func SetFindingReminder(id, at int64) error {
	c, _, err := findingDB()
	if err != nil {
		return err
	}
	return c.exec(`UPDATE findings SET remind_at = ? WHERE id = ?`, at, id)
}

// DueFindingReminders returns findings whose reminder has arrived (remind_at
// in (0, now]), oldest-due first.
func DueFindingReminders(now int64, limit int) ([]*Finding, error) {
	rows, _, err := ListFindings(FindingFilter{RemindDueBefore: now, Limit: limit})
	return rows, err
}

// SetFindingFKey links a finding (e.g. a manual one sent for AI review) to
// the ai_triage key its review is stored under.
func SetFindingFKey(id int64, fkey string) error {
	c, _, err := findingDB()
	if err != nil {
		return err
	}
	return c.exec(`UPDATE findings SET fkey = ? WHERE id = ?`, fkey, id)
}

// SetFindingVerdict records the operator's verdict for a finding. Findings the
// AI never reviewed get a minimal review row (status "human") so the label
// joins like any other.
func SetFindingVerdict(f *Finding, verdict string) error {
	if f.FKey == "" {
		return fmt.Errorf("finding %d has no scan key", f.ID)
	}
	now := time.Now().UTC().Unix()
	if prev, err := GetTriage(f.FKey); err == nil && prev != nil {
		return SetTriageHumanVerdict(f.FKey, verdict, now)
	}
	return UpsertTriage(&TriageRecord{
		ID: f.FKey, ScanID: f.ScanID, TemplateID: f.TemplateID, Title: f.Title, Host: f.Host,
		MatchedAt: f.MatchedAt, Severity: f.Severity, Status: "human", HumanVerdict: verdict,
		CreatedAt: now, UpdatedAt: now,
	})
}

// DeleteFindings removes findings by id. Their AI reviews stay cached, so a
// later scan that sees the same hit re-creates it with the label intact.
func DeleteFindings(ids []int64) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	c, _, err := findingDB()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		var got int64
		if err := c.query(`DELETE FROM findings WHERE id = ? RETURNING id`, func(r rowScanner) error {
			return r.Scan(&got)
		}, id); err != nil {
			return n, err
		}
		if got != 0 {
			n++
		}
	}
	return n, nil
}

// FindingFacets counts findings per AI label and per status (optionally for
// one scan) for the filter chips.
type FindingFacets struct {
	Total     int            `json:"total"`
	AI        map[string]int `json:"ai"`
	Status    map[string]int `json:"status"`
	Platforms map[string]int `json:"platforms"`
	Programs  []ProgramFacet `json:"programs"`   // most findings first, at most 300
	NoProgram int            `json:"no_program"` // findings without a program
	Reported  int            `json:"reported"`   // findings with a report link
	Closed    int            `json:"closed"`     // rejected / dup / wontfix (hidden when HideClosed)
}

// ProgramFacet is one program and how many findings it has.
type ProgramFacet struct {
	Platform string `json:"platform"`
	Program  string `json:"program"`
	Count    int    `json:"count"`
}

// NoProgram is the FindingFilter.Program value for "no program".
const NoProgram = "__none__"

func GetFindingFacets(scanID string) (FindingFacets, error) {
	return GetFindingFacetsOpts(scanID, false)
}

// GetFindingFacetsOpts is GetFindingFacets over the dashboard's view: with
// hideClosed the counts leave out rejected / dup / wontfix findings (Closed
// still reports how many there are, for the "show closed" toggle).
func GetFindingFacetsOpts(scanID string, hideClosed bool) (FindingFacets, error) {
	out := FindingFacets{AI: map[string]int{}, Status: map[string]int{}, Platforms: map[string]int{}, Programs: []ProgramFacet{}}
	c, _, err := findingDB()
	if err != nil {
		return out, err
	}
	scope, args := "1=1", []any{}
	if scanID != "" {
		scope, args = "f.scan_id = ?", []any{scanID}
	}
	if err := c.query(`SELECT COUNT(*) FROM findings f WHERE `+scope+` AND f.status IN (`+closedStatusList+`)`, func(r rowScanner) error {
		var n int64
		err := r.Scan(&n)
		out.Closed = int(n)
		return err
	}, args...); err != nil {
		return out, err
	}
	where := scope
	if hideClosed {
		where += ` AND f.status NOT IN (` + closedStatusList + `)`
	}
	v := "(" + findingEffectiveVerdict + ")"
	sum := func(cond string) string {
		return `CAST(COALESCE(SUM(CASE WHEN ` + cond + ` THEN 1 ELSE 0 END), 0) AS BIGINT)`
	}
	var total, rep, tp, likely, review, fp, unrev, errs int64
	err = c.query(`SELECT COUNT(*), `+
		sum(findingReportableCond)+`, `+
		sum(v+` = 'true_positive'`)+`, `+sum(v+` = 'likely'`)+`, `+sum(v+` = 'needs_manual_review'`)+`, `+
		sum(v+` = 'false_positive'`)+`, `+
		sum(findingUnreviewedCond)+`, `+
		sum(findingAIErrorCond)+
		findingFrom+`WHERE `+where, func(r rowScanner) error {
		return r.Scan(&total, &rep, &tp, &likely, &review, &fp, &unrev, &errs)
	}, args...)
	if err != nil {
		return out, err
	}
	out.Total = int(total)
	out.AI = map[string]int{"reportable": int(rep), "true_positive": int(tp), "likely": int(likely),
		"needs_manual_review": int(review), "false_positive": int(fp), "unreviewed": int(unrev), "error": int(errs)}
	err = c.query(`SELECT f.status, COUNT(*) FROM findings f WHERE `+where+` GROUP BY f.status`,
		func(r rowScanner) error {
			var st string
			var n int64
			if err := r.Scan(&st, &n); err != nil {
				return err
			}
			out.Status[st] = int(n)
			return nil
		}, args...)
	if err != nil {
		return out, err
	}
	// Programs (and their platforms) for the program filter.
	err = c.query(`SELECT f.platform, f.program, COUNT(*) FROM findings f WHERE `+where+`
		GROUP BY f.platform, f.program ORDER BY COUNT(*) DESC, f.program LIMIT 301`, func(r rowScanner) error {
		var platform, program string
		var n int64
		if err := r.Scan(&platform, &program, &n); err != nil {
			return err
		}
		if program == "" {
			out.NoProgram += int(n)
			return nil
		}
		out.Platforms[platform] += int(n)
		if len(out.Programs) < 300 {
			out.Programs = append(out.Programs, ProgramFacet{Platform: platform, Program: program, Count: int(n)})
		}
		return nil
	}, args...)
	if err != nil {
		return out, err
	}
	err = c.query(`SELECT COUNT(*) FROM findings f WHERE `+where+` AND f.report_ref <> ''`, func(r rowScanner) error {
		var n int64
		err := r.Scan(&n)
		out.Reported = int(n)
		return err
	}, args...)
	return out, err
}

var cveRe = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)

// FirstCVE returns the first CVE id in any of the strings, upper-cased.
func FirstCVE(parts ...string) string {
	for _, p := range parts {
		if m := cveRe.FindString(p); m != "" {
			return strings.ToUpper(m)
		}
	}
	return ""
}

// HostOf reduces a URL or host:port to the bare hostname.
func HostOf(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	s = strings.SplitN(s, "/", 2)[0]
	if h, _, ok := strings.Cut(s, ":"); ok && !strings.Contains(h, "]") {
		s = h
	}
	return strings.ToLower(s)
}

// ProgramOf maps a scope label ("hackerone acme", "bc foo (paused)") to the
// findings platform code and program handle.
func ProgramOf(label string) (platform, program string) {
	label = strings.TrimSpace(label)
	if i := strings.Index(label, " ("); i > 0 {
		label = label[:i]
	}
	if label == "" {
		return "", ""
	}
	src, rest, _ := strings.Cut(label, " ")
	switch strings.ToLower(src) {
	case "h1", "hackerone":
		return "h1", rest
	case "bc", "bugcrowd":
		return "bc", rest
	case "ywh", "yeswehack":
		return "ywh", rest
	case "it", "intigriti":
		return "it", rest
	case "bizone", "bi.zone":
		return "bizone", rest
	}
	return "other", label
}

const findingsMergedKey = "findings_merged_ai_triage_v1"

// MergeTriageIntoFindings is the one-time move to a single Findings list:
// every AI verdict without a finding gets one, and findings promoted from
// triage earlier ("triage:<id>") are linked instead of duplicated. Idempotent;
// marks itself done in settings.
func MergeTriageIntoFindings() (created, linked int, err error) {
	if v, _ := GetSetting(findingsMergedKey); v == "1" {
		return 0, 0, nil
	}
	c, _, err := findingDB()
	if err != nil {
		return 0, 0, err
	}
	// Link promoted findings to their review.
	type pr struct {
		id  int64
		key string
	}
	var promoted []pr
	if err := c.query(`SELECT id, source FROM findings WHERE fkey = '' AND source LIKE 'triage:%'`, func(r rowScanner) error {
		var p pr
		var src string
		if err := r.Scan(&p.id, &src); err != nil {
			return err
		}
		p.key = strings.TrimPrefix(src, "triage:")
		promoted = append(promoted, p)
		return nil
	}); err != nil {
		return 0, 0, err
	}
	for _, p := range promoted {
		if p.key == "" {
			continue
		}
		// Skip if another finding already holds this key (unique index).
		var other int64
		_ = c.query(`SELECT id FROM findings WHERE fkey = ? LIMIT 1`, func(r rowScanner) error { return r.Scan(&other) }, p.key)
		if other != 0 {
			continue
		}
		if err := SetFindingFKey(p.id, p.key); err == nil {
			linked++
		}
	}
	// One finding per remaining verdict.
	for offset := 0; ; offset += 500 {
		recs, err := ListTriage(TriageFilter{Limit: 500, Offset: offset})
		if err != nil {
			return created, linked, err
		}
		for _, t := range recs {
			var have int64
			_ = c.query(`SELECT id FROM findings WHERE fkey = ? LIMIT 1`, func(r rowScanner) error { return r.Scan(&have) }, t.ID)
			if have != 0 {
				continue
			}
			sev := t.Severity
			if t.AISeverity != "" && t.AISeverity != "unknown" {
				sev = t.AISeverity
			}
			platform, program := ProgramOf(t.ScopeProgram)
			module := "nuclei"
			var ev struct {
				Type string `json:"type"`
			}
			_ = json.Unmarshal([]byte(t.Evidence), &ev)
			f := &Finding{
				Title: t.Title, CVE: FirstCVE(t.TemplateID, t.Title), Host: HostOf(firstNonEmpty(t.Host, t.MatchedAt)),
				Program: program, Platform: platform, Severity: sev, Source: "scan:" + t.ScanID, Status: "discovered",
				FirstSeen: t.CreatedAt, UpdatedAt: t.UpdatedAt, LastSeen: t.UpdatedAt,
				FKey: t.ID, ScanID: t.ScanID, Module: module, TemplateID: t.TemplateID, MatchedAt: t.MatchedAt, Evidence: t.Evidence,
			}
			if err := CreateFinding(f); err == nil {
				created++
			}
		}
		if len(recs) < 500 {
			break
		}
	}
	_ = SetSetting(findingsMergedKey, "1")
	return created, linked, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// FindingEdit is a partial update of a finding's editable fields; nil
// fields stay as they are. Used by the dashboard PATCH and the MCP.
type FindingEdit struct {
	Title     *string  `json:"title"`
	CVE       *string  `json:"cve"`
	Host      *string  `json:"host"`
	Program   *string  `json:"program"`
	Platform  *string  `json:"platform"`
	Severity  *string  `json:"severity"`
	CVSS      *float64 `json:"cvss"`
	Status    *string  `json:"status"`
	ReportRef *string  `json:"report_ref"`
	Notes     *string  `json:"notes"`
	MatchedAt *string  `json:"matched_at"`
	ReportMD  *string  `json:"report_md"`
}

var validFindingSeverities = map[string]bool{"": true, "critical": true, "high": true, "medium": true, "low": true, "info": true}

// Empty reports whether the edit changes nothing.
func (e FindingEdit) Empty() bool {
	return e.Title == nil && e.CVE == nil && e.Host == nil && e.Program == nil && e.Platform == nil &&
		e.Severity == nil && e.CVSS == nil && e.Status == nil && e.ReportRef == nil && e.Notes == nil &&
		e.MatchedAt == nil && e.ReportMD == nil
}

// UpdateFindingFields applies a partial edit after validating it. An empty
// string clears a text field (title excepted).
func UpdateFindingFields(id int64, e FindingEdit) error {
	if e.Empty() {
		return errors.New("nothing to change")
	}
	var sets []string
	var args []any
	set := func(col string, v any) { sets = append(sets, col+" = ?"); args = append(args, v) }
	text := func(col string, p *string, max int) {
		if p != nil {
			set(col, truncateRunes(strings.TrimSpace(*p), max))
		}
	}
	if e.Title != nil {
		if strings.TrimSpace(*e.Title) == "" {
			return errors.New("title cannot be empty")
		}
		text("title", e.Title, 500)
	}
	if e.Severity != nil {
		v := strings.ToLower(strings.TrimSpace(*e.Severity))
		if !validFindingSeverities[v] {
			return fmt.Errorf("severity must be critical, high, medium, low or info")
		}
		set("severity", v)
	}
	if e.Status != nil {
		v := strings.TrimSpace(*e.Status)
		if !ValidFindingStatuses[v] {
			return fmt.Errorf("invalid status %q", v)
		}
		set("status", v)
	}
	if e.CVSS != nil {
		if *e.CVSS < 0 || *e.CVSS > 10 {
			return errors.New("cvss must be between 0 and 10")
		}
		set("cvss", *e.CVSS)
	}
	if e.CVE != nil {
		set("cve", strings.ToUpper(truncateRunes(strings.TrimSpace(*e.CVE), 40)))
	}
	text("host", e.Host, 300)
	text("program", e.Program, 200)
	text("platform", e.Platform, 40)
	if e.Program != nil || e.Platform != nil {
		set("program_match", "") // set by hand now, not resolved
	}
	if e.ReportRef != nil {
		if err := ValidReportRef(*e.ReportRef); err != nil {
			return err
		}
	}
	text("report_ref", e.ReportRef, 500)
	text("notes", e.Notes, 10000)
	text("matched_at", e.MatchedAt, 2000)
	if e.ReportMD != nil {
		set("report_md", clipText(*e.ReportMD, 100000))
	}
	c, _, err := findingDB()
	if err != nil {
		return err
	}
	if f, err := GetFinding(id); err != nil || f == nil {
		return ErrFindingNotFound
	}
	set("updated_at", time.Now().UTC().Unix())
	args = append(args, id)
	return c.exec(`UPDATE findings SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...)
}
