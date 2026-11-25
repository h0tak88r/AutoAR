// Package triage asks the active AI provider (internal/brain) to validate
// scanner findings, decides — with deterministic rules, not the model alone —
// which ones are reportable, and posts those to the Discord findings channel
// with a draft bug-bounty report attached.
//
// Safety model: the model only ever reads evidence. It never chooses requests
// or commands. The one network action triage takes on its own is an optional
// single GET replay of a hit that was already a GET, through the SSRF-guarded
// client, so the model sees whether the issue still reproduces.
package triage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Finding is one scanner hit, normalised from a nuclei JSONL event.
type Finding struct {
	ScanID      string   `json:"scan_id"`
	TemplateID  string   `json:"template_id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	References  []string `json:"references,omitempty"`
	CVE         []string `json:"cve,omitempty"`
	CVSS        string   `json:"cvss,omitempty"`
	Type        string   `json:"type,omitempty"` // http | dns | network | ...
	Host        string   `json:"host"`
	MatchedAt   string   `json:"matched_at"`
	Matcher     string   `json:"matcher,omitempty"`
	Extracted   []string `json:"extracted,omitempty"`
	Request     string   `json:"request,omitempty"`
	Response    string   `json:"response,omitempty"`
	Curl        string   `json:"curl,omitempty"`
}

// Key is the stable identity of a finding across scans: the same template
// matching the same location is the same finding, so it is triaged once.
func (f Finding) Key() string {
	first := ""
	if len(f.Extracted) > 0 {
		first = f.Extracted[0]
	}
	sum := sha256.Sum256([]byte(strings.ToLower(f.TemplateID) + "\x00" + f.MatchedAt + "\x00" + f.Matcher + "\x00" + first))
	return hex.EncodeToString(sum[:12])
}

// Title is a human label for the finding.
func (f Finding) Title() string {
	if f.Name != "" {
		return f.Name
	}
	return f.TemplateID
}

// nucleiEvent is the subset of a nuclei ResultEvent triage uses.
type nucleiEvent struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name           string          `json:"name"`
		Severity       string          `json:"severity"`
		Description    string          `json:"description"`
		Tags           json.RawMessage `json:"tags"`
		Reference      json.RawMessage `json:"reference"`
		Classification struct {
			CVEID       json.RawMessage `json:"cve-id"`
			CVSSScore   json.Number     `json:"cvss-score"`
			CVSSMetrics string          `json:"cvss-metrics"`
		} `json:"classification"`
	} `json:"info"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	MatchedAt        string   `json:"matched-at"`
	URL              string   `json:"url"`
	MatcherName      string   `json:"matcher-name"`
	ExtractedResults []string `json:"extracted-results"`
	Request          string   `json:"request"`
	Response         string   `json:"response"`
	CurlCommand      string   `json:"curl-command"`
	MatcherStatus    *bool    `json:"matcher-status"`
}

// stringList accepts nuclei's "a,b" strings as well as ["a","b"] arrays.
func stringList(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var arr []string
	if json.Unmarshal(raw, &arr) == nil {
		return trimAll(arr)
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return trimAll(strings.Split(s, ","))
	}
	return nil
}

func trimAll(in []string) []string {
	out := in[:0]
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ParseNucleiLine turns one JSONL line into a Finding. ok is false for lines
// that aren't nuclei match events (summaries, failed matchers, junk).
func ParseNucleiLine(line []byte, scanID string) (Finding, bool) {
	var ev nucleiEvent
	if json.Unmarshal(line, &ev) != nil || ev.TemplateID == "" {
		return Finding{}, false
	}
	if ev.MatcherStatus != nil && !*ev.MatcherStatus {
		return Finding{}, false
	}
	matched := firstNonEmpty(ev.MatchedAt, ev.URL, ev.Host)
	if matched == "" {
		return Finding{}, false
	}
	f := Finding{
		ScanID:      scanID,
		TemplateID:  ev.TemplateID,
		Name:        strings.TrimSpace(ev.Info.Name),
		Severity:    NormalizeSeverity(ev.Info.Severity),
		Description: strings.TrimSpace(ev.Info.Description),
		Tags:        stringList(ev.Info.Tags),
		References:  stringList(ev.Info.Reference),
		CVE:         stringList(ev.Info.Classification.CVEID),
		Type:        strings.ToLower(strings.TrimSpace(ev.Type)),
		Host:        HostOf(firstNonEmpty(ev.Host, matched)),
		MatchedAt:   matched,
		Matcher:     ev.MatcherName,
		Extracted:   ev.ExtractedResults,
		Request:     ev.Request,
		Response:    ev.Response,
		Curl:        ev.CurlCommand,
	}
	if s := ev.Info.Classification.CVSSScore.String(); s != "" {
		f.CVSS = s
		if ev.Info.Classification.CVSSMetrics != "" {
			f.CVSS += " " + ev.Info.Classification.CVSSMetrics
		}
	}
	return f, true
}

// HostOf reduces a URL or host:port to the bare lowercase host.
func HostOf(s string) string {
	h := strings.TrimSpace(s)
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndexByte(h, '@'); i >= 0 {
		h = h[i+1:]
	}
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i > 0 {
			return strings.ToLower(h[1:i])
		}
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 && strings.Count(h, ":") == 1 {
		h = h[:i]
	}
	return strings.ToLower(h)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

var severityRank = map[string]int{"info": 0, "unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// NormalizeSeverity lowercases a severity and maps unknown values to "unknown".
func NormalizeSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if _, ok := severityRank[s]; ok {
		return s
	}
	return "unknown"
}

// SeverityRank orders severities (info/unknown=0 … critical=4).
func SeverityRank(s string) int { return severityRank[NormalizeSeverity(s)] }

// clip truncates s to n bytes on a rune boundary, marking the cut.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut] + fmt.Sprintf("\n…[truncated %d bytes]", len(s)-cut)
}
