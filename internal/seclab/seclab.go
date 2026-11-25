// Package seclab is the single source of truth for the Security Lab reference
// datasets (SSRF payloads, the XSS cheat sheet, and subdomain/DNS takeover
// fingerprints). The datasets are embedded so they are always available, and
// the same corpus feeds three surfaces:
//   - the Security Lab pages (GET /api/seclab/:name, raw dataset JSON)
//   - the MCP tools ssrf_payloads / xss_payloads / takeover_fingerprints
//   - any Go caller via Raw()/SSRF()/XSS()/Takeover().
package seclab

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

//go:embed data/ssrf.json data/xss.json data/takeover-subdomain.json data/takeover-dns.json
var dataFS embed.FS

// datasets maps a public name to its embedded file.
var datasets = map[string]string{
	"ssrf":               "data/ssrf.json",
	"xss":                "data/xss.json",
	"takeover-subdomain": "data/takeover-subdomain.json",
	"takeover-dns":       "data/takeover-dns.json",
}

// Names returns the available dataset names (sorted-ish; map order not relied on).
func Names() []string {
	out := make([]string, 0, len(datasets))
	for k := range datasets {
		out = append(out, k)
	}
	return out
}

// Raw returns the embedded JSON bytes for a dataset (what the pages fetch).
func Raw(name string) ([]byte, error) {
	f, ok := datasets[name]
	if !ok {
		return nil, fmt.Errorf("unknown dataset %q", name)
	}
	return dataFS.ReadFile(f)
}

// ─── Typed views (used by the MCP tools / Go callers) ────────────────────────

// SSRFPayload is one SSRF bypass. Payload carries <allowed>/<attacker>
// placeholders the caller substitutes; prefix/suffix wrap it into a URL.
type SSRFPayload struct {
	Payload     string   `json:"payload"`
	Prefix      string   `json:"prefix,omitempty"`
	Suffix      string   `json:"suffix,omitempty"`
	Description string   `json:"description"`
	Tags        []string `json:"tags,omitempty"`
	Group       string   `json:"group,omitempty"`
	ID          string   `json:"id,omitempty"`
}

type ssrfGroup struct {
	Name     string        `json:"name"`
	Payloads []SSRFPayload `json:"payloads"`
}

// XSSPayload is one entry of the PortSwigger-style XSS cheat sheet.
type XSSPayload struct {
	Code            string `json:"code"`
	Description     string `json:"description,omitempty"`
	Event           string `json:"event,omitempty"`
	Tag             string `json:"tag,omitempty"`
	UserInteraction bool   `json:"userInteraction,omitempty"`
	Link            string `json:"link,omitempty"`
}

var (
	ssrfOnce sync.Once
	ssrfAll  []SSRFPayload
	ssrfErr  error
	xssOnce  sync.Once
	xssAll   []XSSPayload
	xssErr   error
)

// SSRF returns every SSRF payload flattened with its group name attached.
func SSRF() ([]SSRFPayload, error) {
	ssrfOnce.Do(func() {
		b, err := Raw("ssrf")
		if err != nil {
			ssrfErr = err
			return
		}
		var groups []ssrfGroup
		if err := json.Unmarshal(b, &groups); err != nil {
			ssrfErr = err
			return
		}
		for _, g := range groups {
			for _, p := range g.Payloads {
				p.Group = g.Name
				ssrfAll = append(ssrfAll, p)
			}
		}
	})
	return ssrfAll, ssrfErr
}

// XSS returns the full XSS cheat sheet.
func XSS() ([]XSSPayload, error) {
	xssOnce.Do(func() {
		b, err := Raw("xss")
		if err != nil {
			xssErr = err
			return
		}
		xssErr = json.Unmarshal(b, &xssAll)
	})
	return xssAll, xssErr
}

// Takeover returns the takeover fingerprint rows for kind "subdomain" or "dns"
// as generic maps (the two tables have different columns).
func Takeover(kind string) ([]map[string]any, error) {
	name := "takeover-subdomain"
	if kind == "dns" {
		name = "takeover-dns"
	}
	b, err := Raw(name)
	if err != nil {
		return nil, err
	}
	var rows []map[string]any
	if err := json.Unmarshal(b, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// ─── Filtering helpers for the MCP tools ─────────────────────────────────────

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

// FilterSSRF narrows SSRF payloads by a text query (over payload/description/
// group) and an exact tag (URL, HOST, CORS, …). limit<=0 means no cap.
func FilterSSRF(q, tag string, limit int) ([]SSRFPayload, error) {
	all, err := SSRF()
	if err != nil {
		return nil, err
	}
	ql := strings.ToLower(q)
	out := []SSRFPayload{}
	for _, p := range all {
		if tag != "" && !hasTag(p.Tags, tag) {
			continue
		}
		if ql != "" && !strings.Contains(strings.ToLower(p.Payload+" "+p.Description+" "+p.Group), ql) {
			continue
		}
		out = append(out, p)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

// FilterXSS narrows the cheat sheet by text query (over code/description), an
// exact HTML tag, and an event-handler substring. limit<=0 means no cap.
func FilterXSS(q, tag, event string, limit int) ([]XSSPayload, error) {
	all, err := XSS()
	if err != nil {
		return nil, err
	}
	ql, el := strings.ToLower(q), strings.ToLower(event)
	out := []XSSPayload{}
	for _, p := range all {
		if tag != "" && !strings.EqualFold(p.Tag, tag) {
			continue
		}
		if el != "" && !strings.Contains(strings.ToLower(p.Event), el) {
			continue
		}
		if ql != "" && !strings.Contains(strings.ToLower(p.Code+" "+p.Description), ql) {
			continue
		}
		out = append(out, p)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

// FilterTakeover narrows takeover rows by a text query over all string values.
// kind is "subdomain", "dns", or "all". limit<=0 means no cap.
func FilterTakeover(kind, q string, limit int) ([]map[string]any, error) {
	var kinds []string
	switch kind {
	case "dns":
		kinds = []string{"dns"}
	case "", "all":
		kinds = []string{"subdomain", "dns"}
	default:
		kinds = []string{"subdomain"}
	}
	ql := strings.ToLower(q)
	out := []map[string]any{}
	for _, k := range kinds {
		rows, err := Takeover(k)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			if ql != "" {
				var hay strings.Builder
				for _, v := range r {
					if s, ok := v.(string); ok {
						hay.WriteString(strings.ToLower(s))
						hay.WriteByte(' ')
					}
				}
				if !strings.Contains(hay.String(), ql) {
					continue
				}
			}
			r["kind"] = k
			out = append(out, r)
			if limit > 0 && len(out) >= limit {
				return out, nil
			}
		}
	}
	return out, nil
}
