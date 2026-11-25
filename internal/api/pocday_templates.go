package api

// GitHub as a template source for PoC-day: the merged file on the main branch
// of projectdiscovery/nuclei-templates, else the newest pull request that adds
// it. PDCP's search index — the watcher's and bridge's only source until now —
// stalled for 39h on 2026-10-16 while the CVE-2026-85198 and CVE-2026-52715
// template PRs were already on GitHub (an agent swept both by hand).

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Vars so tests can point the lookups at stubs.
var (
	nucleiTplRawBase      = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main"
	nucleiTplRepoAPI      = "https://api.github.com/repos/projectdiscovery/nuclei-templates"
	githubSearchIssuesURL = "https://api.github.com/search/issues"
	githubRawFetch        = func(u string) ([]byte, error) { return cveRadarHTTPWithHeaders(u, nil) }
)

var cveIDStrictRE = regexp.MustCompile(`^CVE-(\d{4})-\d{4,7}$`)

// nucleiTemplateMeta is the info block the pipeline reads from raw YAML.
type nucleiTemplateMeta struct {
	ID   string `yaml:"id"`
	Info struct {
		Name           string `yaml:"name"`
		Severity       string `yaml:"severity"`
		Tags           any    `yaml:"tags"`
		Classification struct {
			CVEID any `yaml:"cve-id"`
		} `yaml:"classification"`
	} `yaml:"info"`
}

// yamlStrings flattens a YAML scalar ("a,b") or sequence into strings.
func yamlStrings(v any) []string {
	var out []string
	switch x := v.(type) {
	case string:
		for _, p := range strings.Split(x, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	}
	return out
}

// templateFromRaw builds the pipeline's template record from raw YAML.
func templateFromRaw(raw, uri string, merged bool) (pdcpTemplate, error) {
	var m nucleiTemplateMeta
	if err := yaml.Unmarshal([]byte(raw), &m); err != nil {
		return pdcpTemplate{}, fmt.Errorf("template yaml: %w", err)
	}
	if strings.TrimSpace(m.ID) == "" {
		return pdcpTemplate{}, fmt.Errorf("template has no id")
	}
	t := pdcpTemplate{
		ID: strings.TrimSpace(m.ID), Name: strings.TrimSpace(m.Info.Name),
		Severity: strings.ToLower(strings.TrimSpace(m.Info.Severity)), Raw: raw, URI: uri,
		Tags: yamlStrings(m.Info.Tags), IsDraft: !merged, IsGithub: merged,
	}
	t.TemplateID = t.ID
	if !merged {
		t.TemplateID = t.ID + "-draft"
	}
	t.Class.CVEs = yamlStrings(m.Info.Classification.CVEID)
	return t, nil
}

// githubTemplatesForCVE returns the GitHub templates for cve, merged first.
func githubTemplatesForCVE(cve string) ([]pdcpTemplate, error) {
	cve = strings.ToUpper(strings.TrimSpace(cve))
	m := cveIDStrictRE.FindStringSubmatch(cve)
	if m == nil {
		return nil, fmt.Errorf("not a CVE id: %q", cve)
	}
	var out []pdcpTemplate
	for _, dir := range []string{"http/cves/", "network/cves/"} {
		path := dir + m[1] + "/" + cve + ".yaml"
		if raw, err := githubRawFetch(nucleiTplRawBase + "/" + path); err == nil && len(raw) > 0 {
			if t, err := templateFromRaw(string(raw), path, true); err == nil {
				out = append(out, t)
				return out, nil
			}
		}
	}
	prs, err := githubTemplatePRs(cve)
	if err != nil {
		return out, err
	}
	return append(out, prs...), nil
}

// githubTemplatePRs finds pull requests that add a template for cve and
// returns their YAML (newest PR first, merged PRs flagged as merged).
func githubTemplatePRs(cve string) ([]pdcpTemplate, error) {
	q := url.Values{
		"q":        {`repo:projectdiscovery/nuclei-templates is:pr "` + cve + `"`},
		"sort":     {"created"},
		"order":    {"desc"},
		"per_page": {"5"},
	}
	body, err := cveRadarGitHubGet(githubSearchIssuesURL + "?" + q.Encode())
	if err != nil {
		return nil, err
	}
	var res struct {
		Items []struct {
			Number      int    `json:"number"`
			State       string `json:"state"`
			PullRequest struct {
				MergedAt *string `json:"merged_at"`
			} `json:"pull_request"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("decode PR search: %w", err)
	}
	var out []pdcpTemplate
	lowCVE := strings.ToLower(cve)
	for _, pr := range res.Items {
		merged := pr.PullRequest.MergedAt != nil && *pr.PullRequest.MergedAt != ""
		if pr.State == "closed" && !merged {
			continue // rejected or abandoned
		}
		fb, err := cveRadarGitHubGet(fmt.Sprintf("%s/pulls/%d/files?per_page=100", nucleiTplRepoAPI, pr.Number))
		if err != nil {
			continue
		}
		var files []struct {
			Filename string `json:"filename"`
			Status   string `json:"status"`
			RawURL   string `json:"raw_url"`
		}
		if json.Unmarshal(fb, &files) != nil {
			continue
		}
		for _, f := range files {
			name := strings.ToLower(f.Filename)
			if f.Status == "removed" || !strings.HasSuffix(name, ".yaml") || !strings.Contains(name, lowCVE) {
				continue
			}
			if !strings.HasPrefix(f.RawURL, "https://github.com/") && !strings.HasPrefix(f.RawURL, "https://raw.githubusercontent.com/") {
				continue
			}
			raw, err := githubRawFetch(f.RawURL)
			if err != nil || len(raw) == 0 {
				continue
			}
			t, err := templateFromRaw(string(raw), f.Filename, merged)
			if err != nil {
				continue
			}
			out = append(out, t)
			break
		}
		if len(out) > 0 {
			break
		}
	}
	return out, nil
}
