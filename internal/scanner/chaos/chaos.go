// Package chaos is a thin client for ProjectDiscovery's Chaos DNS dataset. It
// returns the known subdomains for a root domain from Chaos's curated data —
// instant, single-source, no full recon pipeline. Requires CHAOS_API_KEY.
//
//	GET https://dns.projectdiscovery.io/dns/{domain}/subdomains
//	Header: Authorization: <CHAOS_API_KEY>
//	Response: {"domain":"example.com","subdomains":["www","api","mail", ...]}
package chaos

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const subdomainsAPI = "https://dns.projectdiscovery.io/dns/%s/subdomains"

// APIKey returns the configured Chaos API key (CHAOS_API_KEY, the same env var
// subfinder uses for its chaos provider).
func APIKey() string {
	return strings.TrimSpace(os.Getenv("CHAOS_API_KEY"))
}

// Configured reports whether a Chaos API key is available.
func Configured() bool { return APIKey() != "" }

// NormalizeDomain strips scheme/path/trailing slash and lowercases, so the fetch
// and any downstream persistence agree on the exact domain key.
func NormalizeDomain(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimSuffix(d, "/")
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	return d
}

// FetchSubdomains queries Chaos for a domain's known subdomains and returns them
// as fully-qualified names (deduplicated, sorted-stable by insertion). It returns
// a descriptive error when the key is missing, invalid (401), or the API errors.
func FetchSubdomains(domain string) ([]string, error) {
	key := APIKey()
	if key == "" {
		return nil, fmt.Errorf("CHAOS_API_KEY is not set")
	}
	domain = NormalizeDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	req, err := http.NewRequest("GET", fmt.Sprintf(subdomainsAPI, domain), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", key)
	req.Header.Set("Accept", "application/json")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("chaos request failed: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// ok
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("chaos: invalid or unauthorized CHAOS_API_KEY (%d)", resp.StatusCode)
	case http.StatusNotFound:
		// Chaos has no dataset for this domain — treat as zero results, not an error.
		return []string{}, nil
	default:
		return nil, fmt.Errorf("chaos API returned %d: %s", resp.StatusCode, snippet(body))
	}

	var out struct {
		Domain     string   `json:"domain"`
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("chaos: could not parse response: %w", err)
	}

	seen := make(map[string]bool, len(out.Subdomains))
	subs := make([]string, 0, len(out.Subdomains))
	for _, p := range out.Subdomains {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" || p == "*" {
			continue
		}
		// Chaos returns bare labels ("api"), but be tolerant of already-qualified
		// entries ("api.example.com") too.
		fqdn := p + "." + domain
		if p == domain || strings.HasSuffix(p, "."+domain) {
			fqdn = p
		}
		if seen[fqdn] {
			continue
		}
		seen[fqdn] = true
		subs = append(subs, fqdn)
	}
	return subs, nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
