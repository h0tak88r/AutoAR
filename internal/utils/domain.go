package utils

import (
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// ParseSubdomainAndRoot parses a raw input (URL or bare hostname) and returns
// (rootDomain, subdomain, ok). The root domain is the eTLD+1 (e.g. "example.com").
// The subdomain is the full hostname (e.g. "admin.staging.example.com").
// Returns ok=false if the input can't be parsed as a valid domain.
func ParseSubdomainAndRoot(raw string) (root, sub string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}

	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "http://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", "", false
	}

	host := u.Hostname()
	if host == "" {
		return "", "", false
	}

	eTLD, icann := publicsuffix.PublicSuffix(host)
	if !icann {
		return "", "", false
	}
	if eTLD == host {
		return "", "", false
	}

	// Compute eTLD+1 (root domain)
	withoutTLD := strings.TrimSuffix(host, "."+eTLD)
	parts := strings.Split(withoutTLD, ".")
	root = parts[len(parts)-1] + "." + eTLD
	sub = host

	return root, sub, true
}
