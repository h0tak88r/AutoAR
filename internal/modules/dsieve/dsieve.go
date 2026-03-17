// Package dsieve implements the dsieve top-subdomain frequency filter.
// It takes a list of subdomains, groups them by their level-N root domain,
// and returns the top-N most frequently seen roots (and all their subdomains).
// Logic is a direct port of github.com/trickest/dsieve.
package dsieve

import (
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// FilterTopSubdomains returns up to topN unique root domains (at the level-2
// domain position, e.g. "example.com") that appear most frequently in the
// input slice, sorted by descending occurrence count.
// If topN <= 0, all unique roots are returned sorted by frequency.
func FilterTopSubdomains(subdomains []string, topN int) []string {
	freq := make(map[string]int)
	for _, raw := range subdomains {
		root := rootDomain(raw)
		if root != "" {
			freq[root]++
		}
	}

	type pair struct {
		domain string
		count  int
	}
	pairs := make([]pair, 0, len(freq))
	for d, c := range freq {
		pairs = append(pairs, pair{d, c})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return pairs[i].domain < pairs[j].domain
	})

	if topN > 0 && len(pairs) > topN {
		pairs = pairs[:topN]
	}

	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = p.domain
	}
	return out
}

// FilterSubdomainsByRoots returns all subdomains from the input that belong to
// one of the given root domains.
func FilterSubdomainsByRoots(subdomains []string, roots []string) []string {
	rootSet := make(map[string]bool, len(roots))
	for _, r := range roots {
		rootSet[strings.ToLower(r)] = true
	}

	var out []string
	seen := make(map[string]bool)
	for _, sub := range subdomains {
		r := rootDomain(sub)
		if rootSet[r] {
			if !seen[sub] {
				seen[sub] = true
				out = append(out, sub)
			}
		}
	}
	return out
}

// rootDomain extracts the registrable domain (eTLD+1) from a raw URL or hostname.
// Returns "" if the input is not a valid domain.
func rootDomain(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Add a scheme so url.Parse works properly.
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	host := u.Hostname() // strips port

	eTLD, icann := publicsuffix.PublicSuffix(host)
	if !icann {
		return ""
	}
	if eTLD == host {
		return "" // bare TLD, not a real domain
	}

	// eTLD+1 = one label before the eTLD
	withoutTLD := strings.TrimSuffix(host, "."+eTLD)
	parts := strings.Split(withoutTLD, ".")
	return parts[len(parts)-1] + "." + eTLD
}
