package db

import "strings"

// SanitizeHostname normalizes a value destined for the subdomains.subdomain
// column to a bare, lowercase hostname. The column is the unique dedup key, so
// letting scheme-prefixed URLs, ports, paths, or whitespace through would both
// split one host across several rows and defeat the ON CONFLICT (subdomain)
// dedup. Returns "" for anything that isn't a usable hostname, and callers skip
// empties.
//
// The probed URL (https://host) is NOT stored here — it is derived on read via
// SubdomainStatus.BestURL and exposed as the JSON "host" field.
func SanitizeHostname(raw string) string {
	h := strings.TrimSpace(raw)
	if h == "" {
		return ""
	}
	// Drop a scheme if one slipped in (http://host/path -> host/path).
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	// Strip anything after the authority: path, query, or fragment.
	for _, sep := range []string{"/", "?", "#"} {
		if i := strings.Index(h, sep); i >= 0 {
			h = h[:i]
		}
	}
	// Strip userinfo (user@host) and port (host:443).
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[:i]
	}
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	// A real hostname has no whitespace and at least one dot, and fits DNS limits.
	// The length cap matters beyond validity: the Postgres subdomain column is
	// VARCHAR(255) and BatchInsertSubdomains runs per-row Exec in one transaction,
	// so a single over-long value would abort the transaction and roll back the
	// ENTIRE batch (Postgres poisons the tx on any error), losing every host in it.
	if h == "" || len(h) > 253 || strings.ContainsAny(h, " \t\r\n") || !strings.Contains(h, ".") {
		return ""
	}
	return h
}
