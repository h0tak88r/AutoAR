package utils

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SSRF guard for outbound fetches of operator/user-supplied URLs (URL monitor,
// webhook-style fetchers). Defense in depth: scheme allowlist + public-IP
// resolution + per-redirect revalidation. DNS rebinding (host resolving public
// at check time and private at connect time) is a known residual risk — the
// dial-time check would need a custom DialContext; this closes the common
// direct/redirect cases.

// IsPrivateOrLocalIP reports whether ip is loopback, private (RFC1918),
// link-local, unspecified, multicast, or CGNAT — i.e. not a public unicast IP.
func IsPrivateOrLocalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 || // 10/8
			(ip4[0] == 172 && ip4[1]&0xf0 == 16) || // 172.16/12
			(ip4[0] == 192 && ip4[1] == 168) || // 192.168/16
			(ip4[0] == 100 && ip4[1]&0xc0 == 64) || // 100.64/10 CGNAT
			(ip4[0] == 169 && ip4[1] == 254) // 169.254/16 link-local (cloud metadata)
	}
	// IPv6: ULA fc00::/7 and loopback/unspecified handled above.
	return len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc
}

// ValidatePublicHTTPURL rejects non-http(s) URLs and URLs whose host is a
// literal private/local IP or resolves to one.
func ValidatePublicHTTPURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme %q not allowed (http/https only)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if IsPrivateOrLocalIP(ip) {
			return fmt.Errorf("host %s is a private/local IP", host)
		}
		return nil
	}
	ips, err := net.DefaultResolver.LookupIP(nil, "ip", host)
	if err != nil {
		return fmt.Errorf("cannot resolve host %s: %w", host, err)
	}
	for _, ip := range ips {
		if IsPrivateOrLocalIP(ip) {
			return fmt.Errorf("host %s resolves to private/local IP %s", host, ip)
		}
	}
	return nil
}

// NewPublicHTTPClient returns an http.Client that validates the initial URL is
// supplied by the caller (ValidatePublicHTTPURL) and re-validates EVERY
// redirect hop, so a public URL that 302s to a private/metadata IP is refused.
func NewPublicHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return ValidatePublicHTTPURL(req.URL.String())
		},
	}
}
