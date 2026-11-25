package utils

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
)

// SSRF guard for outbound fetches of operator/user-supplied URLs (URL monitor,
// webhook-style fetchers). Defense in depth: scheme allowlist + public-IP
// resolution + per-redirect revalidation + a dial-time check. The dial-time
// check (NewPublicTransport) runs on the IP actually being connected to, so DNS
// rebinding — a host resolving public at validation time and private at connect
// time — is refused too. Residual: when an operator-configured outbound proxy
// (HTTP(S)_PROXY) is in use the proxy resolves the target itself, so only the
// URL-level validation applies to proxied requests.

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
	// nil ctx would panic inside the resolver (nil interface deref in
	// lookupIPAddr) — and this guard runs on every jsscan URL, taking the
	// whole API process (and every in-flight scan) down with it.
	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", host)
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

// publicDialControl is a net.Dialer Control hook. It runs for every connection
// attempt with the already-resolved address, so it rejects non-public IPs even
// when the hostname was public at ValidatePublicHTTPURL time.
func publicDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("ssrf guard: bad dial address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("ssrf guard: dial address %q is not an IP", address)
	}
	if IsPrivateOrLocalIP(ip) {
		return fmt.Errorf("ssrf guard: refusing to connect to non-public address %s", address)
	}
	return nil
}

// canonicalProxyAddr mirrors net/http's host:port form for a proxy URL (the
// address the transport dials for it).
func canonicalProxyAddr(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "socks5", "socks5h":
			port = "1080"
		default:
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// NewPublicTransport returns a clone of http.DefaultTransport (proxy from the
// environment, HTTP/2 and pooling kept) whose dialer refuses private/loopback/
// link-local/CGNAT/metadata IPs at connect time. Dials to the outbound proxy
// that the transport's own Proxy func chose (operator environment, never the
// target) are exempt — the proxy is commonly on loopback or a private network.
func NewPublicTransport() *http.Transport {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		base = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	return newPublicTransport(base.Clone(), base.Proxy)
}

func newPublicTransport(tr *http.Transport, proxyFunc func(*http.Request) (*url.URL, error)) *http.Transport {
	var proxies sync.Map // canonical proxy addrs handed out by proxyFunc
	tr.Proxy = func(req *http.Request) (*url.URL, error) {
		if proxyFunc == nil {
			return nil, nil
		}
		u, err := proxyFunc(req)
		if err == nil && u != nil {
			proxies.Store(canonicalProxyAddr(u), struct{}{})
		}
		return u, err
	}
	guarded := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: publicDialControl}
	proxyDialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if _, isProxy := proxies.Load(addr); isProxy {
			return proxyDialer.DialContext(ctx, network, addr)
		}
		return guarded.DialContext(ctx, network, addr)
	}
	return tr
}

// NewPublicHTTPClient returns an http.Client that validates the initial URL is
// supplied by the caller (ValidatePublicHTTPURL) and re-validates EVERY
// redirect hop, so a public URL that 302s to a private/metadata IP is refused;
// its transport (NewPublicTransport) also enforces public IPs at connect time.
func NewPublicHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: NewPublicTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return ValidatePublicHTTPURL(req.URL.String())
		},
	}
}
