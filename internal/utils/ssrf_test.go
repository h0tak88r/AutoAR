package utils

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestValidatePublicHTTPURL(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"public literal IP", "http://8.8.8.8/foo", false},
		{"public literal IP https", "https://1.1.1.1/", false},
		{"metadata endpoint", "http://169.254.169.254/latest/meta-data/", true},
		{"loopback", "http://127.0.0.1:8080/internal", true},
		{"rfc1918 10/8", "http://10.0.0.5/", true},
		{"rfc1918 172.16/12", "http://172.16.0.1/", true},
		{"rfc1918 192.168/16", "http://192.168.1.1/", true},
		{"cgnat 100.64/10", "http://100.64.0.1/", true},
		{"ipv6 loopback", "http://[::1]/", true},
		{"ipv6 ula", "http://[fd00::1]/", true},
		{"file scheme", "file:///etc/passwd", true},
		{"gopher scheme", "gopher://example.com/", true},
		{"no host", "http:///path", true},
		{"garbage", "://not a url", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePublicHTTPURL(tc.url)
			if tc.wantErr && err == nil {
				t.Errorf("ValidatePublicHTTPURL(%q) = nil, want error", tc.url)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidatePublicHTTPURL(%q) = %v, want nil", tc.url, err)
			}
		})
	}
}

func TestIsPrivateOrLocalIP(t *testing.T) {
	for ip, want := range map[string]bool{
		"127.0.0.1":   true,
		"10.1.2.3":    true,
		"172.15.9.9":  false, // just below 172.16/12
		"172.16.0.1":  true,
		"172.31.0.1":  true,
		"172.32.0.1":  false, // just above
		"192.168.0.1": true,
		"169.254.0.1": true,
		"100.63.0.1":  false,
		"100.64.0.1":  true,
		"8.8.8.8":     false,
		"0.0.0.0":     true,
	} {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Fatalf("bad test IP %q", ip)
		}
		if got := IsPrivateOrLocalIP(parsed); got != want {
			t.Errorf("IsPrivateOrLocalIP(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestPublicDialControl(t *testing.T) {
	for addr, wantErr := range map[string]bool{
		"8.8.8.8:443":               false,
		"[2001:4860:4860::8888]:53": false,
		"127.0.0.1:80":              true,
		"10.0.0.5:8080":             true,
		"169.254.169.254:80":        true,
		"100.64.0.1:80":             true,
		"[::1]:80":                  true,
		"[fd00::1]:80":              true,
		"[::ffff:192.168.1.1]:80":   true,
		"not-an-ip:80":              true,
		"garbage":                   true,
	} {
		if err := publicDialControl("tcp", addr, nil); (err != nil) != wantErr {
			t.Errorf("publicDialControl(%q) err=%v, wantErr=%v", addr, err, wantErr)
		}
	}
}

// TestPublicTransportRefusesPrivateAtDial covers the TOCTOU/DNS-rebinding case:
// whatever a hostname resolved to at validation time, the connect to a loopback
// address (a live local server, by IP and by a hostname resolving to it at dial
// time) is refused by the transport itself.
func TestPublicTransportRefusesPrivateAtDial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("internal"))
	}))
	defer srv.Close()

	client := NewPublicHTTPClient(5 * time.Second)
	if resp, err := client.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("dial to loopback server succeeded; want ssrf guard refusal")
	} else if !strings.Contains(err.Error(), "ssrf guard") {
		t.Fatalf("unexpected error (want ssrf guard): %v", err)
	}

	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	tr := NewPublicTransport()
	if c, err := tr.DialContext(context.Background(), "tcp", net.JoinHostPort("localhost", port)); err == nil {
		c.Close()
		t.Fatal("hostname resolving to loopback at dial time was connected")
	} else if !strings.Contains(err.Error(), "ssrf guard") {
		t.Fatalf("unexpected error (want ssrf guard): %v", err)
	}
}

// TestPublicTransportAllowsConfiguredProxy: the operator's outbound proxy often
// lives on loopback/private space; dials to the address the transport's Proxy
// func chose must not be refused.
func TestPublicTransportAllowsConfiguredProxy(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("via-proxy"))
	}))
	defer proxy.Close()
	pu, _ := url.Parse(proxy.URL)

	tr := newPublicTransport(&http.Transport{}, func(*http.Request) (*url.URL, error) { return pu, nil })
	client := &http.Client{Timeout: 5 * time.Second, Transport: tr}
	resp, err := client.Get("http://example.com/")
	if err != nil {
		t.Fatalf("proxied request refused: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "via-proxy" {
		t.Fatalf("body = %q, want via-proxy", b)
	}
}
