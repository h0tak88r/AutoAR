package utils

import (
	"net"
	"testing"
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
