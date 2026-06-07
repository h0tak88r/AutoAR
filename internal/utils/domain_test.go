package utils

import "testing"

func TestParseSubdomainAndRoot(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantRoot  string
		wantSub   string
		wantOK    bool
	}{
		{"empty string", "", "", "", false},
		{"bare domain", "example.com", "example.com", "example.com", true},
		{"bare subdomain", "admin.staging.example.com", "example.com", "admin.staging.example.com", true},
		{"https url", "https://example.com/path", "example.com", "example.com", true},
		{"https url with subdomain", "https://api.staging.example.com/v1", "example.com", "api.staging.example.com", true},
		{"http url with port", "http://example.com:8080/path", "example.com", "example.com", true},
		{"ip address", "http://192.168.1.1/path", "", "", false},
		{"single label", "localhost", "", "", false},
		{"public suffix only", "co.uk", "", "", false},
		{"raw with spaces", "  example.com  ", "example.com", "example.com", true},
		{"multipart TLD", "site.co.uk", "site.co.uk", "site.co.uk", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, sub, ok := ParseSubdomainAndRoot(tt.input)
			if ok != tt.wantOK {
				t.Errorf("ParseSubdomainAndRoot(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if root != tt.wantRoot {
				t.Errorf("ParseSubdomainAndRoot(%q) root = %q, want %q", tt.input, root, tt.wantRoot)
			}
			if sub != tt.wantSub {
				t.Errorf("ParseSubdomainAndRoot(%q) sub = %q, want %q", tt.input, sub, tt.wantSub)
			}
		})
	}
}
