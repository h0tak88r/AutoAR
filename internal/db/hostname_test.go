package db

import "testing"

func TestSanitizeHostnameRejectsInvalidUTF8(t *testing.T) {
	// Regression guard: a hostname with invalid UTF-8 bytes (subfinder output
	// occasionally carries them) used to reach Postgres, where the insert error
	// poisoned the BatchInsertSubdomains transaction and rolled back the ENTIRE
	// batch. SanitizeHostname must reject such values up front.
	bad := "sub\xff.example.com"
	if got := SanitizeHostname(bad); got != "" {
		t.Errorf("SanitizeHostname(%q) = %q, want \"\" (invalid UTF-8 must be rejected)", bad, got)
	}
}

func TestSanitizeHostnameValid(t *testing.T) {
	cases := map[string]string{
		"sub.example.com":          "sub.example.com",
		"HTTPS://Sub.Example.COM":  "sub.example.com",
		"sub.example.com:8443":     "sub.example.com",
		"sub.example.com/path":     "sub.example.com",
		"https://sub.example.com/": "sub.example.com",
		"trailing.example.com.":    "trailing.example.com",
	}
	for in, want := range cases {
		if got := SanitizeHostname(in); got != want {
			t.Errorf("SanitizeHostname(%q) = %q, want %q", in, got, want)
		}
	}
}

// SanitizeHostname is the gate in front of the subdomains unique key and
// BatchInsertSubdomains: anything outside the hostname charset (markup, NUL
// bytes that poison a whole Postgres batch, quotes, whitespace) is rejected.
func TestSanitizeHostnameRejectsBadCharset(t *testing.T) {
	for _, bad := range []string{
		`"><svg>.x`,
		"sub\x00.example.com",
		"sub example.com",
		"a'b.example.com",
		"<script>.example.com",
		"a..example.com",
		".example.com",
		"sub%2e.example.com",
		"localhost",
	} {
		if got := SanitizeHostname(bad); got != "" {
			t.Errorf("SanitizeHostname(%q) = %q, want \"\"", bad, got)
		}
	}
}

func TestSanitizeHostnameCharsetAccepts(t *testing.T) {
	cases := map[string]string{
		"_dmarc.Example.com": "_dmarc.example.com",
		"*.example.com":      "*.example.com",
		"a-b.c-d.example.io": "a-b.c-d.example.io",
		"bücher.example.de":  "xn--bcher-kva.example.de",
		"10.0.0.1":           "10.0.0.1",
	}
	for in, want := range cases {
		if got := SanitizeHostname(in); got != want {
			t.Errorf("SanitizeHostname(%q) = %q, want %q", in, got, want)
		}
	}
}
