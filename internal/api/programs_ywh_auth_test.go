package api

import (
	"testing"
	"time"
)

// TestTOTPRFC6238 checks generateTOTP against the RFC 6238 SHA1 test vector:
// ASCII secret "12345678901234567890" (base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ);
// at Unix time 59 the 6-digit TOTP is 287082.
func TestTOTPRFC6238(t *testing.T) {
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{2000000000, "279037"},
	}
	for _, c := range cases {
		got, err := totpAt(secret, time.Unix(c.unix, 0))
		if err != nil {
			t.Fatalf("totpAt(%d): %v", c.unix, err)
		}
		if got != c.want {
			t.Errorf("totpAt(%d) = %s, want %s", c.unix, got, c.want)
		}
	}
	// Lowercase + spaces (as often pasted from a 2FA setup screen) must still work.
	if _, err := generateTOTP("gezd gnbv gy3t qojq gezd gnbv gy3t qojq"); err != nil {
		t.Errorf("spaced/lowercase secret should parse: %v", err)
	}
}

// TestExtractTOTPSecret covers the common mistake of pasting the whole otpauth://
// URI (or a secret= query) instead of just the base32 seed.
func TestExtractTOTPSecret(t *testing.T) {
	cases := map[string]string{
		"GEZDGNBVGY3TQOJQ": "GEZDGNBVGY3TQOJQ", // bare seed → unchanged
		"otpauth://totp/YesWeHack:me@x.com?secret=GEZDGNBVGY3TQOJQ&issuer=YesWeHack&digits=6": "GEZDGNBVGY3TQOJQ",
		"secret=GEZDGNBVGY3TQOJQ&period=30": "GEZDGNBVGY3TQOJQ",
	}
	for in, want := range cases {
		if got := extractTOTPSecret(in); got != want {
			t.Errorf("extractTOTPSecret(%q) = %q, want %q", in, got, want)
		}
	}
	// An otpauth URI must now produce a valid code (RFC vector secret embedded).
	if code, err := totpAt("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time.Unix(59, 0)); err != nil || code != "287082" {
		t.Errorf("otpauth URI TOTP = %q, err=%v; want 287082", code, err)
	}
}
