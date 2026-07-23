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
