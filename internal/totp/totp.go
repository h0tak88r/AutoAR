// Package totp generates RFC 6238 codes (HMAC-SHA1, 30-second step, 6 digits)
// from a stored 2FA seed — what Google Authenticator shows — so AutoAR can sign
// in to a platform that asks for a one-time code (YesWeHack, Bugcrowd).
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Secret returns the bare base32 seed from whatever the user pasted. Users
// often paste the whole otpauth:// URI (or a "…secret=XXXX&…" query) from the
// 2FA QR code instead of just the seed — pull the secret= value out of it.
func Secret(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.Index(strings.ToLower(s), "secret="); i >= 0 {
		v := s[i+len("secret="):]
		if j := strings.IndexAny(v, "&?#\r\n\t "); j >= 0 {
			v = v[:j]
		}
		if dec, err := url.QueryUnescape(v); err == nil {
			v = dec
		}
		return v
	}
	return s
}

// Code returns the 6-digit code for the seed at time t. The seed is the base32
// value shown when setting up 2FA (or its otpauth:// URI), NOT a one-time code.
func Code(secret string, t time.Time) (string, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(Secret(secret)), " ", ""))
	if s == "" {
		return "", fmt.Errorf("empty TOTP secret")
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		if key, err = base32.StdEncoding.DecodeString(s); err != nil {
			return "", fmt.Errorf("invalid base32 TOTP secret: %w", err)
		}
	}
	counter := uint64(t.Unix() / 30)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off]&0x7f) << 24) | (uint32(sum[off+1]) << 16) | (uint32(sum[off+2]) << 8) | uint32(sum[off+3])
	return fmt.Sprintf("%06d", code%1000000), nil
}
