package api

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// generateTOTP returns the current 6-digit TOTP code for a base32 secret
// (RFC 6238: HMAC-SHA1, 30-second step, 6 digits) — the same algorithm Google
// Authenticator and YesWeHack 2FA use. The secret is the base32 "seed" shown when
// setting up 2FA, NOT a one-time code.
func generateTOTP(secret string) (string, error) { return totpAt(secret, time.Now()) }

// extractTOTPSecret returns the bare base32 seed from whatever the user pasted.
// Users often paste the whole otpauth:// URI (or a "…secret=XXXX&…" query) from
// the 2FA QR code instead of just the seed — pull the secret= value out of it.
func extractTOTPSecret(raw string) string {
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

func totpAt(secret string, t time.Time) (string, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(extractTOTPSecret(secret)), " ", ""))
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

// ywhReauthThrottle prevents a re-login storm: at most one login attempt per
// email per window, so many concurrent/expired-token fetches don't hammer YWH's
// /login (which could trip anti-bot / rate limits).
var (
	ywhReauthMu       sync.Mutex
	ywhReauthLastTry  = map[string]time.Time{}
	ywhReauthMinAfter = 20 * time.Second
)

func ywhReauthAllowed(email string) bool {
	ywhReauthMu.Lock()
	defer ywhReauthMu.Unlock()
	if last, ok := ywhReauthLastTry[email]; ok && time.Since(last) < ywhReauthMinAfter {
		return false
	}
	ywhReauthLastTry[email] = time.Now()
	return true
}

// ywhReauth logs in to YesWeHack with email+password (and a generated TOTP code
// if 2FA is enabled) and returns a fresh JWT. Native HTTP so a login failure only
// returns an error — it never crashes the process the way bbscope's log.Fatal does.
func ywhReauth(email, password, totpSecret string) (string, error) {
	if strings.TrimSpace(email) == "" || strings.TrimSpace(password) == "" {
		return "", fmt.Errorf("email and password required for YWH re-auth")
	}
	if !ywhReauthAllowed(email) {
		return "", fmt.Errorf("YWH re-auth throttled (retry shortly)")
	}
	client := &http.Client{Timeout: 30 * time.Second}

	// Step 1: POST /login.
	loginBody := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	req, _ := http.NewRequest("POST", "https://api.yeswehack.com/login", strings.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("YWH login request: %w", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("YWH login failed (%d) — check email/password", resp.StatusCode)
	}
	var lr struct {
		Token     string `json:"token"`
		TOTPToken string `json:"totp_token"`
	}
	if e := json.Unmarshal(raw, &lr); e != nil {
		return "", fmt.Errorf("YWH login parse: %w", e)
	}
	if lr.Token != "" {
		return lr.Token, nil // account has no 2FA
	}
	if lr.TOTPToken == "" {
		return "", fmt.Errorf("YWH login: neither token nor totp_token returned")
	}

	// Step 2: 2FA — generate a code from the stored secret and confirm.
	if strings.TrimSpace(totpSecret) == "" {
		return "", fmt.Errorf("YWH account has 2FA enabled but no TOTP secret is stored")
	}
	code, err := generateTOTP(totpSecret)
	if err != nil {
		return "", err
	}
	totpBody := fmt.Sprintf(`{"token":%q,"code":%q}`, lr.TOTPToken, code)
	req2, _ := http.NewRequest("POST", "https://api.yeswehack.com/account/totp", strings.NewReader(totpBody))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Accept", "application/json")
	resp2, err := client.Do(req2)
	if err != nil {
		return "", fmt.Errorf("YWH 2FA request: %w", err)
	}
	raw2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		return "", fmt.Errorf("YWH 2FA verification failed (%d) — check the TOTP secret", resp2.StatusCode)
	}
	var tr struct {
		Token string `json:"token"`
	}
	if e := json.Unmarshal(raw2, &tr); e != nil || tr.Token == "" {
		return "", fmt.Errorf("YWH 2FA: no token in response")
	}
	return tr.Token, nil
}
