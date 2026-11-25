package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/totp"
)

// generateTOTP returns the current 6-digit TOTP code for a base32 secret
// (see internal/totp) — the same algorithm Google Authenticator and YesWeHack
// 2FA use. The secret is the base32 "seed" shown when setting up 2FA, NOT a
// one-time code.
func generateTOTP(secret string) (string, error) { return totp.Code(secret, time.Now()) }

func extractTOTPSecret(raw string) string { return totp.Secret(raw) }

func totpAt(secret string, t time.Time) (string, error) { return totp.Code(secret, t) }

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
	req, err := http.NewRequest("POST", "https://api.yeswehack.com/login", strings.NewReader(loginBody))
	if err != nil {
		return "", fmt.Errorf("YWH login request: %w", err)
	}
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
	req2, err := http.NewRequest("POST", "https://api.yeswehack.com/account/totp", strings.NewReader(totpBody))
	if err != nil {
		return "", fmt.Errorf("YWH 2FA request: %w", err)
	}
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
