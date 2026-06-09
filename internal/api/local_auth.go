package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/h0tak88r/AutoAR/internal/db"
)

const (
	localAuthIssuer     = "autoar-local"
	jwtSecretSettingKey = "local_auth_jwt_secret"
)

var (
	localAuthSecret     []byte
	localAuthSecretOnce sync.Once

	// tokensRevokedBefore: any token issued before this instant is rejected
	// (server-side "logout"/logout-all). Zero value = nothing revoked.
	tokensRevokedBefore   time.Time
	tokensRevokedBeforeMu sync.RWMutex
)

// localAuthJWTSecret returns the HS256 signing secret.
// Priority: AUTOAR_JWT_SECRET env → a persisted random secret (settings KV, so
// tokens survive restarts) → a freshly generated random secret.
// The secret is NEVER derived from the password: deriving it from the password
// made captured tokens offline-crackable to recover the cleartext password.
func localAuthJWTSecret() []byte {
	if s := strings.TrimSpace(os.Getenv("AUTOAR_JWT_SECRET")); s != "" {
		return []byte(s)
	}
	localAuthSecretOnce.Do(func() {
		// Reuse a persisted secret if one exists so issued tokens stay valid
		// across restarts.
		if v, err := db.GetSetting(jwtSecretSettingKey); err == nil {
			if v = strings.TrimSpace(v); len(v) >= 32 {
				localAuthSecret = []byte(v)
				return
			}
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			panic("failed to generate local auth secret: " + err.Error())
		}
		hexKey := hex.EncodeToString(key)
		_ = db.SetSetting(jwtSecretSettingKey, hexKey) // best-effort persist
		localAuthSecret = []byte(hexKey)
	})
	return localAuthSecret
}

// localAuthEnabled returns true when DASHBOARD_USER and DASHBOARD_PASSWORD are set.
func localAuthEnabled() bool {
	user := strings.TrimSpace(os.Getenv("DASHBOARD_USER"))
	pass := strings.TrimSpace(os.Getenv("DASHBOARD_PASSWORD"))
	return user != "" && pass != ""
}

// issueLocalJWT creates a signed HS256 JWT for the given username (24h expiry).
func issueLocalJWT(username string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": username,
		"iss": localAuthIssuer,
		"iat": now.Unix(),
		"exp": now.Add(24 * time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(localAuthJWTSecret())
}

// revokeAllTokens invalidates every token issued before now (server-side logout).
func revokeAllTokens() {
	tokensRevokedBeforeMu.Lock()
	tokensRevokedBefore = time.Now()
	tokensRevokedBeforeMu.Unlock()
}

func tokenIssuedBeforeRevocation(iat time.Time) bool {
	tokensRevokedBeforeMu.RLock()
	defer tokensRevokedBeforeMu.RUnlock()
	return !tokensRevokedBefore.IsZero() && iat.Before(tokensRevokedBefore)
}

// verifyLocalJWT validates the signature (HS256 only), expiry, issuer, the
// revocation cutoff, and — when local auth is enabled — that the subject matches
// the configured DASHBOARD_USER.
func verifyLocalJWT(raw string) error {
	secret := localAuthJWTSecret()
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithIssuer(localAuthIssuer))
	if err != nil {
		return err
	}
	if iat, e := claims.GetIssuedAt(); e == nil && iat != nil && tokenIssuedBeforeRevocation(iat.Time) {
		return fmt.Errorf("token revoked")
	}
	if localAuthEnabled() {
		sub, _ := claims["sub"].(string)
		if sub != strings.TrimSpace(os.Getenv("DASHBOARD_USER")) {
			return fmt.Errorf("subject not authorized")
		}
	}
	return nil
}

// ── Login brute-force lockout (keyed by client IP) ───────────────────────────

type loginAttemptState struct {
	fails     int
	lockUntil time.Time
}

var (
	loginAttempts   = map[string]*loginAttemptState{}
	loginAttemptsMu sync.Mutex
)

const (
	loginMaxFails = 5
	loginBaseLock = 30 * time.Second
	loginMaxLock  = 15 * time.Minute
)

func loginLockRemaining(key string) time.Duration {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	if st := loginAttempts[key]; st != nil {
		if d := time.Until(st.lockUntil); d > 0 {
			return d
		}
	}
	return 0
}

func loginRecordFailure(key string) {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	st := loginAttempts[key]
	if st == nil {
		st = &loginAttemptState{}
		loginAttempts[key] = st
	}
	st.fails++
	if st.fails >= loginMaxFails {
		shift := st.fails - loginMaxFails
		if shift > 5 {
			shift = 5
		}
		lock := loginBaseLock << uint(shift)
		if lock > loginMaxLock {
			lock = loginMaxLock
		}
		st.lockUntil = time.Now().Add(lock)
	}
}

func loginReset(key string) {
	loginAttemptsMu.Lock()
	delete(loginAttempts, key)
	loginAttemptsMu.Unlock()
}

// POST /api/auth/login — accepts { "username": "...", "password": "..." }
// and returns { "token": "<jwt>", "expires_in": 86400 }.
func apiLocalAuthLogin(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}

	expectedUser := strings.TrimSpace(os.Getenv("DASHBOARD_USER"))
	expectedPass := strings.TrimSpace(os.Getenv("DASHBOARD_PASSWORD"))

	if expectedUser == "" || expectedPass == "" {
		// Auth is disabled; issue a token for anyone (no-op auth).
		tok, err := issueLocalJWT(body.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not issue token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": tok, "expires_in": 86400})
		return
	}

	ipKey := c.ClientIP()
	if d := loginLockRemaining(ipKey); d > 0 {
		secs := int(d.Seconds()) + 1
		c.Header("Retry-After", fmt.Sprintf("%d", secs))
		c.JSON(http.StatusTooManyRequests, gin.H{"error": fmt.Sprintf("too many failed attempts — retry in %ds", secs)})
		return
	}

	// Constant-time, no short-circuit: both fields are always compared so neither
	// username validity nor password prefix length leaks via timing.
	userOK := subtle.ConstantTimeCompare([]byte(body.Username), []byte(expectedUser)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(body.Password), []byte(expectedPass)) == 1
	if !(userOK && passOK) {
		loginRecordFailure(ipKey)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	loginReset(ipKey)

	tok, err := issueLocalJWT(body.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not issue token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": tok, "expires_in": 86400})
}

// redactTokenInPath replaces the value of a `token=` query parameter with
// "REDACTED" so session JWTs passed via query string don't appear in access logs.
func redactTokenInPath(path string) string {
	i := strings.Index(path, "token=")
	if i < 0 {
		return path
	}
	start := i + len("token=")
	end := start
	for end < len(path) && path[end] != '&' {
		end++
	}
	return path[:start] + "REDACTED" + path[end:]
}

// POST /api/auth/logout — revokes all tokens issued before now (server-side).
func apiLocalAuthLogout(c *gin.Context) {
	revokeAllTokens()
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// CheckAuthBindSafety refuses to run unauthenticated on a public (non-loopback)
// interface. Returns a non-nil error that the caller should treat as fatal.
func CheckAuthBindSafety(host string) error {
	if dashboardAPIAuthEnforced() {
		return nil // auth is enforced — safe
	}
	// Auth is off. If the operator explicitly opted out, allow it.
	v := strings.TrimSpace(os.Getenv("AUTOAR_API_AUTH_DISABLED"))
	if strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes") {
		return nil
	}
	// Off and not explicitly disabled → only loopback binds are allowed.
	h := strings.TrimSpace(host)
	if h == "" || h == "127.0.0.1" || h == "::1" || strings.EqualFold(h, "localhost") {
		return nil
	}
	return fmt.Errorf("refusing to start: API_HOST=%q exposes the dashboard on a public interface with authentication DISABLED. "+
		"Set DASHBOARD_USER and DASHBOARD_PASSWORD to require login, or set AUTOAR_API_AUTH_DISABLED=true to explicitly run without auth", host)
}
