package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/h0tak88r/AutoAR/internal/db"
	"golang.org/x/crypto/bcrypt"
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

	// usersExistLatch is a process-lifetime latch: true once at least one DB user
	// is known to exist. Set at boot by SeedInitialAdmin and whenever a user is
	// created, so the hot auth path never queries the DB just to decide whether
	// multi-user mode is active. It stays false in unit tests (which never seed),
	// keeping localAuthEnabled / CheckAuthBindSafety free of DB access.
	usersExistLatch atomic.Bool
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
// It is intentionally env-only (no DB access) so it stays safe to call from unit
// tests and from the pre-DB bind-safety check.
func localAuthEnabled() bool {
	user := strings.TrimSpace(os.Getenv("DASHBOARD_USER"))
	pass := strings.TrimSpace(os.Getenv("DASHBOARD_PASSWORD"))
	return user != "" && pass != ""
}

// usersExist reports whether at least one dashboard user row exists. Reads the
// process-lifetime latch only (no DB round-trip on the hot path).
func usersExist() bool { return usersExistLatch.Load() }

func markUsersExist() { usersExistLatch.Store(true) }

// authConfigured reports whether any authentication is in effect: either the
// legacy DASHBOARD_USER/PASSWORD env pair, or one or more DB users.
func authConfigured() bool { return localAuthEnabled() || usersExist() }

// hashPassword returns a bcrypt hash of a plaintext password.
func hashPassword(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	return string(b), err
}

// checkPassword reports whether plain matches a stored bcrypt hash.
func checkPassword(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// SeedInitialAdmin makes multi-user auth backward compatible. On boot, if no
// users exist yet but the legacy DASHBOARD_USER/DASHBOARD_PASSWORD env pair is
// set, it creates that account as the first admin — so existing single-login
// deployments keep working with the same credentials, now as an admin who can add
// more users from Settings ▸ Users. Idempotent: it never touches a non-empty
// users table. Call AFTER db.EnsureSchema().
func SeedInitialAdmin() {
	n, err := db.CountUsers()
	if err != nil {
		log.Printf("[users] seed: count failed: %v", err)
		return
	}
	if n == 0 {
		u := strings.TrimSpace(os.Getenv("DASHBOARD_USER"))
		p := strings.TrimSpace(os.Getenv("DASHBOARD_PASSWORD"))
		if u != "" && p != "" {
			hash, herr := hashPassword(p)
			if herr != nil {
				log.Printf("[users] seed: hash failed: %v", herr)
				return
			}
			if _, cerr := db.CreateUser(u, hash, "admin"); cerr != nil {
				log.Printf("[users] seed: create admin %q failed: %v", u, cerr)
				return
			}
			log.Printf("[users] seeded initial admin %q from DASHBOARD_USER (manage users in Settings ▸ Users)", u)
			n = 1
		}
	}
	if n > 0 {
		markUsersExist()
	}
}

// issueLocalJWT creates a signed HS256 JWT for the given username (24h expiry).
func issueLocalJWT(username string) (string, error) {
	return issueLocalJWTWithRole(username, "")
}

// issueLocalJWTWithRole is issueLocalJWT plus a "role" claim (admin/viewer). An
// empty role omits the claim (legacy/no-auth tokens carry no role).
func issueLocalJWTWithRole(username, role string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": username,
		"iss": localAuthIssuer,
		"iat": now.Unix(),
		"exp": now.Add(24 * time.Hour).Unix(),
	}
	if role != "" {
		claims["role"] = role
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

// verifyLocalJWTClaims validates a token like verifyLocalJWT and additionally
// resolves the subject and role for the request context. In DB-users mode the
// role is read authoritatively from the users table, so a role change or a
// disable/delete takes effect on the very next request (no wait for the token to
// expire) and a missing/disabled user is rejected. In legacy env-only mode the
// subject must equal DASHBOARD_USER and the role is "admin". When no auth is
// configured the caller uses the passthrough and never invokes this.
func verifyLocalJWTClaims(raw string) (sub, role string, err error) {
	secret := localAuthJWTSecret()
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithIssuer(localAuthIssuer))
	if err != nil {
		return "", "", err
	}
	if iat, e := claims.GetIssuedAt(); e == nil && iat != nil && tokenIssuedBeforeRevocation(iat.Time) {
		return "", "", fmt.Errorf("token revoked")
	}
	sub, _ = claims["sub"].(string)
	role, _ = claims["role"].(string)

	if usersExist() {
		u, e := db.GetUserByUsername(sub)
		if e != nil || u == nil || u.Disabled {
			return "", "", fmt.Errorf("user not found or disabled")
		}
		return u.Username, u.Role, nil // DB role is authoritative
	}
	if localAuthEnabled() {
		if sub != strings.TrimSpace(os.Getenv("DASHBOARD_USER")) {
			return "", "", fmt.Errorf("subject not authorized")
		}
		if role == "" {
			role = "admin"
		}
	}
	return sub, role, nil
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

// auditLogin records a login attempt in the audit log with the attempted username
// and source IP (the request has no auth context yet, so the generic audit() would
// mis-attribute it to "system").
func auditLogin(c *gin.Context, username, action string) {
	_ = db.InsertAuditEvent(db.AuditEvent{Actor: strings.TrimSpace(username), Action: action, IP: c.ClientIP()})
}

// POST /api/auth/login — accepts { "username": "...", "password": "..." } and
// returns { "token": "<jwt>", "expires_in": 86400, "role": "admin|viewer" }.
//
// Resolution order:
//  1. No auth configured (no users AND no env pair) → issue a token for anyone
//     (dev / no-op auth), matching the previous single-login behavior.
//  2. Users exist → authenticate against the DB with bcrypt, honoring the role
//     and the disabled flag.
//  3. Legacy fallback (env pair set but no users seeded yet, e.g. a boot-time
//     seed failure) → constant-time compare against the env pair as an admin.
func apiLocalAuthLogin(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	body.Username = strings.TrimSpace(body.Username)

	// (1) Nothing configured → no-op auth (issue a token for anyone).
	if !authConfigured() {
		tok, err := issueLocalJWTWithRole(body.Username, "admin")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not issue token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": tok, "expires_in": 86400, "role": "admin"})
		return
	}

	ipKey := c.ClientIP()
	if d := loginLockRemaining(ipKey); d > 0 {
		secs := int(d.Seconds()) + 1
		c.Header("Retry-After", fmt.Sprintf("%d", secs))
		c.JSON(http.StatusTooManyRequests, gin.H{"error": fmt.Sprintf("too many failed attempts — retry in %ds", secs)})
		return
	}

	// (2) DB users mode.
	if usersExist() {
		u, err := db.GetUserByUsername(body.Username)
		if err != nil || u == nil || u.Disabled || !checkPassword(u.PasswordHash, body.Password) {
			auditLogin(c, body.Username, "auth.login_failed")
			loginRecordFailure(ipKey)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		loginReset(ipKey)
		_ = db.TouchUserLogin(u.ID)
		auditLogin(c, u.Username, "auth.login")
		tok, err := issueLocalJWTWithRole(u.Username, u.Role)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not issue token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": tok, "expires_in": 86400, "role": u.Role})
		return
	}

	// (3) Legacy env-only fallback (no users seeded yet). Constant-time compare of
	// both fields so neither username validity nor password length leaks via timing.
	expectedUser := strings.TrimSpace(os.Getenv("DASHBOARD_USER"))
	expectedPass := strings.TrimSpace(os.Getenv("DASHBOARD_PASSWORD"))
	userOK := subtle.ConstantTimeCompare([]byte(body.Username), []byte(expectedUser)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(body.Password), []byte(expectedPass)) == 1
	if !(userOK && passOK) {
		auditLogin(c, body.Username, "auth.login_failed")
		loginRecordFailure(ipKey)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	loginReset(ipKey)
	auditLogin(c, body.Username, "auth.login")
	tok, err := issueLocalJWTWithRole(body.Username, "admin")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not issue token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": tok, "expires_in": 86400, "role": "admin"})
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
	audit(c, "auth.logout", "", "revoked all sessions")
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
