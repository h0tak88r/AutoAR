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

	// minJWTSecretLen is the shortest AUTOAR_JWT_SECRET accepted: HS256 needs
	// at least 256 bits of key material to resist offline brute force of a
	// captured token.
	minJWTSecretLen = 32

	// Token "m" (mode) claim — how the token was obtained. Tokens minted while
	// no auth was configured ("open": any username, role admin) are rejected
	// once auth is enforced, so they can't outlive the switch to real logins.
	tokenModeDB   = "db"
	tokenModeEnv  = "env"
	tokenModeOpen = "open"

	roleAdmin  = "admin"
	roleViewer = "viewer" // legacy value only; resolved to roleMember below
	roleMember = "member"

	// bcrypt only uses the first 72 bytes and x/crypto refuses longer input.
	minPasswordLen   = 8
	maxPasswordBytes = 72

	// usersRecheckInterval bounds how often the auth path re-reads the users
	// table while the users-exist latch is still false.
	usersRecheckInterval = 30 * time.Second

	// maxLoginBodyBytes caps /api/auth/login (and change-password) bodies.
	maxLoginBodyBytes = 8 << 10
)

var (
	localAuthSecret     []byte
	localAuthSecretOnce sync.Once
	shortJWTSecretOnce  sync.Once

	// usersExistLatch is a process-lifetime latch: true once at least one DB user
	// is known to exist. Set by SeedInitialAdmin, by the lazy re-check and
	// whenever a user is created, so the hot auth path never queries the DB once
	// multi-user mode is active.
	usersExistLatch atomic.Bool

	// usersCheckArmed enables the lazy users-table re-check (see usersExist).
	// SeedInitialAdmin arms it at boot; unit tests that never seed keep
	// localAuthEnabled / CheckAuthBindSafety free of DB access.
	usersCheckArmed atomic.Bool
	// usersCountFailed is set while the users table cannot be read. Auth then
	// fails CLOSED — enforced, with logins and tokens refused — instead of
	// treating "unknown" as "no users" (open access) or as legacy env mode.
	usersCountFailed atomic.Bool
	// usersNextCheck is the unix-nano time of the next allowed re-check.
	usersNextCheck atomic.Int64

	// usersMu serializes user-table changes that must see a consistent view:
	// the last-admin guard, first-user role forcing and env-admin seeding.
	usersMu sync.Mutex

	// envTokensValidAfter is the legacy env-pair mode (no DB users) session
	// revocation cutoff per subject, unix seconds. In-memory only: DB users get
	// the persisted users.tokens_valid_after instead.
	envTokensValidAfter   = map[string]int64{}
	envTokensValidAfterMu sync.Mutex

	envSeedTooLongOnce sync.Once

	dummyHashOnce sync.Once
	dummyHash     []byte
)

// localAuthJWTSecret returns the HS256 signing secret.
// Priority: AUTOAR_JWT_SECRET env (≥32 bytes) → a persisted random secret
// (settings KV, so tokens survive restarts) → a freshly generated random secret.
// The secret is NEVER derived from the password: deriving it from the password
// made captured tokens offline-crackable to recover the cleartext password.
func localAuthJWTSecret() []byte {
	if s := strings.TrimSpace(os.Getenv("AUTOAR_JWT_SECRET")); s != "" {
		if len(s) >= minJWTSecretLen {
			return []byte(s)
		}
		shortJWTSecretOnce.Do(func() {
			log.Printf("[auth] ERROR: AUTOAR_JWT_SECRET is only %d bytes (minimum %d) — refusing to sign with it; using the DB-persisted signing secret instead", len(s), minJWTSecretLen)
		})
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
// tests.
func localAuthEnabled() bool {
	user := strings.TrimSpace(os.Getenv("DASHBOARD_USER"))
	pass := strings.TrimSpace(os.Getenv("DASHBOARD_PASSWORD"))
	return user != "" && pass != ""
}

// usersExist reports whether at least one dashboard user row exists. Once the
// latch is set this is a plain atomic read; until then (and once armed at boot)
// it re-reads the users table at most every usersRecheckInterval, so a DB that
// was not ready at boot — or users created by another process — are picked up
// without a restart.
func usersExist() bool {
	if usersExistLatch.Load() {
		return true
	}
	if usersCheckArmed.Load() {
		maybeRecheckUsers()
	}
	return usersExistLatch.Load()
}

func markUsersExist() {
	usersExistLatch.Store(true)
	usersCountFailed.Store(false)
}

// authConfigured reports whether any authentication is in effect: the legacy
// DASHBOARD_USER/PASSWORD env pair, one or more DB users, or — failing closed —
// a users table that could not be read.
func authConfigured() bool {
	return localAuthEnabled() || usersExist() || usersCountFailed.Load()
}

// refreshUsersState re-reads the users count, updating the latch and the
// fail-closed flag.
func refreshUsersState() (int, error) {
	n, err := db.CountUsers()
	if err != nil {
		usersCountFailed.Store(true)
		return 0, err
	}
	usersCountFailed.Store(false)
	if n > 0 {
		markUsersExist()
	}
	return n, nil
}

// maybeRecheckUsers runs one rate-limited re-check (single-flight via CAS; other
// callers keep the current state). An empty table with the env pair set seeds
// the env admin, covering a DB that only became reachable after boot.
func maybeRecheckUsers() {
	now := time.Now().UnixNano()
	next := usersNextCheck.Load()
	if now < next || !usersNextCheck.CompareAndSwap(next, now+int64(usersRecheckInterval)) {
		return
	}
	// TryLock: a holder of usersMu (user CRUD) may itself be calling usersExist;
	// skipping this round instead of blocking avoids a self-deadlock.
	if !usersMu.TryLock() {
		return
	}
	defer usersMu.Unlock()
	if _, err := seedEnvAdminIfEmptyLocked(); err != nil {
		log.Printf("[users] re-check: users table still unreadable (%v) — authentication stays fail-closed", err)
	}
}

// seedEnvAdminIfEmptyLocked counts users and, when the table is empty, seeds the
// DASHBOARD_USER/DASHBOARD_PASSWORD admin. Caller holds usersMu. The error is
// non-nil only when the users table could not be read.
func seedEnvAdminIfEmptyLocked() (seeded bool, err error) {
	n, err := refreshUsersState()
	if err != nil || n > 0 {
		return false, err
	}
	return seedEnvAdmin(), nil
}

// seedEnvAdmin creates the env-pair account as the first admin (caller has
// confirmed the users table is empty). Returns false when the pair is unset or
// the account cannot be created; the deployment then stays in legacy env mode.
// tokens_valid_after stays 0 so the env admin's current session survives the
// switch to DB-users mode.
func seedEnvAdmin() bool {
	u := strings.TrimSpace(os.Getenv("DASHBOARD_USER"))
	p := strings.TrimSpace(os.Getenv("DASHBOARD_PASSWORD"))
	if u == "" || p == "" {
		return false
	}
	if len(p) > maxPasswordBytes {
		envSeedTooLongOnce.Do(func() {
			log.Printf("[users] seed: DASHBOARD_PASSWORD is %d bytes but bcrypt accepts at most %d — the initial admin was NOT created in the users table. "+
				"Staying in legacy env-login mode; set a DASHBOARD_PASSWORD of at most %d bytes to migrate to DB users.", len(p), maxPasswordBytes, maxPasswordBytes)
		})
		return false
	}
	hash, err := hashPassword(p)
	if err != nil {
		log.Printf("[users] seed: hash failed: %v", err)
		return false
	}
	if _, err := db.CreateUser(u, hash, roleAdmin); err != nil {
		log.Printf("[users] seed: create admin %q failed: %v", u, err)
		return false
	}
	markUsersExist()
	log.Printf("[users] seeded initial admin %q from DASHBOARD_USER (manage users in Settings ▸ Users)", u)
	return true
}

// hashPassword returns a bcrypt hash of a plaintext password.
func hashPassword(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	return string(b), err
}

// checkPassword reports whether plain matches a stored bcrypt hash.
func checkPassword(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// dummyPasswordCompare burns one bcrypt comparison so a login for an unknown
// username takes as long as one for a real user (no enumeration by timing).
func dummyPasswordCompare(plain string) {
	dummyHashOnce.Do(func() {
		dummyHash, _ = bcrypt.GenerateFromPassword([]byte("autoar-timing-equalizer"), bcrypt.DefaultCost)
	})
	_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(plain))
}

// passwordPolicyError returns a user-facing reason a new password is
// unacceptable, or "" when it is fine.
func passwordPolicyError(p string) string {
	if len(p) < minPasswordLen {
		return fmt.Sprintf("password must be at least %d characters", minPasswordLen)
	}
	if len(p) > maxPasswordBytes {
		return fmt.Sprintf("password must be at most %d bytes", maxPasswordBytes)
	}
	return ""
}

// SeedInitialAdmin makes multi-user auth backward compatible. On boot, if no
// users exist yet but the legacy DASHBOARD_USER/DASHBOARD_PASSWORD env pair is
// set, it creates that account as the first admin — so existing single-login
// deployments keep working with the same credentials, now as an admin who can add
// more users from Settings ▸ Users. Idempotent: it never touches a non-empty
// users table. It also latches "users exist" and arms the lazy re-check; when the
// users table can't be read, auth fails CLOSED until a re-check succeeds.
// Call it on every boot, whichever env (DB_HOST / DATABASE_URL / defaults)
// configured the DB, after the schema exists (db.EnsureSchema).
func SeedInitialAdmin() {
	defer usersCheckArmed.Store(true)
	usersNextCheck.Store(time.Now().Add(usersRecheckInterval).UnixNano())
	usersMu.Lock()
	defer usersMu.Unlock()
	if _, err := seedEnvAdminIfEmptyLocked(); err != nil {
		log.Printf("[users] cannot read the users table (%v) — failing CLOSED: authentication is enforced and logins are refused until the database is reachable (re-checked every %s)", err, usersRecheckInterval)
	}
}

// issueLocalJWT creates a signed HS256 JWT (24h expiry) for username carrying
// the given role and mode ("m") claims. An empty role omits the claim.
func issueLocalJWT(username, role, mode string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": username,
		"iss": localAuthIssuer,
		"iat": now.Unix(),
		"exp": now.Add(24 * time.Hour).Unix(),
		"m":   mode,
	}
	if role != "" {
		claims["role"] = role
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(localAuthJWTSecret())
}

// issueLocalJWTWithRole issues a DB-users-mode token (the common case).
func issueLocalJWTWithRole(username, role string) (string, error) {
	return issueLocalJWT(username, role, tokenModeDB)
}

// revokeUserSessions ends every session of a DB user: tokens issued before the
// current second are rejected from now on (persisted, survives restarts).
func revokeUserSessions(id int64) error {
	return db.SetUserTokensValidAfter(id, time.Now().Unix())
}

// revokeEnvSessions is revokeUserSessions for the legacy env-pair login.
func revokeEnvSessions(sub string) {
	envTokensValidAfterMu.Lock()
	envTokensValidAfter[sub] = time.Now().Unix()
	envTokensValidAfterMu.Unlock()
}

func envTokenRevoked(sub string, iat int64) bool {
	envTokensValidAfterMu.Lock()
	defer envTokensValidAfterMu.Unlock()
	return iat < envTokensValidAfter[sub]
}

// verifyLocalJWT validates a token exactly like verifyLocalJWTClaims.
func verifyLocalJWT(raw string) error {
	_, _, err := verifyLocalJWTClaims(raw)
	return err
}

// verifyLocalJWTClaims validates the signature (HS256 only), expiry and issuer,
// then resolves the subject and role for the request context:
//   - DB-users mode: the token must come from a login ("db"/"env" mode), the user
//     must exist and be enabled, and iat must not precede the user's persisted
//     revocation cutoff. The role is read authoritatively from the users table,
//     so a role change or disable takes effect on the very next request.
//   - Users table unreadable: rejected (fail closed).
//   - Legacy env-only mode: an "env" token whose subject equals DASHBOARD_USER
//     and that was not revoked by a logout; role "admin".
//
// When no auth is configured the caller uses the passthrough and never invokes
// this.
func verifyLocalJWTClaims(raw string) (sub, role string, err error) {
	secret := localAuthJWTSecret()
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithIssuer(localAuthIssuer), jwt.WithExpirationRequired())
	if err != nil {
		return "", "", err
	}
	sub, _ = claims["sub"].(string)
	role, _ = claims["role"].(string)
	mode, _ := claims["m"].(string)
	var iat int64
	if t, e := claims.GetIssuedAt(); e == nil && t != nil {
		iat = t.Unix()
	}

	if usersExist() {
		if mode != tokenModeDB && mode != tokenModeEnv {
			return "", "", fmt.Errorf("token was not issued by a login")
		}
		u, e := db.GetUserByUsername(sub)
		if e != nil || u == nil || u.Disabled {
			return "", "", fmt.Errorf("user not found or disabled")
		}
		if iat < u.TokensValidAfter {
			return "", "", fmt.Errorf("token revoked")
		}
		if u.Role == roleViewer { // pre-rename rows resolve to member
			u.Role = roleMember
		}
		return u.Username, u.Role, nil // DB role is authoritative
	}
	if usersCountFailed.Load() {
		return "", "", fmt.Errorf("user database unavailable")
	}
	if localAuthEnabled() {
		if mode != tokenModeEnv {
			return "", "", fmt.Errorf("token was not issued by a login")
		}
		if sub != strings.TrimSpace(os.Getenv("DASHBOARD_USER")) {
			return "", "", fmt.Errorf("subject not authorized")
		}
		if envTokenRevoked(sub, iat) {
			return "", "", fmt.Errorf("token revoked")
		}
		return sub, roleAdmin, nil
	}
	return sub, role, nil
}

// ── Login brute-force lockout (keyed by username + client IP) ────────────────
//
// Keying on the pair means failures from one client against one account lock
// only that pair: behind a reverse proxy without AUTOAR_TRUSTED_PROXIES every
// client shares the proxy's IP, and an IP-only key let five bad logins from
// anyone lock out every user.

type loginAttemptState struct {
	fails     int
	lockUntil time.Time
	lastFail  time.Time
}

var (
	loginAttempts    = map[string]*loginAttemptState{}
	loginAttemptsMu  sync.Mutex
	loginLastPruneAt time.Time
)

const (
	loginMaxFails = 5
	loginBaseLock = 30 * time.Second
	loginMaxLock  = 15 * time.Minute
	// loginAttemptTTL: a key with no failure for this long (and no active lock)
	// is forgotten, and its failure count starts over.
	loginAttemptTTL        = 30 * time.Minute
	loginPruneEvery        = time.Minute
	loginAttemptsSoftLimit = 10000
)

// loginKey builds the lockout key for a login attempt.
func loginKey(username, ip string) string {
	return strings.ToLower(capAuditField(strings.TrimSpace(username), maxAuditUsernameLen)) + "\x00" + ip
}

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
	now := time.Now()
	pruneLoginAttemptsLocked(now)
	st := loginAttempts[key]
	if st == nil || (now.Sub(st.lastFail) > loginAttemptTTL && now.After(st.lockUntil)) {
		st = &loginAttemptState{}
		loginAttempts[key] = st
	}
	st.fails++
	st.lastFail = now
	if st.fails >= loginMaxFails {
		// Exponential backoff: 30s, 1m, 2m, 4m, 8m, then capped at 15m.
		shift := st.fails - loginMaxFails
		if shift > 5 {
			shift = 5
		}
		lock := loginBaseLock << uint(shift)
		if lock > loginMaxLock {
			lock = loginMaxLock
		}
		st.lockUntil = now.Add(lock)
	}
}

// pruneLoginAttemptsLocked drops stale entries (at most once a minute, or when
// the map grows past the soft limit) so username spraying can't grow it
// without bound. Caller holds loginAttemptsMu.
func pruneLoginAttemptsLocked(now time.Time) {
	if now.Sub(loginLastPruneAt) < loginPruneEvery && len(loginAttempts) < loginAttemptsSoftLimit {
		return
	}
	loginLastPruneAt = now
	for k, st := range loginAttempts {
		if now.Sub(st.lastFail) > loginAttemptTTL && now.After(st.lockUntil) {
			delete(loginAttempts, k)
		}
	}
	if len(loginAttempts) >= loginAttemptsSoftLimit {
		// Still flooded: forget keys that are not currently locked.
		for k, st := range loginAttempts {
			if now.After(st.lockUntil) {
				delete(loginAttempts, k)
			}
		}
	}
}

func loginReset(key string) {
	loginAttemptsMu.Lock()
	delete(loginAttempts, key)
	loginAttemptsMu.Unlock()
}

// auditLogin records a login attempt in the audit log with the attempted username
// (capped — it is attacker-chosen) and source IP (the request has no auth context
// yet, so the generic audit() would mis-attribute it to "system").
func auditLogin(c *gin.Context, username, action string) {
	actor := capAuditField(strings.TrimSpace(username), maxAuditUsernameLen)
	_ = db.InsertAuditEvent(db.AuditEvent{Actor: actor, Action: action, IP: c.ClientIP()})
}

func tooManyAttempts(c *gin.Context, d time.Duration) {
	secs := int(d.Seconds()) + 1
	c.Header("Retry-After", fmt.Sprintf("%d", secs))
	c.JSON(http.StatusTooManyRequests, gin.H{"error": fmt.Sprintf("too many failed attempts — retry in %ds", secs)})
}

// POST /api/auth/login — accepts { "username": "...", "password": "..." } and
// returns { "token": "<jwt>", "expires_in": 86400, "role": "admin|viewer" }.
//
// Resolution order:
//  1. No auth configured (no users AND no env pair) → issue an "open" token for
//     anyone (dev / no-op auth); it stops working once auth is enforced.
//  2. Users exist → authenticate against the DB with bcrypt, honoring the role
//     and the disabled flag.
//  3. Users table unreadable → 503 (fail closed; never fall back to the env pair,
//     whose password may have been changed in the UI since it was seeded).
//  4. Legacy fallback (env pair set, users table empty — e.g. a seed failure) →
//     constant-time compare against the env pair as an admin.
func apiLocalAuthLogin(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxLoginBodyBytes)
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
		tok, err := issueLocalJWT(body.Username, roleAdmin, tokenModeOpen)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not issue token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": tok, "expires_in": 86400, "role": roleAdmin})
		return
	}

	lockKey := loginKey(body.Username, c.ClientIP())
	if d := loginLockRemaining(lockKey); d > 0 {
		tooManyAttempts(c, d)
		return
	}

	// (2) DB users mode.
	if usersExist() {
		u, err := db.GetUserByUsername(body.Username)
		if err != nil && !db.IsNoRows(err) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "user database unavailable — try again shortly"})
			return
		}
		ok := false
		if u != nil {
			// Compare even for a disabled user so timing doesn't reveal it.
			ok = checkPassword(u.PasswordHash, body.Password) && !u.Disabled
		} else {
			dummyPasswordCompare(body.Password)
		}
		if !ok {
			auditLogin(c, body.Username, "auth.login_failed")
			loginRecordFailure(lockKey)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		loginReset(lockKey)
		_ = db.TouchUserLogin(u.ID)
		auditLogin(c, u.Username, "auth.login")
		tok, err := issueLocalJWT(u.Username, u.Role, tokenModeDB)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not issue token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": tok, "expires_in": 86400, "role": u.Role})
		return
	}

	// (3) Fail closed while the users table can't be read.
	if usersCountFailed.Load() || !localAuthEnabled() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "user database unavailable — try again shortly"})
		return
	}

	// (4) Legacy env-only fallback (no users seeded yet). Constant-time compare of
	// both fields so neither username validity nor password length leaks via timing.
	expectedUser := strings.TrimSpace(os.Getenv("DASHBOARD_USER"))
	expectedPass := strings.TrimSpace(os.Getenv("DASHBOARD_PASSWORD"))
	userOK := subtle.ConstantTimeCompare([]byte(body.Username), []byte(expectedUser)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(body.Password), []byte(expectedPass)) == 1
	if !(userOK && passOK) {
		auditLogin(c, body.Username, "auth.login_failed")
		loginRecordFailure(lockKey)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	loginReset(lockKey)
	auditLogin(c, body.Username, "auth.login")
	tok, err := issueLocalJWT(body.Username, roleAdmin, tokenModeEnv)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not issue token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": tok, "expires_in": 86400, "role": roleAdmin})
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

// POST /api/auth/logout — ends every session of the CALLER only (tokens issued
// before now). Persisted for DB users; in-memory for the legacy env login.
func apiLocalAuthLogout(c *gin.Context) {
	sub := currentUsername(c)
	if dashboardAPIAuthEnforced() && sub != "" {
		if usersExist() {
			u, err := db.GetUserByUsername(sub)
			if err != nil || u == nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "could not revoke session"})
				return
			}
			if err := revokeUserSessions(u.ID); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "could not revoke session"})
				return
			}
		} else {
			revokeEnvSessions(sub)
		}
	}
	audit(c, "auth.logout", sub, "ended this user's sessions")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// CheckAuthBindSafety refuses to run unauthenticated on a public (non-loopback)
// interface. Call it AFTER the DB is initialized and SeedInitialAdmin has run,
// so DB users count as configured auth. Returns a non-nil error that the caller
// should treat as fatal.
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
	return fmt.Errorf("refusing to start: API_HOST=%q exposes the dashboard on a public interface but no login is configured "+
		"(no dashboard users in the database and no DASHBOARD_USER/DASHBOARD_PASSWORD). "+
		"Set DASHBOARD_USER and DASHBOARD_PASSWORD to create the first admin, or bind to 127.0.0.1 and add users in Settings ▸ Users. "+
		"(AUTOAR_API_AUTH_DISABLED=true turns authentication off entirely — only for a trusted, isolated network.)", host)
}
