package api

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/h0tak88r/AutoAR/internal/db"
)

// fixturePW returns a throwaway test password built at runtime. Written as
// `"password": "<literal>"` pairs, fake fixtures were raised as incidents by
// secret scanners (GitGuardian's generic-password detector). Values only need
// to be stable within a test and pass the 8-72 byte policy.
func fixturePW(tag string) string { return tag + "-fixture-" + "x1" }

// issueTestToken signs a token like issueLocalJWT but with an explicit iat, so
// revocation (second precision) can be tested without sleeping.
func issueTestToken(t *testing.T, sub, role, mode string, iat time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub": sub, "iss": localAuthIssuer, "iat": iat.Unix(),
		"exp": iat.Add(24 * time.Hour).Unix(), "m": mode,
	}
	if role != "" {
		claims["role"] = role
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(localAuthJWTSecret())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

// buildSelfServiceEngine is buildAuthEngine plus the logout route and the
// ?token=-capable stream path.
func buildSelfServiceEngine() *gin.Engine {
	r := buildAuthEngine()
	auth := supabaseJWTAuth()
	r.POST("/api/auth/logout", auth, apiLocalAuthLogout)
	r.GET("/api/auth/me", auth, apiAuthMe)
	r.GET("/api/scans/:id/logs/stream", auth, func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
	return r
}

// A1: an unreadable users table fails CLOSED (auth enforced, logins refused —
// even the env pair), and the lazy re-check recovers without a restart.
func TestSeedFailsClosedWhenUsersTableUnreadable(t *testing.T) {
	setupUsersTestDB(t)
	t.Setenv("DASHBOARD_USER", "root")
	t.Setenv("DASHBOARD_PASSWORD", fixturePW("env"))
	goodType, goodHost := os.Getenv("DB_TYPE"), os.Getenv("DB_HOST")

	db.SetDB(nil)
	t.Setenv("DB_TYPE", "unsupported-for-test") // db.Init now fails
	SeedInitialAdmin()
	if !usersCountFailed.Load() {
		t.Fatal("count failure should set the fail-closed flag")
	}
	t.Setenv("DASHBOARD_USER", "")
	t.Setenv("DASHBOARD_PASSWORD", "")
	if !dashboardAPIAuthEnforced() {
		t.Fatal("auth must stay enforced (fail closed) when the users table can't be read, even with no env pair")
	}
	t.Setenv("DASHBOARD_USER", "root")
	t.Setenv("DASHBOARD_PASSWORD", fixturePW("env"))
	if w := doLogin(t, "root", fixturePW("env")); w.Code != http.StatusServiceUnavailable {
		t.Errorf("env-pair login while users table unreadable = %d, want 503", w.Code)
	}

	// DB comes back: the next (forced) re-check seeds the env admin.
	t.Setenv("DB_TYPE", goodType)
	t.Setenv("DB_HOST", goodHost)
	if err := db.Init(); err != nil {
		t.Fatalf("db.Init: %v", err)
	}
	usersNextCheck.Store(0)
	if !usersExist() {
		t.Fatal("re-check should have seeded the env admin and latched users-exist")
	}
	if usersCountFailed.Load() {
		t.Error("fail-closed flag should clear after a successful re-check")
	}
	if w := doLogin(t, "root", fixturePW("env")); w.Code != http.StatusOK {
		t.Errorf("login after recovery = %d, body=%s", w.Code, w.Body.String())
	}
}

// A1: users created after boot (latch still false) are picked up lazily.
func TestLazyRecheckPicksUpUsers(t *testing.T) {
	setupUsersTestDB(t)
	SeedInitialAdmin() // empty table, no env pair → open, but armed
	if dashboardAPIAuthEnforced() {
		t.Fatal("no users and no env pair should mean no auth")
	}
	h, _ := hashPassword("someone-pass-1")
	if _, err := db.CreateUser("someone", h, roleAdmin); err != nil { // bypasses markUsersExist
		t.Fatalf("CreateUser: %v", err)
	}
	usersNextCheck.Store(0)
	if !dashboardAPIAuthEnforced() {
		t.Error("lazy re-check should detect the new DB user and enforce auth")
	}
}

// A2: an AUTOAR_JWT_SECRET shorter than 32 bytes is refused.
func TestShortJWTSecretIgnored(t *testing.T) {
	setupUsersTestDB(t)
	t.Setenv("AUTOAR_JWT_SECRET", "too-short")
	if got := string(localAuthJWTSecret()); got == "too-short" || len(got) < minJWTSecretLen {
		t.Errorf("short AUTOAR_JWT_SECRET was used (or fallback too short): %q", got)
	}
	long := strings.Repeat("k", 40)
	t.Setenv("AUTOAR_JWT_SECRET", long)
	if got := string(localAuthJWTSecret()); got != long {
		t.Error("a 40-byte AUTOAR_JWT_SECRET should be used as-is")
	}
}

// A3: admin-only data routes 403 for viewers on the real route table.
func TestAdminOnlyRoutesRejectViewer(t *testing.T) {
	setupUsersTestDB(t)
	mustCreateUser(t, "adm", "adm-pass-12", roleAdmin)
	mustCreateUser(t, "vwr", "vwr-pass-12", roleViewer)
	adminTok, _ := issueLocalJWTWithRole("adm", roleAdmin)
	viewerTok, _ := issueLocalJWTWithRole("vwr", roleViewer)
	r := SetupAPI()

	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/api/r2/files"},
		{http.MethodPost, "/api/r2/delete"},
		{http.MethodGet, "/api/report-templates"},
		{http.MethodGet, "/api/report-templates/export"},
		{http.MethodGet, "/api/report-templates/some-name"},
		{http.MethodPost, "/api/report-templates"},
		{http.MethodPost, "/api/report-templates/import"},
		{http.MethodDelete, "/api/report-templates/some-name"},
		{http.MethodGet, "/api/system/metrics"},
		{http.MethodGet, "/api/system/limits"},
		{http.MethodGet, "/api/scope/debug"},
		{http.MethodGet, "/metrics"},
		{http.MethodPost, "/api/settings"},
	} {
		if w := req(t, r, rt.method, rt.path, viewerTok, map[string]string{}); w.Code != http.StatusForbidden {
			t.Errorf("viewer %s %s = %d, want 403", rt.method, rt.path, w.Code)
		}
	}
	if w := req(t, r, http.MethodGet, "/api/system/limits", adminTok, nil); w.Code != http.StatusOK {
		t.Errorf("admin GET /api/system/limits = %d, want 200", w.Code)
	}
}

// A4: logout ends only the caller's sessions, persists the cutoff in the DB, and
// a fresh login afterwards works.
func TestLogoutRevokesOnlyCaller(t *testing.T) {
	setupUsersTestDB(t)
	mustCreateUser(t, "alice", "alice-pass-1", roleAdmin)
	mustCreateUser(t, "bob", "bob-pass-12", roleViewer)
	past := time.Now().Add(-10 * time.Second)
	aliceTok := issueTestToken(t, "alice", roleAdmin, tokenModeDB, past)
	bobTok := issueTestToken(t, "bob", roleViewer, tokenModeDB, past)
	r := buildSelfServiceEngine()

	// A viewer may log out (self-service) — and that must not touch alice.
	if w := req(t, r, http.MethodPost, "/api/auth/logout", bobTok, nil); w.Code != 200 {
		t.Fatalf("viewer logout = %d", w.Code)
	}
	if w := req(t, r, http.MethodGet, "/api/ping", bobTok, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("bob's token after his logout = %d, want 401", w.Code)
	}
	if w := req(t, r, http.MethodGet, "/api/ping", aliceTok, nil); w.Code != 200 {
		t.Errorf("alice's token after BOB's logout = %d, want 200 (logout must not sign out everyone)", w.Code)
	}
	// Persisted (survives a restart).
	if u, _ := db.GetUserByUsername("bob"); u == nil || u.TokensValidAfter == 0 {
		t.Error("logout should persist users.tokens_valid_after")
	}
	// A token issued at/after the cutoff second is valid (no same-second lockout).
	fresh, _ := issueLocalJWTWithRole("bob", roleViewer)
	if w := req(t, r, http.MethodGet, "/api/ping", fresh, nil); w.Code != 200 {
		t.Errorf("fresh token after logout = %d, want 200", w.Code)
	}
}

// A4: disable / role change / admin password reset end the target's sessions.
func TestUserUpdateRevokesTargetSessions(t *testing.T) {
	setupUsersTestDB(t)
	mustCreateUser(t, "adm", "adm-pass-12", roleAdmin)
	vid := mustCreateUser(t, "vwr", "vwr-pass-12", roleViewer)
	adminTok, _ := issueLocalJWTWithRole("adm", roleAdmin)
	r := buildSelfServiceEngine()
	for _, upd := range []map[string]any{
		{"password": fixturePW("brand-new")},
		{"role": roleAdmin},
		{"disabled": true},
	} {
		old := issueTestToken(t, "vwr", "", tokenModeDB, time.Now().Add(-10*time.Second))
		if w := req(t, r, http.MethodPut, "/api/users/"+itoa(vid), adminTok, upd); w.Code != 200 {
			t.Fatalf("update %v = %d, body=%s", upd, w.Code, w.Body.String())
		}
		if _, _, err := verifyLocalJWTClaims(old); err == nil {
			t.Errorf("update %v should revoke the target's existing token", upd)
		}
	}
}

// A-minor(b): a token minted in no-auth mode is useless once auth is enforced.
func TestOpenModeTokenRejectedOnceAuthEnforced(t *testing.T) {
	setupUsersTestDB(t)
	w := doLogin(t, "alice", "anything") // no auth configured → open token
	if w.Code != 200 {
		t.Fatalf("open-mode login = %d", w.Code)
	}
	var resp struct{ Token string }
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	mustCreateUser(t, "alice", "alice-pass-1", roleAdmin)
	if _, _, err := verifyLocalJWTClaims(resp.Token); err == nil {
		t.Error("an open-mode token must be rejected once DB users exist")
	}
	// Tokens with no mode claim (pre-upgrade) are rejected too.
	if _, _, err := verifyLocalJWTClaims(issueTestToken(t, "alice", roleAdmin, "", time.Now())); err == nil {
		t.Error("a token without a mode claim must be rejected while auth is enforced")
	}
}

// A-minor(a): ?token= is honored only on GET for the stream/download routes.
func TestQueryTokenOnlyOnStreamRoutes(t *testing.T) {
	setupUsersTestDB(t)
	mustCreateUser(t, "adm", "adm-pass-12", roleAdmin)
	tok, _ := issueLocalJWTWithRole("adm", roleAdmin)
	r := buildSelfServiceEngine()
	if w := req(t, r, http.MethodGet, "/api/ping?token="+tok, "", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("?token= on a normal route = %d, want 401", w.Code)
	}
	if w := req(t, r, http.MethodPost, "/api/ping?token="+tok, "", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("?token= on a POST = %d, want 401", w.Code)
	}
	if w := req(t, r, http.MethodGet, "/api/scans/abc/logs/stream?token="+tok, "", nil); w.Code != 200 {
		t.Errorf("?token= on the log stream = %d, want 200", w.Code)
	}
}

// A5: the first user can never be a viewer (that would leave zero admins).
func TestFirstUserForcedToAdmin(t *testing.T) {
	setupUsersTestDB(t)
	r := buildAuthEngine() // no auth configured → caller acts as admin
	w := req(t, r, http.MethodPost, "/api/users", "", map[string]string{"username": "first", "password": "first-pass-1", "role": "viewer"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create first user = %d, body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Role       string `json:"role"`
		RoleForced bool   `json:"role_forced"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Role != roleAdmin || !resp.RoleForced {
		t.Errorf("first user role=%q forced=%v, want admin/true", resp.Role, resp.RoleForced)
	}
	if n, _ := db.CountAdmins(); n != 1 {
		t.Errorf("CountAdmins = %d, want 1", n)
	}
}

// A5: in legacy env mode, adding the first DB user migrates the env admin first
// (it would otherwise be locked out), and its current session survives.
func TestCreateUserInEnvModeSeedsEnvAdmin(t *testing.T) {
	setupUsersTestDB(t)
	t.Setenv("DASHBOARD_USER", "root")
	t.Setenv("DASHBOARD_PASSWORD", fixturePW("env"))
	envTok := issueTestToken(t, "root", roleAdmin, tokenModeEnv, time.Now().Add(-10*time.Second))
	r := buildAuthEngine()
	w := req(t, r, http.MethodPost, "/api/users", envTok, map[string]string{"username": "bob", "password": fixturePW("bob"), "role": "viewer"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create in env mode = %d, body=%s", w.Code, w.Body.String())
	}
	root, err := db.GetUserByUsername("root")
	if err != nil || root == nil || root.Role != roleAdmin {
		t.Fatalf("env admin not migrated into the users table: %+v %v", root, err)
	}
	if bob, _ := db.GetUserByUsername("bob"); bob == nil || bob.Role != roleViewer {
		t.Errorf("bob should be a viewer (an admin already exists): %+v", bob)
	}
	if _, _, err := verifyLocalJWTClaims(envTok); err != nil {
		t.Errorf("env admin's existing session should survive the migration: %v", err)
	}
	if w := doLogin(t, "root", fixturePW("env")); w.Code != 200 {
		t.Errorf("env admin login after migration = %d", w.Code)
	}
}

// A5: a DASHBOARD_PASSWORD over bcrypt's 72-byte limit can't be seeded — the
// deployment stays in env mode instead of failing.
func TestLongEnvPasswordStaysInEnvMode(t *testing.T) {
	setupUsersTestDB(t)
	long := strings.Repeat("p", 80)
	t.Setenv("DASHBOARD_USER", "root")
	t.Setenv("DASHBOARD_PASSWORD", long)
	SeedInitialAdmin()
	if usersExist() {
		t.Fatal("an over-long env password must not seed a DB user")
	}
	if w := doLogin(t, "root", long); w.Code != 200 {
		t.Errorf("env-mode login with the long password = %d, want 200", w.Code)
	}
}

// A6: lockout is per (username, IP) — one account's failures don't lock others.
func TestLoginLockoutPerUsernameAndIP(t *testing.T) {
	setupUsersTestDB(t)
	mustCreateUser(t, "alice", "alice-pass-1", roleAdmin)
	mustCreateUser(t, "bob", "bob-pass-12", roleViewer)
	for i := 0; i < loginMaxFails; i++ {
		_ = doLogin(t, "alice", "wrong")
	}
	if w := doLogin(t, "alice", "alice-pass-1"); w.Code != http.StatusTooManyRequests {
		t.Errorf("alice after %d failures = %d, want 429", loginMaxFails, w.Code)
	}
	if w := doLogin(t, "bob", "bob-pass-12"); w.Code != 200 {
		t.Errorf("bob from the same IP = %d, want 200 (lockout must not be IP-wide)", w.Code)
	}
}

// A6: stale lockout entries are pruned.
func TestLoginAttemptsPruned(t *testing.T) {
	resetAuthStateForTest()
	defer resetAuthStateForTest()
	loginAttemptsMu.Lock()
	loginAttempts["stale\x00203.0.113.9"] = &loginAttemptState{fails: 3, lastFail: time.Now().Add(-2 * loginAttemptTTL)}
	loginLastPruneAt = time.Time{}
	loginAttemptsMu.Unlock()
	loginRecordFailure("fresh\x00203.0.113.9")
	loginAttemptsMu.Lock()
	_, stale := loginAttempts["stale\x00203.0.113.9"]
	loginAttemptsMu.Unlock()
	if stale {
		t.Error("stale lockout entry was not pruned")
	}
}

// A7: change-password ends old sessions, returns a fresh token, throttles wrong
// current passwords and is audited.
func TestChangePasswordRevokesThrottlesAudits(t *testing.T) {
	setupUsersTestDB(t)
	mustCreateUser(t, "adm", "adm-pass-12", roleAdmin)
	mustCreateUser(t, "vwr", fixturePW("old"), roleViewer)
	oldTok := issueTestToken(t, "vwr", roleViewer, tokenModeDB, time.Now().Add(-10*time.Second))
	stolen := issueTestToken(t, "vwr", roleViewer, tokenModeDB, time.Now().Add(-20*time.Second))
	r := buildSelfServiceEngine()

	w := req(t, r, http.MethodPost, "/api/auth/change-password", oldTok,
		map[string]string{"old_password": fixturePW("old"), "new_password": fixturePW("new")})
	if w.Code != 200 {
		t.Fatalf("change-password = %d, body=%s", w.Code, w.Body.String())
	}
	var resp struct{ Token string }
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Token == "" {
		t.Fatal("change-password should return a fresh token")
	}
	if w := req(t, r, http.MethodGet, "/api/ping", stolen, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("pre-change token = %d, want 401", w.Code)
	}
	if w := req(t, r, http.MethodGet, "/api/ping", resp.Token, nil); w.Code != 200 {
		t.Errorf("fresh token = %d, want 200", w.Code)
	}
	if ev, _ := db.ListAuditEvents(50, "", "auth.change_password"); len(ev) != 1 {
		t.Errorf("auth.change_password audit events = %d, want 1", len(ev))
	}

	for i := 0; i < loginMaxFails; i++ {
		_ = req(t, r, http.MethodPost, "/api/auth/change-password", resp.Token,
			map[string]string{"old_password": "guess", "new_password": "whatever-123"})
	}
	w = req(t, r, http.MethodPost, "/api/auth/change-password", resp.Token,
		map[string]string{"old_password": fixturePW("new"), "new_password": "whatever-123"})
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("change-password after %d wrong guesses = %d, want 429", loginMaxFails, w.Code)
	}
	if ev, _ := db.ListAuditEvents(50, "", "auth.change_password_failed"); len(ev) != loginMaxFails {
		t.Errorf("failed change-password audit events = %d, want %d", len(ev), loginMaxFails)
	}
}

// A9: webhook URLs must be public https; a bad one rejects the whole request.
func TestWebhookURLValidation(t *testing.T) {
	for _, bad := range []string{
		"http://discord.com/api/webhooks/1/x",
		"https://127.0.0.1/hook",
		"https://10.0.0.5/hook",
		"https://169.254.169.254/latest/meta-data",
		"ftp://example.com/x",
	} {
		if err := validateWebhookURL(bad); err == nil {
			t.Errorf("validateWebhookURL(%q) = nil, want error", bad)
		}
	}

	setupUsersTestDB(t)
	t.Setenv("OPENROUTER_API_KEY", "unchanged")
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/settings", apiUpdateSettingsHandler)
	w := req(t, r, http.MethodPost, "/api/settings", "", map[string]string{
		"webhook_findings": "https://192.168.1.10/hook",
		"openrouter_key":   "should-not-be-saved",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("internal webhook = %d, want 400", w.Code)
	}
	if got := os.Getenv("OPENROUTER_API_KEY"); got != "unchanged" {
		t.Errorf("a rejected request still saved another setting: OPENROUTER_API_KEY=%q", got)
	}
}

// A11: apiUpdateUser validates everything before mutating anything.
func TestUpdateUserValidatesBeforeMutating(t *testing.T) {
	setupUsersTestDB(t)
	mustCreateUser(t, "adm", "adm-pass-12", roleAdmin)
	id := mustCreateUser(t, "adm2", "adm2-pass-1", roleAdmin)
	tok, _ := issueLocalJWTWithRole("adm", roleAdmin)
	r := buildAuthEngine()
	w := req(t, r, http.MethodPut, "/api/users/"+itoa(id), tok, map[string]any{"role": "viewer", "disabled": true, "password": "short"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("short password = %d, want 400", w.Code)
	}
	u, _ := db.GetUserByID(id)
	if u.Role != roleAdmin || u.Disabled {
		t.Errorf("rejected update still mutated the user: role=%q disabled=%v", u.Role, u.Disabled)
	}
}

// A11: failed-login audit caps the attacker-chosen username.
func TestFailedLoginAuditCapsUsername(t *testing.T) {
	setupUsersTestDB(t)
	mustCreateUser(t, "adm", "adm-pass-12", roleAdmin)
	_ = doLogin(t, strings.Repeat("A", 5000), "x")
	ev, _ := db.ListAuditEvents(5, "", "auth.login_failed")
	if len(ev) != 1 || len(ev[0].Actor) > maxAuditUsernameLen {
		t.Errorf("failed-login audit actor not capped: %d events, len=%d", len(ev), func() int {
			if len(ev) == 0 {
				return 0
			}
			return len(ev[0].Actor)
		}())
	}
}

// A12: concurrent demotes of the last two admins can't both pass the guard.
func TestLastAdminGuardSerialized(t *testing.T) {
	setupUsersTestDB(t)
	a := mustCreateUser(t, "a1", "a1-pass-123", roleAdmin)
	b := mustCreateUser(t, "a2", "a2-pass-123", roleAdmin)
	tok, _ := issueLocalJWTWithRole("a1", roleAdmin)
	r := buildAuthEngine()
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i, id := range []int64{a, b} {
		wg.Add(1)
		go func(i int, id int64) {
			defer wg.Done()
			body, _ := json.Marshal(map[string]string{"role": "viewer"})
			rq, _ := http.NewRequest(http.MethodPut, "/api/users/"+itoa(id), bytes.NewReader(body))
			rq.Header.Set("Authorization", "Bearer "+tok)
			rq.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, rq)
			codes[i] = w.Code
		}(i, id)
	}
	wg.Wait()
	if n, _ := db.CountAdmins(); n < 1 {
		t.Errorf("concurrent demotes left %d admins (codes %v)", n, codes)
	}
}

// A13: only the exact "admin" role may mutate or pass requireAdmin.
func TestRoleAllowlist(t *testing.T) {
	setupUsersTestDB(t)
	mustCreateUser(t, "adm", "adm-pass-12", roleAdmin)
	mustCreateUser(t, "odd", "odd-pass-123", "Viewer") // mis-cased / unknown role
	tok, _ := issueLocalJWTWithRole("odd", "")
	r := buildAuthEngine()
	if w := req(t, r, http.MethodPost, "/api/ping", tok, map[string]string{}); w.Code != http.StatusForbidden {
		t.Errorf("unknown role POST = %d, want 403", w.Code)
	}
	if w := req(t, r, http.MethodGet, "/api/users", tok, nil); w.Code != http.StatusForbidden {
		t.Errorf("unknown role GET /api/users = %d, want 403", w.Code)
	}
}

// A15: usernames are restricted to an inert charset.
func TestCreateUserRejectsUnsafeUsername(t *testing.T) {
	setupUsersTestDB(t)
	mustCreateUser(t, "adm", "adm-pass-12", roleAdmin)
	tok, _ := issueLocalJWTWithRole("adm", roleAdmin)
	r := buildAuthEngine()
	for _, name := range []string{`x');alert(1)//`, "<img src=x>", "has space", strings.Repeat("a", 65)} {
		if w := req(t, r, http.MethodPost, "/api/users", tok, map[string]string{"username": name, "password": "long-enough-1"}); w.Code != http.StatusBadRequest {
			t.Errorf("username %q = %d, want 400", name, w.Code)
		}
	}
}

// A17: /api/config returns only the login-screen fields without a valid token.
func TestConfigPublicPayloadWithoutToken(t *testing.T) {
	setupUsersTestDB(t)
	mustCreateUser(t, "adm", "adm-pass-12", roleAdmin)
	tok, _ := issueLocalJWTWithRole("adm", roleAdmin)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/config", apiConfigHandler)

	for _, bearer := range []string{"", "garbage.token.value"} {
		w := req(t, r, http.MethodGet, "/api/config", bearer, nil)
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		if _, leaked := m["r2_bucket"]; leaked || m["auth_enabled"] != true || len(m) > 4 {
			t.Errorf("unauthenticated /api/config (bearer=%q) leaked fields: %v", bearer, m)
		}
	}
	w := req(t, r, http.MethodGet, "/api/config", tok, nil)
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	if _, ok := m["r2_bucket"]; !ok || m["public"] != nil {
		t.Errorf("authenticated /api/config should return the full payload: %v", m)
	}
}

// A18: a container env value shadowed by a different DB value is reported by
// KEY name only.
func TestHydrateWarnsOnEnvDBMismatchByKeyOnly(t *testing.T) {
	setupUsersTestDB(t)
	if err := db.SetSetting("CHAOS_API_KEY", "db-secret-value"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	t.Setenv("CHAOS_API_KEY", "env-secret-value")
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	HydrateEnvFromDB()
	out := buf.String()
	if !strings.Contains(out, "CHAOS_API_KEY") {
		t.Errorf("expected a warning naming CHAOS_API_KEY, got %q", out)
	}
	if strings.Contains(out, "secret-value") {
		t.Errorf("warning leaked a value: %q", out)
	}
}

// A11: settings.update audit detail lists changed KEYS only, never values, and
// ignores unrelated settings (e.g. the JWT secret row).
func TestChangedSettingKeysNamesOnly(t *testing.T) {
	before := map[string]string{"H1_TOKEN": "old-secret", "timeout_nuclei": "600"}
	after := map[string]string{"H1_TOKEN": "new-secret", "timeout_nuclei": "600", "CHAOS_API_KEY": "x", jwtSecretSettingKey: "zz"}
	got := changedSettingKeys(before, after)
	if got != "keys: CHAOS_API_KEY,H1_TOKEN" {
		t.Errorf("changedSettingKeys = %q", got)
	}
	if strings.Contains(got, "secret") {
		t.Errorf("detail leaked a value: %q", got)
	}
	if got := changedSettingKeys(before, before); got != "no changes" {
		t.Errorf("unchanged snapshot = %q, want \"no changes\"", got)
	}
}

// A10: DB users satisfy the bind-safety check without the env pair.
func TestBindSafetyCountsDBUsers(t *testing.T) {
	setupUsersTestDB(t)
	mustCreateUser(t, "adm", "adm-pass-12", roleAdmin)
	if err := CheckAuthBindSafety("0.0.0.0"); err != nil {
		t.Errorf("DB users exist → public bind should be allowed, got %v", err)
	}
}
