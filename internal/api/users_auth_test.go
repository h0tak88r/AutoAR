package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/db"
)

// setupUsersTestDB points the DB layer at a throwaway SQLite file, creates the
// schema directly (bypassing the once-gated EnsureSchema so each test is clean),
// resets the users-exist latch, and pins a fixed JWT secret so issue/verify are
// deterministic without DB access.
func setupUsersTestDB(t *testing.T) {
	t.Helper()
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "users_test.db"))
	t.Setenv("AUTOAR_SILENT", "true")
	t.Setenv("AUTOAR_JWT_SECRET", "unit-test-secret-key-please-ignore")
	t.Setenv("AUTOAR_API_AUTH_DISABLED", "")
	t.Setenv("DASHBOARD_USER", "")
	t.Setenv("DASHBOARD_PASSWORD", "")

	db.SetDB(nil) // drop any instance a prior test created
	if err := db.Init(); err != nil {
		t.Fatalf("db.Init: %v", err)
	}
	if err := db.InitSchema(); err != nil {
		t.Fatalf("db.InitSchema: %v", err)
	}
	usersExistLatch.Store(false)
	t.Cleanup(func() {
		db.SetDB(nil)
		usersExistLatch.Store(false)
	})
}

func mustCreateUser(t *testing.T, username, password, role string) int64 {
	t.Helper()
	h, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	id, err := db.CreateUser(username, h, role)
	if err != nil {
		t.Fatalf("CreateUser %q: %v", username, err)
	}
	markUsersExist()
	return id
}

func TestSeedInitialAdmin(t *testing.T) {
	setupUsersTestDB(t)
	t.Setenv("DASHBOARD_USER", "root")
	t.Setenv("DASHBOARD_PASSWORD", "hunter2hunter")

	SeedInitialAdmin()

	if !usersExist() {
		t.Fatal("usersExist() should be true after seeding")
	}
	u, err := db.GetUserByUsername("root")
	if err != nil || u == nil {
		t.Fatalf("seeded admin not found: %v", err)
	}
	if u.Role != "admin" {
		t.Errorf("seeded role = %q, want admin", u.Role)
	}
	if !checkPassword(u.PasswordHash, "hunter2hunter") {
		t.Error("seeded password hash does not verify")
	}
	if checkPassword(u.PasswordHash, "wrong") {
		t.Error("seeded password verified a wrong password")
	}

	// Idempotent: a second call must not create a duplicate or a second admin.
	SeedInitialAdmin()
	if n, _ := db.CountUsers(); n != 1 {
		t.Errorf("CountUsers after re-seed = %d, want 1", n)
	}
}

func doLogin(t *testing.T, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/auth/login", apiLocalAuthLogin)
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestLoginDBUsersRolesAndDisabled(t *testing.T) {
	setupUsersTestDB(t)
	mustCreateUser(t, "alice", "correct-horse", "admin")
	mustCreateUser(t, "bob", "viewer-pass-1", "viewer")

	// Correct admin creds → 200 with role=admin and a role claim in the token.
	w := doLogin(t, "alice", "correct-horse")
	if w.Code != http.StatusOK {
		t.Fatalf("admin login: status = %d, body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
		Role  string `json:"role"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Role != "admin" {
		t.Errorf("login role = %q, want admin", resp.Role)
	}
	sub, role, err := verifyLocalJWTClaims(resp.Token)
	if err != nil || sub != "alice" || role != "admin" {
		t.Errorf("verifyLocalJWTClaims = (%q,%q,%v), want (alice,admin,nil)", sub, role, err)
	}

	// Viewer login → role=viewer.
	w = doLogin(t, "bob", "viewer-pass-1")
	if w.Code != http.StatusOK {
		t.Fatalf("viewer login: status = %d", w.Code)
	}

	// Wrong password → 401.
	if w := doLogin(t, "alice", "nope"); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong password: status = %d, want 401", w.Code)
	}

	// Disabled user cannot log in even with the right password.
	u, _ := db.GetUserByUsername("bob")
	if err := db.SetUserDisabled(u.ID, true); err != nil {
		t.Fatalf("SetUserDisabled: %v", err)
	}
	if w := doLogin(t, "bob", "viewer-pass-1"); w.Code != http.StatusUnauthorized {
		t.Errorf("disabled user login: status = %d, want 401", w.Code)
	}
}

func TestDisabledUserTokenRejectedMidSession(t *testing.T) {
	setupUsersTestDB(t)
	id := mustCreateUser(t, "carol", "carol-pass-1", "admin")
	tok, err := issueLocalJWTWithRole("carol", "admin")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, _, err := verifyLocalJWTClaims(tok); err != nil {
		t.Fatalf("token should be valid before disable: %v", err)
	}
	// Need another admin so disabling carol isn't blocked at the handler layer;
	// here we disable directly to prove verify rejects an already-issued token.
	if err := db.SetUserDisabled(id, true); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, _, err := verifyLocalJWTClaims(tok); err == nil {
		t.Error("verifyLocalJWTClaims accepted a token for a disabled user")
	}
}

// buildAuthEngine mirrors the real wiring: auth middleware on the /api group,
// requireAdmin on /api/users, and a couple of dummy data routes to exercise the
// viewer read-only contract.
func buildAuthEngine() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	auth := supabaseJWTAuth()
	r.POST("/api/auth/change-password", auth, apiAuthChangePassword)
	apiGroup := r.Group("/api")
	apiGroup.Use(auth)
	{
		users := apiGroup.Group("/users")
		users.Use(requireAdmin())
		{
			users.GET("", apiListUsers)
			users.POST("", apiCreateUser)
			users.PUT("/:id", apiUpdateUser)
			users.DELETE("/:id", apiDeleteUser)
		}
		apiGroup.GET("/ping", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
		apiGroup.POST("/ping", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
	}
	return r
}

func req(t *testing.T, r *gin.Engine, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	rq := httptest.NewRequest(method, path, rdr)
	if token != "" {
		rq.Header.Set("Authorization", "Bearer "+token)
	}
	rq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, rq)
	return w
}

func TestViewerReadOnlyAndAdminGate(t *testing.T) {
	setupUsersTestDB(t)
	mustCreateUser(t, "adm", "adm-pass-12", "admin")
	mustCreateUser(t, "vwr", "vwr-pass-12", "viewer")
	adminTok, _ := issueLocalJWTWithRole("adm", "admin")
	viewerTok, _ := issueLocalJWTWithRole("vwr", "viewer")

	r := buildAuthEngine()

	// Viewer can read.
	if w := req(t, r, http.MethodGet, "/api/ping", viewerTok, nil); w.Code != 200 {
		t.Errorf("viewer GET /api/ping = %d, want 200", w.Code)
	}
	// Viewer cannot mutate (read-only enforcement in the auth middleware).
	if w := req(t, r, http.MethodPost, "/api/ping", viewerTok, map[string]string{}); w.Code != http.StatusForbidden {
		t.Errorf("viewer POST /api/ping = %d, want 403", w.Code)
	}
	// Viewer cannot list users (admin-gated), even though it's a GET.
	if w := req(t, r, http.MethodGet, "/api/users", viewerTok, nil); w.Code != http.StatusForbidden {
		t.Errorf("viewer GET /api/users = %d, want 403", w.Code)
	}
	// Admin can mutate and manage users.
	if w := req(t, r, http.MethodPost, "/api/ping", adminTok, map[string]string{}); w.Code != 200 {
		t.Errorf("admin POST /api/ping = %d, want 200", w.Code)
	}
	if w := req(t, r, http.MethodGet, "/api/users", adminTok, nil); w.Code != 200 {
		t.Errorf("admin GET /api/users = %d, want 200", w.Code)
	}
	// Missing token → 401.
	if w := req(t, r, http.MethodGet, "/api/ping", "", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("no token GET /api/ping = %d, want 401", w.Code)
	}
}

func TestViewerCanChangeOwnPassword(t *testing.T) {
	setupUsersTestDB(t)
	mustCreateUser(t, "adm", "adm-pass-12", "admin") // so viewer isn't the only user
	mustCreateUser(t, "vwr", "old-pass-123", "viewer")
	viewerTok, _ := issueLocalJWTWithRole("vwr", "viewer")
	r := buildAuthEngine()

	// change-password is allowlisted for viewers despite being a POST.
	w := req(t, r, http.MethodPost, "/api/auth/change-password", viewerTok,
		map[string]string{"old_password": "old-pass-123", "new_password": "new-pass-456"})
	if w.Code != 200 {
		t.Fatalf("viewer change-password = %d, body=%s", w.Code, w.Body.String())
	}
	u, _ := db.GetUserByUsername("vwr")
	if !checkPassword(u.PasswordHash, "new-pass-456") {
		t.Error("password was not updated")
	}
	// Wrong old password → 401.
	w = req(t, r, http.MethodPost, "/api/auth/change-password", viewerTok,
		map[string]string{"old_password": "totally-wrong", "new_password": "another-pass-1"})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("change-password wrong old = %d, want 401", w.Code)
	}
}

func TestLastAdminGuards(t *testing.T) {
	setupUsersTestDB(t)
	adminID := mustCreateUser(t, "solo", "solo-pass-12", "admin")
	adminTok, _ := issueLocalJWTWithRole("solo", "admin")
	r := buildAuthEngine()

	// Cannot demote the last admin.
	if w := req(t, r, http.MethodPut, "/api/users/"+itoa(adminID), adminTok, map[string]string{"role": "viewer"}); w.Code != http.StatusBadRequest {
		t.Errorf("demote last admin = %d, want 400", w.Code)
	}
	// Cannot disable the last admin.
	if w := req(t, r, http.MethodPut, "/api/users/"+itoa(adminID), adminTok, map[string]bool{"disabled": true}); w.Code != http.StatusBadRequest {
		t.Errorf("disable last admin = %d, want 400", w.Code)
	}
	// Cannot delete the last admin.
	if w := req(t, r, http.MethodDelete, "/api/users/"+itoa(adminID), adminTok, nil); w.Code != http.StatusBadRequest {
		t.Errorf("delete last admin = %d, want 400", w.Code)
	}

	// Add a second admin, then demoting the first is allowed.
	mustCreateUser(t, "second", "second-pass-1", "admin")
	if w := req(t, r, http.MethodPut, "/api/users/"+itoa(adminID), adminTok, map[string]string{"role": "viewer"}); w.Code != 200 {
		t.Errorf("demote with a spare admin = %d, want 200, body=%s", w.Code, w.Body.String())
	}
}

func TestCreateUserValidation(t *testing.T) {
	setupUsersTestDB(t)
	mustCreateUser(t, "adm", "adm-pass-12", "admin")
	adminTok, _ := issueLocalJWTWithRole("adm", "admin")
	r := buildAuthEngine()

	// Short password rejected.
	if w := req(t, r, http.MethodPost, "/api/users", adminTok, map[string]string{"username": "x", "password": "short", "role": "viewer"}); w.Code != http.StatusBadRequest {
		t.Errorf("short password = %d, want 400", w.Code)
	}
	// Bad role rejected.
	if w := req(t, r, http.MethodPost, "/api/users", adminTok, map[string]string{"username": "x", "password": "long-enough-1", "role": "superuser"}); w.Code != http.StatusBadRequest {
		t.Errorf("bad role = %d, want 400", w.Code)
	}
	// Valid create → 201.
	if w := req(t, r, http.MethodPost, "/api/users", adminTok, map[string]string{"username": "newbie", "password": "long-enough-1", "role": "viewer"}); w.Code != http.StatusCreated {
		t.Fatalf("valid create = %d, body=%s", w.Code, w.Body.String())
	}
	// Duplicate username → 409.
	if w := req(t, r, http.MethodPost, "/api/users", adminTok, map[string]string{"username": "newbie", "password": "long-enough-1", "role": "viewer"}); w.Code != http.StatusConflict {
		t.Errorf("duplicate username = %d, want 409", w.Code)
	}
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }
