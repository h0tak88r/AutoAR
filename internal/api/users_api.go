package api

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/db"
)

// User management + self-service auth endpoints. The user-CRUD routes are mounted
// under requireAdmin(); /api/auth/me and /api/auth/change-password are available
// to any authenticated user (viewers included — change-password is allowlisted in
// the viewer read-only check).

func validRole(role string) bool {
	return role == roleAdmin || role == roleMember || role == roleViewer
}

// usernamePattern restricts new usernames to a charset that is inert in HTML,
// JS strings and log lines.
var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

func parseUserID(s string) int64 {
	id, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || id <= 0 {
		return 0
	}
	return id
}

// GET /api/users — list all users (admin only). Password hashes are never
// serialized (json:"-" on the field).
func apiListUsers(c *gin.Context) {
	users, err := db.ListUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not list users"})
		return
	}
	if users == nil {
		users = []db.User{}
	}
	c.JSON(http.StatusOK, gin.H{"users": users})
}

// createUserResponse is the created user plus whether its role was forced to
// admin (the first admin can't be a viewer — that would leave zero admins).
type createUserResponse struct {
	*db.User
	RoleForced bool `json:"role_forced,omitempty"`
}

// POST /api/users — create a user (admin only). Body: {username, password, role}.
// When no enabled admin exists yet the new user is made an admin regardless of
// the requested role. In legacy env-login mode the DASHBOARD_USER admin is first
// migrated into the users table, so turning on DB-users mode never locks it out.
func apiCreateUser(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	body.Role = strings.ToLower(strings.TrimSpace(body.Role))
	if body.Role == "" {
		body.Role = roleMember
	}
	if body.Username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
		return
	}
	if !usernamePattern.MatchString(body.Username) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username must be 1-64 characters: letters, digits, '.', '_', '@' or '-'"})
		return
	}
	if !validRole(body.Role) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role must be 'admin' or 'member'"})
		return
	}
	if msg := passwordPolicyError(body.Password); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}
	hash, err := hashPassword(body.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not hash password"})
		return
	}

	usersMu.Lock()
	defer usersMu.Unlock()

	// Legacy env-login mode: migrate the env admin first. Without this the new
	// user would switch the deployment to DB-users mode with no row for
	// DASHBOARD_USER, locking the env admin out.
	if !usersExistLatch.Load() && localAuthEnabled() {
		if _, err := seedEnvAdminIfEmptyLocked(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "user database unavailable — try again shortly"})
			return
		}
		if !usersExistLatch.Load() {
			c.JSON(http.StatusConflict, gin.H{"error": "the DASHBOARD_USER admin could not be migrated into the users table (see the server log — e.g. a DASHBOARD_PASSWORD longer than 72 bytes); fix that before adding users"})
			return
		}
	}

	if existing, _ := db.GetUserByUsername(body.Username); existing != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "a user with that username already exists"})
		return
	}
	admins, err := db.CountAdmins()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not count admins"})
		return
	}
	forced := false
	if admins == 0 && body.Role != roleAdmin {
		body.Role = roleAdmin
		forced = true
	}
	id, err := db.CreateUser(body.Username, hash, body.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create user"})
		return
	}
	// A re-created username must not inherit the sessions of a deleted namesake.
	_ = revokeUserSessions(id)
	markUsersExist()
	detail := "role=" + body.Role
	if forced {
		detail += " (forced: no other admin)"
	}
	audit(c, "user.create", body.Username, detail)
	u, _ := db.GetUserByID(id)
	c.JSON(http.StatusCreated, createUserResponse{User: u, RoleForced: forced})
}

// PUT /api/users/:id — update role, disabled flag, and/or reset password (admin
// only). Any field is optional; only provided fields change. Everything is
// validated before anything is written, and any change ends the target's
// existing sessions.
func apiUpdateUser(c *gin.Context) {
	id := parseUserID(c.Param("id"))
	if id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}
	var body struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
		Password *string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	newRole := ""
	if body.Role != nil {
		newRole = strings.ToLower(strings.TrimSpace(*body.Role))
		if !validRole(newRole) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "role must be 'admin' or 'member'"})
			return
		}
	}
	newHash := ""
	if body.Password != nil {
		if msg := passwordPolicyError(*body.Password); msg != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": msg})
			return
		}
		h, err := hashPassword(*body.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not hash password"})
			return
		}
		newHash = h
	}

	// Serialize the last-admin check with the write so two concurrent demotes
	// can't both pass it.
	usersMu.Lock()
	defer usersMu.Unlock()

	u, err := db.GetUserByID(id)
	if err != nil || u == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	roleChange := body.Role != nil && newRole != u.Role
	disabledChange := body.Disabled != nil && *body.Disabled != u.Disabled

	// Guard against locking everyone out: never demote or disable the final
	// enabled admin.
	if u.Role == roleAdmin && !u.Disabled && ((roleChange && newRole != roleAdmin) || (disabledChange && *body.Disabled)) {
		n, err := db.CountAdmins()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not count admins"})
			return
		}
		if n <= 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cannot remove the last admin — create or promote another admin first"})
			return
		}
	}

	if !roleChange && !disabledChange && body.Password == nil {
		c.JSON(http.StatusOK, u)
		return
	}
	// End the target's sessions before changing anything (fail-safe: if a later
	// write fails, the user merely has to sign in again).
	if err := revokeUserSessions(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not revoke the user's sessions"})
		return
	}
	var changes []string
	if roleChange {
		if err := db.UpdateUserRole(id, newRole); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not update role"})
			return
		}
		changes = append(changes, "role "+u.Role+"→"+newRole)
	}
	if disabledChange {
		if err := db.SetUserDisabled(id, *body.Disabled); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not update status"})
			return
		}
		if *body.Disabled {
			changes = append(changes, "disabled")
		} else {
			changes = append(changes, "enabled")
		}
	}
	if body.Password != nil {
		if err := db.UpdateUserPassword(id, newHash); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not update password"})
			return
		}
		changes = append(changes, "password reset")
	}
	audit(c, "user.update", u.Username, strings.Join(changes, ", ")+"; sessions ended")
	nu, _ := db.GetUserByID(id)
	c.JSON(http.StatusOK, nu)
}

// DELETE /api/users/:id — remove a user (admin only). Blocks deleting the last
// enabled admin.
func apiDeleteUser(c *gin.Context) {
	id := parseUserID(c.Param("id"))
	if id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}
	usersMu.Lock()
	defer usersMu.Unlock()
	u, err := db.GetUserByID(id)
	if err != nil || u == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if u.Role == roleAdmin && !u.Disabled {
		n, err := db.CountAdmins()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not count admins"})
			return
		}
		if n <= 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cannot delete the last admin"})
			return
		}
	}
	if err := db.DeleteUser(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not delete user"})
		return
	}
	audit(c, "user.delete", u.Username, "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// GET /api/auth/me — the current session's identity, so the SPA can show the
// username and gate the admin-only UI. In no-auth mode the caller is treated as
// an admin (the middleware sets the role).
func apiAuthMe(c *gin.Context) {
	role := c.GetString("auth_role")
	c.JSON(http.StatusOK, gin.H{
		"username":      c.GetString("auth_sub"),
		"role":          role,
		"is_admin":      role == roleAdmin,
		"auth_enforced": dashboardAPIAuthEnforced(),
	})
}

// POST /api/auth/change-password — change your own password. Body:
// {old_password, new_password}. Available to any authenticated user. Wrong
// current passwords are throttled per user (same backoff as login), every
// attempt is audited, and success ends all of the user's sessions — the
// response carries a fresh token so the caller stays signed in.
func apiAuthChangePassword(c *gin.Context) {
	if !dashboardAPIAuthEnforced() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "authentication is not enabled"})
		return
	}
	if !usersExist() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password change requires DB-backed users; set them up in Settings ▸ Users"})
		return
	}
	sub := strings.TrimSpace(c.GetString("auth_sub"))
	if sub == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxLoginBodyBytes)
	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	lockKey := "chpw\x00" + strings.ToLower(sub)
	if d := loginLockRemaining(lockKey); d > 0 {
		tooManyAttempts(c, d)
		return
	}
	if msg := passwordPolicyError(body.NewPassword); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "new " + msg})
		return
	}
	u, err := db.GetUserByUsername(sub)
	if err != nil || u == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if !checkPassword(u.PasswordHash, body.OldPassword) {
		loginRecordFailure(lockKey)
		audit(c, "auth.change_password_failed", u.Username, "wrong current password")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "current password is incorrect"})
		return
	}
	loginReset(lockKey)
	hash, err := hashPassword(body.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not hash password"})
		return
	}
	// Revoke first (fail-safe), then write the new hash.
	if err := revokeUserSessions(u.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not revoke sessions"})
		return
	}
	if err := db.UpdateUserPassword(u.ID, hash); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not update password"})
		return
	}
	audit(c, "auth.change_password", u.Username, "sessions ended")
	tok, err := issueLocalJWT(u.Username, u.Role, tokenModeDB)
	if err != nil {
		// Password changed, but the caller must sign in again.
		c.JSON(http.StatusOK, gin.H{"ok": true})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "token": tok, "expires_in": 86400, "role": u.Role})
}
