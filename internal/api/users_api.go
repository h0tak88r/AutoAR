package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/db"
)

// User management + self-service auth endpoints. The user-CRUD routes are mounted
// under requireAdmin(); /api/auth/me and /api/auth/change-password are available
// to any authenticated user (viewers included — change-password is allowlisted in
// the viewer read-only check).

func validRole(role string) bool { return role == "admin" || role == "viewer" }

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

// POST /api/users — create a user (admin only). Body: {username, password, role}.
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
		body.Role = "viewer"
	}
	if body.Username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
		return
	}
	if !validRole(body.Role) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role must be 'admin' or 'viewer'"})
		return
	}
	if len(body.Password) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password must be at least 8 characters"})
		return
	}
	if existing, _ := db.GetUserByUsername(body.Username); existing != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "a user with that username already exists"})
		return
	}
	hash, err := hashPassword(body.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not hash password"})
		return
	}
	id, err := db.CreateUser(body.Username, hash, body.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create user"})
		return
	}
	markUsersExist()
	audit(c, "user.create", body.Username, "role="+body.Role)
	u, _ := db.GetUserByID(id)
	c.JSON(http.StatusCreated, u)
}

// PUT /api/users/:id — update role, disabled flag, and/or reset password (admin
// only). Any field is optional; only provided fields change.
func apiUpdateUser(c *gin.Context) {
	id := parseUserID(c.Param("id"))
	if id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}
	u, err := db.GetUserByID(id)
	if err != nil || u == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
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

	// Guard against locking everyone out: never demote or disable the final admin.
	demoting := body.Role != nil && strings.ToLower(strings.TrimSpace(*body.Role)) != "admin" && u.Role == "admin"
	disabling := body.Disabled != nil && *body.Disabled && u.Role == "admin" && !u.Disabled
	if demoting || disabling {
		if n, _ := db.CountAdmins(); n <= 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cannot remove the last admin — create or promote another admin first"})
			return
		}
	}

	if body.Role != nil {
		role := strings.ToLower(strings.TrimSpace(*body.Role))
		if !validRole(role) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "role must be 'admin' or 'viewer'"})
			return
		}
		if err := db.UpdateUserRole(id, role); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not update role"})
			return
		}
	}
	if body.Disabled != nil {
		if err := db.SetUserDisabled(id, *body.Disabled); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not update status"})
			return
		}
	}
	if body.Password != nil {
		if len(*body.Password) < 8 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "password must be at least 8 characters"})
			return
		}
		hash, herr := hashPassword(*body.Password)
		if herr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not hash password"})
			return
		}
		if err := db.UpdateUserPassword(id, hash); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not update password"})
			return
		}
	}
	audit(c, "user.update", u.Username, "")
	nu, _ := db.GetUserByID(id)
	c.JSON(http.StatusOK, nu)
}

// DELETE /api/users/:id — remove a user (admin only). Blocks deleting the last
// admin.
func apiDeleteUser(c *gin.Context) {
	id := parseUserID(c.Param("id"))
	if id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}
	u, err := db.GetUserByID(id)
	if err != nil || u == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if u.Role == "admin" && !u.Disabled {
		if n, _ := db.CountAdmins(); n <= 1 {
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
// an admin.
func apiAuthMe(c *gin.Context) {
	role := c.GetString("auth_role")
	c.JSON(http.StatusOK, gin.H{
		"username":      c.GetString("auth_sub"),
		"role":          role,
		"is_admin":      role == "" || role == "admin",
		"auth_enforced": dashboardAPIAuthEnforced(),
	})
}

// POST /api/auth/change-password — change your own password. Body:
// {old_password, new_password}. Available to any authenticated user.
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
	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	u, err := db.GetUserByUsername(sub)
	if err != nil || u == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if !checkPassword(u.PasswordHash, body.OldPassword) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "current password is incorrect"})
		return
	}
	if len(body.NewPassword) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "new password must be at least 8 characters"})
		return
	}
	hash, err := hashPassword(body.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not hash password"})
		return
	}
	if err := db.UpdateUserPassword(u.ID, hash); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not update password"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
