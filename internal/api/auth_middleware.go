package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// dashboardAPIAuthEnforced returns true when authentication is in effect: either
// DB users exist or the legacy DASHBOARD_USER/DASHBOARD_PASSWORD pair is set.
// Set AUTOAR_API_AUTH_DISABLED=true to bypass auth entirely for development.
func dashboardAPIAuthEnforced() bool {
	if v := strings.TrimSpace(utils.GetEnv("AUTOAR_API_AUTH_DISABLED", "")); v != "" {
		if strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes") {
			return false
		}
	}
	return authConfigured()
}

// supabaseJWTAuth is the auth middleware (name kept for api.go wiring). It now
// validates local HS256 tokens, resolves the user's role, and enforces the
// read-only contract for the "viewer" role across the whole authenticated
// surface. The enforced/disabled decision is made per-request so seeding the
// first user (or setting the env pair) activates auth without a restart.
func supabaseJWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !dashboardAPIAuthEnforced() {
			// No auth configured (or explicitly disabled): open access, treated as
			// admin so role gates and the viewer read-only check are no-ops.
			c.Set("auth_role", "admin")
			c.Next()
			return
		}

		auth := strings.TrimSpace(c.GetHeader("Authorization"))
		var raw string
		if auth != "" {
			const p = "Bearer "
			if !strings.HasPrefix(auth, p) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization must be Bearer <token>"})
				return
			}
			raw = strings.TrimSpace(auth[len(p):])
		} else {
			raw = strings.TrimSpace(c.Query("token"))
		}

		if raw == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			return
		}

		sub, role, err := verifyLocalJWTClaims(raw)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}
		c.Set("auth_sub", sub)
		c.Set("auth_role", role)

		// Viewer role is read-only: reject mutating requests everywhere except the
		// handful of self-service endpoints (logout, change own password).
		if role == "viewer" && isMutatingMethod(c.Request.Method) && !viewerSelfServicePath(c.FullPath()) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "read-only: the viewer role cannot modify data"})
			return
		}

		c.Next()
	}
}

// isMutatingMethod reports whether an HTTP method changes state.
func isMutatingMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// viewerSelfServicePath lists the few mutating endpoints a read-only viewer may
// still call to manage their own session/account.
func viewerSelfServicePath(fullPath string) bool {
	switch fullPath {
	case "/api/auth/logout", "/api/auth/change-password":
		return true
	}
	return false
}

// requireAdmin gates a route group to admin users. When auth is not enforced the
// role is "admin" (set by supabaseJWTAuth), so dev/no-auth mode is unaffected.
func requireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		if role := c.GetString("auth_role"); role != "" && role != "admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "admin role required"})
			return
		}
		c.Next()
	}
}
