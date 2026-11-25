package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// dashboardAPIAuthEnforced returns true when authentication is in effect: either
// DB users exist, the legacy DASHBOARD_USER/DASHBOARD_PASSWORD pair is set, or the
// users table can't be read (fail closed). Set AUTOAR_API_AUTH_DISABLED=true to
// bypass auth entirely for development.
func dashboardAPIAuthEnforced() bool {
	if v := strings.TrimSpace(utils.GetEnv("AUTOAR_API_AUTH_DISABLED", "")); v != "" {
		if strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes") {
			return false
		}
	}
	return authConfigured()
}

// queryTokenPaths are the only routes that accept the session token as a
// ?token= query parameter (EventSource and plain download links can't set an
// Authorization header), and only for GET. Everywhere else a token in the URL
// is ignored, so it can't leak via links, Referer or proxy logs.
var queryTokenPaths = map[string]bool{
	"/api/scans/:id/logs/stream":      true,
	"/api/scans/:id/results/download": true,
	"/scan/:scan_id/download":         true,
}

func queryTokenAllowed(c *gin.Context) bool {
	return c.Request.Method == http.MethodGet && queryTokenPaths[c.FullPath()]
}

// supabaseJWTAuth is the auth middleware (name kept for api.go wiring). It now
// validates local HS256 tokens, resolves the user's role, and enforces the
// read-only contract for every non-admin role across the whole authenticated
// surface. The enforced/disabled decision is made per-request so seeding the
// first user (or setting the env pair) activates auth without a restart.
func supabaseJWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !dashboardAPIAuthEnforced() {
			// No auth configured (or explicitly disabled): open access, treated as
			// admin so role gates and the read-only check are no-ops.
			c.Set("auth_role", roleAdmin)
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
		} else if queryTokenAllowed(c) {
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

		// Allowlist: only the exact "admin" role may mutate. Every other role
		// Members (the renamed viewer role) are read-only, except for the
		// handful of self-service endpoints (logout, change own password).
		if role != roleAdmin && role != roleMember {
			role = roleMember // unknown/mis-cased legacy values degrade to member
		}
		if role != roleAdmin && isMutatingMethod(c.Request.Method) && !viewerSelfServicePath(c.FullPath()) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "read-only: the member role cannot modify data"})
			return
		}
		// Members never see the Bug Bounty surface (programs, scope, CVEs,
		// findings, port surface) — the tabs are hidden in the UI and the
		// APIs refuse regardless of method, so deep links and direct calls
		// cannot leak it.
		if role != roleAdmin && memberBlockedPath(c.FullPath()) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "not available to the member role"})
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

// memberBlockedPath reports whether an authenticated route belongs to the
// Bug Bounty surface that members cannot access at all.
func memberBlockedPath(fullPath string) bool {
	if fullPath == "" {
		return false
	}
	switch {
	case strings.HasPrefix(fullPath, "/api/scope"),
		strings.HasPrefix(fullPath, "/api/programs"),
		strings.HasPrefix(fullPath, "/api/cves"),
		strings.HasPrefix(fullPath, "/api/findings"),
		strings.HasPrefix(fullPath, "/api/ports"),
		strings.HasPrefix(fullPath, "/api/chaos"),
		strings.HasPrefix(fullPath, "/api/digest"),
		strings.HasPrefix(fullPath, "/api/subdomains/discovered"),
		strings.HasPrefix(fullPath, "/api/triage"),
		strings.HasPrefix(fullPath, "/api/ai/agent"):
		return true
	}
	return false
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

// requireAdmin gates a route to admin users: only the exact "admin" role passes
// (allowlist — an empty or unknown role is refused). When auth is not enforced
// supabaseJWTAuth sets the role to "admin", so dev/no-auth mode is unaffected.
func requireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetString("auth_role") != roleAdmin {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "admin role required"})
			return
		}
		c.Next()
	}
}
