package gobot

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// dashboardAPIAuthEnforced returns true when DASHBOARD_USER + DASHBOARD_PASSWORD
// are set (local auth) OR when AUTOAR_API_AUTH_DISABLED is explicitly "false".
// Set AUTOAR_API_AUTH_DISABLED=true to bypass auth entirely for development.
func dashboardAPIAuthEnforced() bool {
	if v := strings.TrimSpace(getEnv("AUTOAR_API_AUTH_DISABLED", "")); v != "" {
		if strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes") {
			return false
		}
	}
	return localAuthEnabled()
}

// supabaseJWTAuth is kept as the name used in api.go for the auth middleware.
// It now validates local HS256 tokens (no Supabase dependency).
func supabaseJWTAuth() gin.HandlerFunc {
	if !dashboardAPIAuthEnforced() {
		return func(c *gin.Context) { c.Next() }
	}

	return func(c *gin.Context) {
		auth := strings.TrimSpace(c.GetHeader("Authorization"))
		if auth == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization bearer token"})
			return
		}
		const p = "Bearer "
		if !strings.HasPrefix(auth, p) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization must be Bearer <token>"})
			return
		}
		raw := strings.TrimSpace(auth[len(p):])
		if raw == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "empty bearer token"})
			return
		}

		if err := verifyLocalJWT(raw); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		// Extract sub claim and store for downstream handlers.
		parser := jwt.NewParser()
		tok, _, err := parser.ParseUnverified(raw, jwt.MapClaims{})
		if err == nil && tok != nil {
			if claims, ok := tok.Claims.(jwt.MapClaims); ok {
				if sub, _ := claims["sub"].(string); sub != "" {
					c.Set("auth_sub", sub)
				}
			}
		}

		c.Next()
	}
}
