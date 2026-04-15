package gobot

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// localAuthJWTSecret returns the HS256 signing secret for local JWTs.
// Uses AUTOAR_JWT_SECRET; falls back to DASHBOARD_PASSWORD so a single
// credential env-var is sufficient for simple setups.
func localAuthJWTSecret() []byte {
	if s := strings.TrimSpace(os.Getenv("AUTOAR_JWT_SECRET")); s != "" {
		return []byte(s)
	}
	// Fallback — combined so it's hard to brute-force even with known password.
	pw := strings.TrimSpace(os.Getenv("DASHBOARD_PASSWORD"))
	if pw != "" {
		return []byte("autoar-local-auth-" + pw)
	}
	return []byte("autoar-local-auth-insecure-default")
}

// localAuthEnabled returns true when DASHBOARD_USER and DASHBOARD_PASSWORD are set.
func localAuthEnabled() bool {
	user := strings.TrimSpace(os.Getenv("DASHBOARD_USER"))
	pass := strings.TrimSpace(os.Getenv("DASHBOARD_PASSWORD"))
	return user != "" && pass != ""
}

// issueLocalJWT creates a signed HS256 JWT for the given username.
// Tokens expire after 24 hours.
func issueLocalJWT(username string) (string, error) {
	claims := jwt.MapClaims{
		"sub": username,
		"iss": "autoar-local",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(localAuthJWTSecret())
}

// verifyLocalJWT validates a signed HS256 JWT produced by issueLocalJWT.
func verifyLocalJWT(raw string) error {
	secret := localAuthJWTSecret()
	_, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	return err
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

	if body.Username != expectedUser || body.Password != expectedPass {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	tok, err := issueLocalJWT(body.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not issue token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": tok, "expires_in": 86400})
}
