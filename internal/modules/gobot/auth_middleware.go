package gobot

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// supabaseJWTAuth verifies Supabase access tokens when SUPABASE_JWT_SECRET and/or SUPABASE_URL is set.
// Supports HS256 (legacy JWT secret) and RS256/ES256 via Supabase JWKS (new JWT signing keys).
// If neither is set, the middleware is a no-op (local dev without dashboard auth).
func supabaseJWTAuth() gin.HandlerFunc {
	secretSet := strings.TrimSpace(os.Getenv("SUPABASE_JWT_SECRET")) != ""
	urlSet := strings.TrimSpace(os.Getenv("SUPABASE_URL")) != ""
	if !secretSet && !urlSet {
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

		if err := verifySupabaseAccessToken(raw); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

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

func jwtSigningKeys() []byte {
	s := strings.TrimSpace(os.Getenv("SUPABASE_JWT_SECRET"))
	if s == "" {
		return nil
	}
	// Supabase often stores the legacy secret as standard base64.
	if dec, err := base64.StdEncoding.DecodeString(s); err == nil && len(dec) > 0 {
		return dec
	}
	return []byte(s)
}

var supabaseJWKS struct {
	k   keyfunc.Keyfunc
	err error
	once sync.Once
}

func getSupabaseJWKS() (keyfunc.Keyfunc, error) {
	supabaseJWKS.once.Do(func() {
		base := strings.TrimSuffix(strings.TrimSpace(os.Getenv("SUPABASE_URL")), "/")
		if base == "" {
			supabaseJWKS.err = fmt.Errorf("SUPABASE_URL is required for JWKS verification")
			return
		}
		u := base + "/auth/v1/.well-known/jwks.json"
		supabaseJWKS.k, supabaseJWKS.err = keyfunc.NewDefault([]string{u})
	})
	return supabaseJWKS.k, supabaseJWKS.err
}

func verifySupabaseAccessToken(raw string) error {
	secret := jwtSigningKeys()
	parser := jwt.NewParser()

	tok, _, err := parser.ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		return err
	}
	alg, _ := tok.Header["alg"].(string)

	switch alg {
	case jwt.SigningMethodHS256.Alg():
		if len(secret) == 0 {
			return fmt.Errorf("no jwt secret for HS256")
		}
		_, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return secret, nil
		}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
		if err != nil {
			// Retry with raw UTF-8 secret (not base64-decoded)
			rawSecret := []byte(strings.TrimSpace(os.Getenv("SUPABASE_JWT_SECRET")))
			_, err2 := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return rawSecret, nil
			}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
			return err2
		}
		return nil

	case jwt.SigningMethodRS256.Alg(), jwt.SigningMethodES256.Alg(), "RS256", "ES256":
		kf, err := getSupabaseJWKS()
		if err != nil {
			return err
		}
		_, err = jwt.Parse(raw, kf.Keyfunc)
		return err

	default:
		// Try JWKS first (unknown alg string), then HS256
		kf, kerr := getSupabaseJWKS()
		if kerr == nil && kf != nil {
			if _, err := jwt.Parse(raw, kf.Keyfunc); err == nil {
				return nil
			}
		}
		if len(secret) == 0 {
			return fmt.Errorf("unsupported alg %q", alg)
		}
		_, err2 := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return secret, nil
		}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
		return err2
	}
}
