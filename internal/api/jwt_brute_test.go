package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func makeHS256Token(secret string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	p := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1234567890","name":"test"}`))
	signingInput := h + "." + p
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig
}

func postJWTBrute(t *testing.T, body string) map[string]any {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/jwt/brute", apiJWTBrute)
	req := httptest.NewRequest(http.MethodPost, "/jwt/brute", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad json: %v (%s)", err, w.Body.String())
	}
	return resp
}

func TestJWTBruteCracksBundledSecret(t *testing.T) {
	resp := postJWTBrute(t, `{"token":"`+makeHS256Token("secret")+`"}`)
	if resp["found"] != true || resp["secret"] != "secret" {
		t.Fatalf("expected to crack bundled secret 'secret', got %v", resp)
	}
}

func TestJWTBruteCracksCustomSecret(t *testing.T) {
	tok := makeHS256Token("zzz-not-in-default-list-xyz")
	resp := postJWTBrute(t, `{"token":"`+tok+`","use_default":false,"secrets":"foo\nzzz-not-in-default-list-xyz\nbar"}`)
	if resp["found"] != true || resp["secret"] != "zzz-not-in-default-list-xyz" {
		t.Fatalf("expected to crack custom secret, got %v", resp)
	}
}

func TestJWTBruteRejectsNonHMAC(t *testing.T) {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	p := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1"}`))
	tok := h + "." + p + "." + base64.RawURLEncoding.EncodeToString([]byte("sig"))
	resp := postJWTBrute(t, `{"token":"`+tok+`"}`)
	if resp["found"] != false {
		t.Fatalf("expected found=false for RS256, got %v", resp)
	}
	if _, ok := resp["error"]; !ok {
		t.Fatalf("expected an error message for RS256, got %v", resp)
	}
}

func TestJWTBruteNotFound(t *testing.T) {
	tok := makeHS256Token("this-secret-is-definitely-not-in-any-list-9f8a7b6c5d")
	resp := postJWTBrute(t, `{"token":"`+tok+`"}`)
	if resp["found"] != false {
		t.Fatalf("expected found=false for a strong secret, got %v", resp)
	}
}
