package api

import (
	"context"
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

func jwtBruteStatus(body string) int {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/jwt/brute", apiJWTBrute)
	req := httptest.NewRequest(http.MethodPost, "/jwt/brute", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestJWTBruteBounds(t *testing.T) {
	// Oversized token: every candidate would HMAC megabytes.
	huge := makeHS256Token("x")
	huge = strings.Replace(huge, ".", "."+strings.Repeat("A", maxJWTTokenLen), 1)
	if code := jwtBruteStatus(`{"token":"` + huge + `"}`); code != http.StatusBadRequest {
		t.Fatalf("oversized token: status %d, want 400", code)
	}

	// One brute-force at a time.
	jwtBruteBusy.Store(true)
	code := jwtBruteStatus(`{"token":"` + makeHS256Token("secret") + `"}`)
	jwtBruteBusy.Store(false)
	if code != http.StatusTooManyRequests {
		t.Fatalf("concurrent request: status %d, want 429", code)
	}

	// The candidate cap is applied while parsing and keeps the empty secret.
	var b strings.Builder
	for i := 0; i < 50; i++ {
		b.WriteString("cand-" + strings.Repeat("z", i) + "\n")
	}
	got, truncated := buildJWTSecretCandidates(jwtBruteRequest{Secrets: b.String(), UseDefault: new(bool)}, 10)
	if len(got) != 10 || !truncated || got[0] != "" {
		t.Fatalf("buildJWTSecretCandidates cap: len=%d truncated=%v first=%q", len(got), truncated, got[0])
	}
}

func TestJWTBruteStopsOnCancelledContext(t *testing.T) {
	cands := make([]string, 50000)
	for i := range cands {
		cands[i] = "c" + strings.Repeat("x", i%64)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	found, _, tried := bruteForceJWTSecret(ctx, []byte("a.b"), []byte("nope"), sha256.New, cands)
	if found || tried > len(cands)/2 {
		t.Fatalf("cancelled brute-force kept hashing: found=%v tried=%d", found, tried)
	}
}
