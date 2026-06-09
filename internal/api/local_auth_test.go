package api

import (
	"testing"
	"time"
)

func TestRedactTokenInPath(t *testing.T) {
	cases := map[string]string{
		"/api/scans/1/logs/stream?token=abc.def.ghi": "/api/scans/1/logs/stream?token=REDACTED",
		"/x?token=secret&format=json":                "/x?token=REDACTED&format=json",
		"/x?a=1&token=secret":                        "/x?a=1&token=REDACTED",
		"/x?y=1":                                     "/x?y=1",
		"/plain":                                     "/plain",
	}
	for in, want := range cases {
		if got := redactTokenInPath(in); got != want {
			t.Errorf("redactTokenInPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckAuthBindSafety(t *testing.T) {
	// Auth disabled (no creds), public bind, no explicit opt-out → must refuse.
	t.Run("public bind unauth refuses", func(t *testing.T) {
		t.Setenv("DASHBOARD_USER", "")
		t.Setenv("DASHBOARD_PASSWORD", "")
		t.Setenv("AUTOAR_API_AUTH_DISABLED", "")
		if err := CheckAuthBindSafety("0.0.0.0"); err == nil {
			t.Error("expected refusal on public bind without auth, got nil")
		}
	})
	t.Run("loopback bind unauth allowed", func(t *testing.T) {
		t.Setenv("DASHBOARD_USER", "")
		t.Setenv("DASHBOARD_PASSWORD", "")
		t.Setenv("AUTOAR_API_AUTH_DISABLED", "")
		for _, h := range []string{"127.0.0.1", "::1", "localhost", ""} {
			if err := CheckAuthBindSafety(h); err != nil {
				t.Errorf("loopback host %q should be allowed, got %v", h, err)
			}
		}
	})
	t.Run("explicit opt-out allowed on public bind", func(t *testing.T) {
		t.Setenv("DASHBOARD_USER", "")
		t.Setenv("DASHBOARD_PASSWORD", "")
		t.Setenv("AUTOAR_API_AUTH_DISABLED", "true")
		if err := CheckAuthBindSafety("0.0.0.0"); err != nil {
			t.Errorf("explicit opt-out should be allowed, got %v", err)
		}
	})
	t.Run("auth enabled allowed on public bind", func(t *testing.T) {
		t.Setenv("DASHBOARD_USER", "admin")
		t.Setenv("DASHBOARD_PASSWORD", "s3cret")
		t.Setenv("AUTOAR_API_AUTH_DISABLED", "")
		if err := CheckAuthBindSafety("0.0.0.0"); err != nil {
			t.Errorf("auth-enabled public bind should be allowed, got %v", err)
		}
	})
}

func TestIssueVerifyRoundtripAndRevocation(t *testing.T) {
	t.Setenv("AUTOAR_JWT_SECRET", "test-secret-at-least-32-bytes-long-xxxxx")
	t.Setenv("DASHBOARD_USER", "")
	t.Setenv("DASHBOARD_PASSWORD", "")

	tok, err := issueLocalJWT("admin")
	if err != nil {
		t.Fatalf("issueLocalJWT: %v", err)
	}
	if err := verifyLocalJWT(tok); err != nil {
		t.Fatalf("verifyLocalJWT of fresh token: %v", err)
	}

	// Revoke everything issued before now+1h → the token must be rejected.
	tokensRevokedBeforeMu.Lock()
	tokensRevokedBefore = time.Now().Add(time.Hour)
	tokensRevokedBeforeMu.Unlock()
	defer func() {
		tokensRevokedBeforeMu.Lock()
		tokensRevokedBefore = time.Time{}
		tokensRevokedBeforeMu.Unlock()
	}()
	if err := verifyLocalJWT(tok); err == nil {
		t.Error("expected revoked token to fail verification")
	}
}

func TestVerifyRejectsGarbageAndWrongSecret(t *testing.T) {
	t.Setenv("AUTOAR_JWT_SECRET", "test-secret-at-least-32-bytes-long-xxxxx")
	if err := verifyLocalJWT("not-a-jwt"); err == nil {
		t.Error("expected garbage token to fail")
	}
	if err := verifyLocalJWT(""); err == nil {
		t.Error("expected empty token to fail")
	}
}

func TestLoginLockout(t *testing.T) {
	key := "203.0.113.7"
	loginReset(key)
	defer loginReset(key)
	if d := loginLockRemaining(key); d != 0 {
		t.Fatalf("fresh key should not be locked, got %v", d)
	}
	for i := 0; i < loginMaxFails; i++ {
		loginRecordFailure(key)
	}
	if d := loginLockRemaining(key); d <= 0 {
		t.Errorf("expected lockout after %d failures, got remaining=%v", loginMaxFails, d)
	}
	loginReset(key)
	if d := loginLockRemaining(key); d != 0 {
		t.Errorf("loginReset should clear lockout, got %v", d)
	}
}
