package accounts

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// fakeBC replaces the Bugcrowd check and sign-in: sessions in good are valid.
type fakeBC struct {
	mu      sync.Mutex
	good    map[string]bool
	blocked bool
	logins  int
	fail    error
	next    string
}

func (f *fakeBC) install(t *testing.T) {
	t.Helper()
	oC, oL := bcCheck, bcLogin
	bcCheck = func(tok string) (string, string) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.blocked {
			return "blocked", "WAF"
		}
		if f.good[tok] {
			return "valid", "ok"
		}
		return "invalid", "expired"
	}
	bcLogin = func(email, password, secret string) (string, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.logins++
		if f.fail != nil {
			return "", f.fail
		}
		f.good[f.next] = true
		return f.next, nil
	}
	bcMu.Lock()
	bcLocks, bcValid, bcAttempts = map[string]*sync.Mutex{}, map[string]time.Time{}, map[string]bcAttempt{}
	bcMu.Unlock()
	t.Cleanup(func() { bcCheck, bcLogin = oC, oL })
}

func bcAccount(t *testing.T, token, email, password string) Account {
	t.Helper()
	id, err := db.UpsertBBPAccount(db.BBPAccount{Platform: "bc", Label: "main", Token: token, Email: email, Password: password,
		TOTPSecret: "GEZDGNBVGY3TQOJQ", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range For("bc") {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("account %d not usable: %+v", id, For("bc"))
	return Account{}
}

func storedToken(t *testing.T, id int64) string {
	t.Helper()
	rows, _ := db.ListBBPAccounts("bc")
	for _, r := range rows {
		if r.ID == id {
			return r.Token
		}
	}
	return ""
}

func TestBugcrowdSessionRenewsAndSaves(t *testing.T) {
	freshAccountsDB(t)
	f := &fakeBC{good: map[string]bool{}, next: "a=1; _bugcrowd_session=NEW"}
	f.install(t)
	pw := fixturePW("bc")

	// Email + password alone make a usable account (no session yet).
	a := bcAccount(t, "", "me@example.com", pw)
	tok, st, _ := BugcrowdSession(a, false)
	if st != "refreshed" || tok != f.next || f.logins != 1 || storedToken(t, a.ID) != f.next {
		t.Fatalf("first sign-in: %s %q logins=%d stored=%q", st, tok, f.logins, storedToken(t, a.ID))
	}
	// A caller still holding the old (empty) account gets the new session
	// without a second sign-in.
	if tok, st, _ := BugcrowdSession(a, false); st != "refreshed" || tok != f.next || f.logins != 1 {
		t.Fatalf("stale caller: %s %q logins=%d", st, tok, f.logins)
	}
	// The saved session is used while Bugcrowd accepts it, and not re-checked
	// for a while.
	a.Token = f.next
	checks := 0
	inner := bcCheck
	bcCheck = func(tok string) (string, string) { checks++; return inner(tok) }
	for range 3 {
		if tok, st, _ := BugcrowdSession(a, false); st != "valid" || tok != a.Token {
			t.Fatalf("valid session: %s", st)
		}
	}
	if checks != 0 || f.logins != 1 {
		t.Fatalf("checks=%d logins=%d", checks, f.logins)
	}
	if _, st, _ := BugcrowdSession(a, true); st != "valid" || checks != 1 {
		t.Fatalf("force re-checks: %s checks=%d", st, checks)
	}
	// Expired → sign in again.
	f.good[a.Token] = false
	bcMu.Lock()
	bcValid = map[string]time.Time{}
	at := bcAttempts[bcKey(a)]
	at.at = time.Now().Add(-time.Hour)
	bcAttempts[bcKey(a)] = at
	bcMu.Unlock()
	f.next = "_bugcrowd_session=NEWER"
	if tok, st, _ := BugcrowdSession(a, false); st != "refreshed" || tok != f.next || f.logins != 2 {
		t.Fatalf("renew: %s %q logins=%d", st, tok, f.logins)
	}
}

func TestBugcrowdSessionFailureBackoff(t *testing.T) {
	freshAccountsDB(t)
	f := &fakeBC{good: map[string]bool{}, fail: errors.New("password rejected: Password is incorrect"), next: "s=1"}
	f.install(t)
	a := bcAccount(t, "old-session", "me@example.com", fixturePW("bc"))
	if tok, st, d := BugcrowdSession(a, false); tok != "" || st != "invalid" || !strings.Contains(d, "Password is incorrect") || f.logins != 1 {
		t.Fatalf("failed sign-in: %q %s %s logins=%d", tok, st, d, f.logins)
	}
	// Not again within a minute, even forced.
	if _, _, d := BugcrowdSession(a, true); f.logins != 1 || !strings.Contains(d, "Password is incorrect") {
		t.Fatalf("retried within a minute: %d %s", f.logins, d)
	}
	// Later: the automatic paths back off; a forced Test retries.
	bcMu.Lock()
	at := bcAttempts[bcKey(a)]
	at.at = time.Now().Add(-10 * time.Minute)
	bcAttempts[bcKey(a)] = at
	bcMu.Unlock()
	if _, _, d := BugcrowdSession(a, false); f.logins != 1 || !strings.Contains(d, "press Test") {
		t.Fatalf("no back-off: logins=%d %s", f.logins, d)
	}
	f.fail = nil
	if _, st, _ := BugcrowdSession(a, true); st != "refreshed" || f.logins != 2 {
		t.Fatalf("forced retry: %s logins=%d", st, f.logins)
	}
	// New credentials are tried right away (no back-off from the old ones).
	f.fail = errors.New("2FA code rejected")
	bcMu.Lock()
	bcAttempts[bcKey(a)] = bcAttempt{at: time.Now().Add(-10 * time.Minute), creds: "old", err: f.fail}
	bcMu.Unlock()
	a.Token = "expired"
	a.Password = fixturePW("bc2")
	if _, _, _ = BugcrowdSession(a, false); f.logins != 3 {
		t.Fatalf("changed credentials not tried: logins=%d", f.logins)
	}
}

func TestBugcrowdSessionWithoutCredentials(t *testing.T) {
	freshAccountsDB(t)
	f := &fakeBC{good: map[string]bool{"good": true}}
	f.install(t)
	a := bcAccount(t, "stale", "", "")
	if tok, st, d := BugcrowdSession(a, false); tok != "" || st != "invalid" || !strings.Contains(d, "add the email") || f.logins != 0 {
		t.Fatalf("expired, no creds: %q %s %s", tok, st, d)
	}
	f.blocked = true
	if tok, st, _ := BugcrowdSession(a, false); tok != "stale" || st != "blocked" || f.logins != 0 {
		t.Fatalf("blocked check keeps the session: %q %s", tok, st)
	}
	if _, st, _ := BugcrowdSession(Account{Platform: "bc", Label: "x"}, false); st != "invalid" {
		t.Fatal("nothing to use")
	}
}
