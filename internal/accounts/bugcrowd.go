package accounts

// Bugcrowd sessions: a pasted session cookie expires, so an account can also
// carry email + password + TOTP secret, and AutoAR signs in again when the
// stored session stops working, saving the new one on the account.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/bugcrowd"
	"github.com/h0tak88r/AutoAR/internal/db"
)

// Seams for tests.
var (
	bcCheck = bugcrowd.CheckSession
	bcLogin = bugcrowd.Login
)

const (
	bcValidFor    = 15 * time.Minute // a session that just passed the check isn't re-checked
	bcRetryAfter  = time.Minute      // never two sign-ins for one account within this
	bcFailBackoff = 6 * time.Hour    // after a failed sign-in, wait this long (unless forced or the credentials change)
)

var (
	bcMu       sync.Mutex
	bcLocks    = map[string]*sync.Mutex{}
	bcValid    = map[string]time.Time{} // sha256(session) → last passed the check
	bcAttempts = map[string]bcAttempt{} // account → last sign-in
)

type bcAttempt struct {
	at    time.Time
	creds string // fingerprint of the credentials used
	token string // the session it produced, when it worked
	err   error
}

func bcHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func bcKey(a Account) string {
	if a.ID > 0 {
		return fmt.Sprintf("id:%d", a.ID)
	}
	return "label:" + a.Label
}

func bcLock(key string) *sync.Mutex {
	bcMu.Lock()
	defer bcMu.Unlock()
	if bcLocks[key] == nil {
		bcLocks[key] = &sync.Mutex{}
	}
	return bcLocks[key]
}

// BugcrowdSession returns a working Bugcrowd session for a — the stored one
// while Bugcrowd accepts it, else a fresh sign-in with the account's email +
// password + TOTP secret (saved on the account). Status:
//
//	valid     the stored session works
//	refreshed signed in again; token is the new session
//	invalid   no working session (detail says why)
//	blocked   Bugcrowd refused the check (WAF / rate limit); token is the stored one
//	error     the check failed (network); token is the stored one
//
// force (Settings ▸ Test) re-checks a recently checked session and retries a
// sign-in that failed recently; sign-ins stay at most one a minute.
func BugcrowdSession(a Account, force bool) (token, status, detail string) {
	canSignIn := a.Email != "" && a.Password != ""
	if a.Token != "" {
		bcMu.Lock()
		at, ok := bcValid[bcHash(a.Token)]
		bcMu.Unlock()
		if ok && !force && time.Since(at) < bcValidFor {
			return a.Token, "valid", "session checked recently"
		}
		switch st, d := bcCheck(a.Token); st {
		case "valid":
			bcMarkValid(a.Token)
			return a.Token, "valid", d
		case "blocked", "error":
			return a.Token, st, d
		}
		if !canSignIn {
			return "", "invalid", "session expired — add the email, password and 2FA secret to renew it automatically"
		}
	} else if !canSignIn {
		return "", "invalid", "no session cookie, and no email/password to sign in"
	}

	key := bcKey(a)
	l := bcLock(key)
	l.Lock()
	defer l.Unlock()
	creds := bcHash(a.Email + "\x00" + a.Password + "\x00" + a.TOTPSecret)
	bcMu.Lock()
	last, tried := bcAttempts[key]
	bcMu.Unlock()
	if tried && last.creds == creds {
		ago := time.Since(last.at)
		switch {
		case last.err == nil && last.token != "" && last.token != a.Token && ago < bcValidFor:
			return last.token, "refreshed", "signed in " + ago.Round(time.Second).String() + " ago"
		case ago < bcRetryAfter:
			if last.err != nil {
				return "", "invalid", "sign-in failed: " + last.err.Error()
			}
			return "", "invalid", "signed in less than a minute ago — try again shortly"
		case last.err != nil && !force && ago < bcFailBackoff:
			return "", "invalid", fmt.Sprintf("sign-in failed %s ago: %v — fix the credentials or press Test to retry", ago.Round(time.Minute), last.err)
		}
	}

	tok, err := bcLogin(a.Email, a.Password, a.TOTPSecret)
	bcMu.Lock()
	bcAttempts[key] = bcAttempt{at: time.Now(), creds: creds, token: tok, err: err}
	bcMu.Unlock()
	if err != nil {
		log.Printf("[accounts] Bugcrowd sign-in for %q failed: %v", a.Label, err)
		return "", "invalid", "sign-in failed: " + err.Error()
	}
	bcMarkValid(tok)
	if a.ID > 0 {
		if err := db.UpdateBBPAccountToken(a.ID, tok); err != nil {
			log.Printf("[accounts] could not save the new Bugcrowd session for %q (it signs in again next time): %v", a.Label, err)
		}
	}
	log.Printf("[accounts] Bugcrowd session for %q renewed", a.Label)
	return tok, "refreshed", "signed in with email, password and 2FA"
}

func bcMarkValid(token string) {
	bcMu.Lock()
	bcValid[bcHash(token)] = time.Now()
	bcMu.Unlock()
}

// FromDB is a stored account as an Account.
func FromDB(r db.BBPAccount) Account {
	return Account{ID: r.ID, Platform: Canonical(r.Platform), Label: r.Label, Username: r.Username,
		Token: r.Token, Email: r.Email, Password: r.Password, TOTPSecret: r.TOTPSecret, Source: "db"}
}
