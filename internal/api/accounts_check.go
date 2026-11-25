package api

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/accounts"
	"github.com/h0tak88r/AutoAR/internal/db"
)

// GET /api/accounts/:id/check[?force=1] — validate one stored account's
// credentials against its platform with a single lightweight authenticated
// request. Returns a status: valid | invalid | blocked | unsupported | error.
// A Bugcrowd account with email + password signs in again when its session
// has expired; force=1 (the Test button) retries a sign-in that failed lately.
func apiCheckBBPAccount(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	rows, err := db.ListBBPAccounts("") // all platforms
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var acct *db.BBPAccount
	for i := range rows {
		if rows[i].ID == id {
			acct = &rows[i]
			break
		}
	}
	if acct == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "account not found"})
		return
	}
	status, detail := checkAccountCredential(*acct, c.Query("force") == "1")
	// A Bugcrowd check may have signed in again and saved a new session.
	refreshed := false
	if accounts.Canonical(acct.Platform) == "bc" {
		if rows, err := db.ListBBPAccounts("bc"); err == nil {
			for _, r := range rows {
				refreshed = refreshed || (r.ID == id && r.Token != acct.Token)
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"id":        id,
		"platform":  acct.Platform,
		"status":    status,
		"detail":    detail,
		"valid":     status == "valid",
		"refreshed": refreshed,
	})
}

// checkAccountCredential makes one minimal authenticated call per platform and
// classifies the outcome. It never returns program data — only a status.
func checkAccountCredential(a db.BBPAccount, force bool) (status, detail string) {
	client := &http.Client{
		Timeout: 12 * time.Second,
		// Don't follow redirects: an expired Bugcrowd session 302s to the login
		// page, which would otherwise look like a 200 "success".
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	switch accounts.Canonical(a.Platform) {
	case "h1":
		if a.Username == "" || a.Token == "" {
			return "invalid", "missing username or token"
		}
		req, _ := http.NewRequest("GET", "https://api.hackerone.com/v1/hackers/programs?page%5Bsize%5D=1", nil)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(a.Username+":"+a.Token)))
		return interpretAPI(client.Do(req))

	case "it":
		if a.Token == "" {
			return "invalid", "missing API token"
		}
		req, _ := http.NewRequest("GET", "https://api.intigriti.com/external/researcher/v1/programs?limit=1", nil)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+a.Token)
		return interpretAPI(client.Do(req))

	case "ywh":
		// /user is auth-gated (401 without a valid JWT); the /programs list is public
		// so it can't distinguish a good token from a bad one.
		if a.Token != "" {
			req, _ := http.NewRequest("GET", "https://api.yeswehack.com/user", nil)
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Authorization", "Bearer "+a.Token)
			if status, detail := interpretAPI(client.Do(req)); status == "valid" {
				return status, detail
			}
		}
		// JWT missing/expired — try re-authenticating with the stored credentials
		// (email + password + optional 2FA). On success, persist the fresh JWT so the
		// tag goes green and future fetches reuse it.
		if a.Email != "" && a.Password != "" {
			jwt, rerr := ywhReauth(a.Email, a.Password, a.TOTPSecret)
			if rerr != nil {
				return "invalid", "re-auth failed: " + trimErr(rerr.Error())
			}
			if a.ID > 0 {
				if err := db.UpdateBBPAccountToken(a.ID, jwt); err != nil {
					log.Printf("[ERROR] failed to cache re-auth token for account %d (will re-auth next cycle): %v", a.ID, err)
				}
			}
			return "valid", "re-authenticated via email/password"
		}
		if a.Token == "" {
			return "invalid", "no token, and no email/password to re-auth"
		}
		return "invalid", "JWT expired — add email/password (+2FA) to auto-refresh"

	case "bc":
		// The session is checked against /dashboard (see bugcrowd.CheckSession);
		// an expired one is renewed from the email + password + 2FA secret.
		_, st, d := accounts.BugcrowdSession(accounts.FromDB(a), force)
		if st == "refreshed" {
			return "valid", d
		}
		return st, d

	default:
		return "unsupported", "no validity check for this platform"
	}
}

// interpretAPI classifies a JSON-API response: 200 = valid, 401/403 = bad creds.
func interpretAPI(resp *http.Response, err error) (string, string) {
	if err != nil {
		return "error", trimErr(err.Error())
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == 200:
		return "valid", "authenticated (200)"
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return "invalid", fmt.Sprintf("credential rejected (%d)", resp.StatusCode)
	case resp.StatusCode == 429:
		return "blocked", "rate limited (429) — try again shortly"
	default:
		return "error", fmt.Sprintf("unexpected status %d", resp.StatusCode)
	}
}

func trimErr(s string) string {
	if len(s) > 140 {
		return s[:140] + "…"
	}
	return s
}
