package api

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/accounts"
	"github.com/h0tak88r/AutoAR/internal/db"
)

// A browser-like UA for the Bugcrowd session-cookie check (its edge rejects
// obviously-scripted clients). This authenticates to Bugcrowd as the researcher
// to list *their own* programs — a normal platform interaction, not target probing.
const acctCheckUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

// GET /api/accounts/:id/check — validate one stored account's credentials against
// its platform with a single lightweight authenticated request. Returns a status:
// valid | invalid | blocked | unsupported | error.
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
	status, detail := checkAccountCredential(*acct)
	c.JSON(http.StatusOK, gin.H{
		"id":       id,
		"platform": acct.Platform,
		"status":   status,
		"detail":   detail,
		"valid":    status == "valid",
	})
}

// checkAccountCredential makes one minimal authenticated call per platform and
// classifies the outcome. It never returns program data — only a status.
func checkAccountCredential(a db.BBPAccount) (status, detail string) {
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
		if a.Token == "" {
			return "invalid", "missing JWT token"
		}
		req, _ := http.NewRequest("GET", "https://api.yeswehack.com/programs?page=1", nil)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+a.Token)
		return interpretAPI(client.Do(req))

	case "bc":
		if a.Token == "" {
			return "invalid", "missing session cookie"
		}
		req, _ := http.NewRequest("GET", "https://bugcrowd.com/engagements.json?category=bug_bounty&sort_by=promoted&sort_direction=desc&page=1", nil)
		req.Header.Set("Cookie", "_crowdcontrol_session_key="+a.Token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", acctCheckUA)
		return interpretBugcrowd(client.Do(req))

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

// interpretBugcrowd handles the cookie-auth case: a valid session returns 200
// with the engagements JSON; an expired one 302s to login (or 200 login HTML).
func interpretBugcrowd(resp *http.Response, err error) (string, string) {
	if err != nil {
		return "error", trimErr(err.Error())
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if strings.Contains(string(body), "engagements") || strings.Contains(string(body), "paginationMeta") {
			return "valid", "session cookie accepted (200)"
		}
		return "invalid", "session cookie expired — refresh it"
	case 301, 302, 303, 307, 308, 401:
		return "invalid", "session cookie expired — refresh it"
	case 403, 406:
		return "blocked", "Bugcrowd WAF/IP block — try again later"
	case 429:
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
