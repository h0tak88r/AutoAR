// Package bugcrowd signs a researcher in to Bugcrowd and checks a session, so
// a Bugcrowd account keeps working after its session cookie expires.
//
// Bugcrowd signs researchers in through Okta (login.hackers.bugcrowd.com, the
// IDX API):
//
//	identity.bugcrowd.com/login                 identity cookies
//	…/login/hacker/oauth2/authorization/hacker  → Okta's sign-in page (stateToken)
//	Okta /idp/idx/introspect → identify → challenge/answer (password)
//	     → select the authenticator app → challenge/answer (TOTP code)
//	success.href                                → bugcrowd.com sets the session
//
// Ported from bbscope's Login (github.com/sw33tLie/bbscope 75c2841, Sep 2026):
// one request a second (Bugcrowd's WAF bans faster clients), redirects only
// within bugcrowd.com, errors instead of log.Fatal, and a check that Bugcrowd
// accepts the new session before it is returned.
package bugcrowd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/internal/totp"
	"github.com/tidwall/gjson"
)

const (
	identityURL = "https://identity.bugcrowd.com"
	oktaURL     = "https://login.hackers.bugcrowd.com"
	siteURL     = "https://bugcrowd.com"

	// loginUA is bbscope's, which Bugcrowd's edge and Okta accept for the
	// sign-in flow.
	loginUA = "Mozilla/5.0 (X11; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0"
	// checkUA is the browser UA the session check has always used (the edge
	// rejects obviously-scripted clients on /dashboard).
	checkUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

// Seams for tests: the transport (a fake Bugcrowd) and the gap between
// sign-in requests.
var (
	Transport http.RoundTripper = http.DefaultTransport
	Pace                        = time.Second
)

// ErrWAF is Bugcrowd's edge refusing the client (403/406).
var ErrWAF = errors.New("Bugcrowd's WAF blocked the request (403/406) — wait a few hours or change IP")

// CookieHeader is the Cookie header for a stored session. A login stores the
// whole bugcrowd.com cookie string ("a=b; c=d"); a session cookie pasted by
// hand is the bare _bugcrowd_session value.
func CookieHeader(token string) string {
	token = strings.TrimSpace(token)
	if strings.Contains(token, "=") {
		return token
	}
	return "_bugcrowd_session=" + token
}

// CheckSession asks bugcrowd.com/dashboard, which needs a signed-in session:
// 200 = valid; a redirect (to the sign-in page) or 401 = expired. The public
// engagements list can't tell a good session from a bad one.
// Status: valid | invalid | blocked | error.
func CheckSession(token string) (status, detail string) {
	if strings.TrimSpace(token) == "" {
		return "invalid", "no session"
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest("GET", siteURL+"/dashboard", nil)
	req.Header.Set("Cookie", CookieHeader(token))
	req.Header.Set("User-Agent", checkUA)
	resp, err := client.Do(req)
	if err != nil {
		return "error", err.Error()
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200:
		return "valid", "session authenticated (200)"
	case 301, 302, 303, 307, 308, 401:
		return "invalid", "session expired or invalid"
	case 403, 406:
		return "blocked", "Bugcrowd WAF/IP block — try again later"
	case 429:
		return "blocked", "rate limited (429) — try again shortly"
	default:
		return "error", fmt.Sprintf("unexpected status %d", resp.StatusCode)
	}
}

// Login signs in with email + password and, when Bugcrowd asks for one, a
// code from the TOTP secret (the base32 seed or otpauth:// URI). It returns
// the bugcrowd.com cookie string to store as the account's session.
func Login(email, password, totpSecret string) (string, error) {
	email = strings.TrimSpace(email)
	if email == "" || password == "" {
		return "", errors.New("email and password are required")
	}
	jar, _ := cookiejar.New(nil)
	c := &client{hc: &http.Client{Timeout: 30 * time.Second, Jar: jar, Transport: Transport, CheckRedirect: stayOnBugcrowd}}

	signIn := identityURL + "/login?user_hint=researcher&returnTo=https%3A%2F%2Fbugcrowd.com%2Fdashboard"
	if _, _, err := c.get(signIn, ""); err != nil {
		return "", err
	}
	// The OAuth start redirects to Okta's sign-in page, which carries the
	// stateToken the IDX calls continue from.
	start := identityURL + "/login/hacker/oauth2/authorization/hacker?returnTo=https://bugcrowd.com/dashboard"
	resp, page, err := c.get(start, signIn)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("Okta sign-in page: %s", oktaError(page, resp.StatusCode))
	}
	if strings.Contains(page, "unexpected internal error") || strings.Contains(page, "Something went wrong") {
		return "", errors.New("Okta's sign-in page returned an error")
	}
	referer := start
	if m := authorizeRE.FindString(page); m != "" {
		referer = m
	} else if resp.Request != nil && onBugcrowd(resp.Request.URL.String()) {
		referer = resp.Request.URL.String()
	}

	st := &oktaState{}
	intro := map[string]any{}
	if m := stateTokenRE.FindStringSubmatch(page); m != nil {
		intro["stateToken"] = decodeOktaEscapes(m[1])
	}
	body, err := c.idx(oktaURL+"/idp/idx/introspect", intro, st, referer)
	if err != nil {
		return "", fmt.Errorf("Okta introspect: %w", err)
	}
	if st.handle == "" && st.token == "" {
		return "", errors.New("Okta returned no state token")
	}
	needPassword := requiresPassword(body)
	if hasRemediation(body, "identify") {
		if body, err = c.idx(oktaURL+"/idp/idx/identify", map[string]any{"identifier": email}, st, referer); err != nil {
			return "", fmt.Errorf("Okta identify: %w", err)
		}
		needPassword = requiresPassword(body)
	}
	if needPassword {
		if body, err = c.idx(oktaURL+"/idp/idx/challenge/answer", map[string]any{"credentials": map[string]any{"passcode": password}}, st, referer); err != nil {
			return "", fmt.Errorf("password rejected: %w", err)
		}
	}
	if hasRemediation(body, "select-authenticator-authenticate") {
		href, id := otpAuthenticator(body)
		if id == "" {
			return "", errors.New("Bugcrowd's Okta offers no authenticator-app (TOTP) factor for this account")
		}
		if !onBugcrowd(href) {
			return "", fmt.Errorf("unexpected authenticator URL %q", href)
		}
		if body, err = c.idx(href, map[string]any{"authenticator": map[string]any{"id": id}}, st, referer); err != nil {
			return "", fmt.Errorf("selecting the authenticator app: %w", err)
		}
	}
	// An account without 2FA is done after the password.
	if gjson.Get(body, "success.href").String() == "" {
		if strings.TrimSpace(totpSecret) == "" {
			return "", errors.New("Bugcrowd asks for a 2FA code but the account has no TOTP secret")
		}
		code, err := totp.Code(totpSecret, time.Now())
		if err != nil {
			return "", err
		}
		if body, err = c.idx(oktaURL+"/idp/idx/challenge/answer", map[string]any{"credentials": map[string]any{"passcode": code}}, st, referer); err != nil {
			return "", fmt.Errorf("2FA code rejected: %w", err)
		}
	}

	// success.href goes back to Bugcrowd, which sets the session cookies.
	next := gjson.Get(body, "success.href").String()
	if next == "" {
		next = oktaURL + "/login/token/redirect?stateToken=" + url.QueryEscape(st.redirectToken(body))
	}
	if !onBugcrowd(next) {
		return "", fmt.Errorf("unexpected sign-in redirect %q", next)
	}
	if _, _, err := c.get(next, referer); err != nil {
		return "", err
	}
	cookies := jarHeader(jar)
	if cookies == "" {
		if _, _, err := c.get(siteURL+"/dashboard", identityURL+"/"); err != nil {
			return "", err
		}
		if cookies = jarHeader(jar); cookies == "" {
			return "", errors.New("signed in, but Bugcrowd set no session cookie")
		}
	}
	if status, detail := CheckSession(cookies); status == "invalid" {
		return "", fmt.Errorf("signed in, but Bugcrowd doesn't accept the session (%s)", detail)
	}
	return cookies, nil
}

type client struct {
	hc   *http.Client
	last time.Time
}

func (c *client) send(req *http.Request) (*http.Response, string, error) {
	if wait := Pace - time.Since(c.last); wait > 0 {
		time.Sleep(wait)
	}
	defer func() { c.last = time.Now() }()
	req.Header.Set("User-Agent", loginUA)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, "", err
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	resp.Body.Close()
	if resp.StatusCode == 403 || resp.StatusCode == 406 {
		return resp, string(raw), ErrWAF
	}
	return resp, string(raw), nil
}

func (c *client) get(u, referer string) (*http.Response, string, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, "", err
	}
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	return c.send(req)
}

// idx posts one Okta IDX step and carries its state forward.
func (c *client) idx(u string, body map[string]any, st *oktaState, referer string) (string, error) {
	st.add(body)
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", u, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Origin", oktaURL)
	req.Header.Set("Referer", referer)
	resp, raw, err := c.send(req)
	// Okta answers a wrong code or password with a JSON message, sometimes
	// as a 403: that message, not "WAF", is the reason.
	if msg := oktaMessage(raw); errors.Is(err, ErrWAF) && msg != "" {
		return raw, errors.New(msg)
	}
	if err != nil {
		return raw, err
	}
	if msg := gjson.Get(raw, "errorSummary").String(); msg != "" {
		return raw, errors.New(msg)
	}
	if resp.StatusCode >= 400 {
		return raw, errors.New(oktaError(raw, resp.StatusCode))
	}
	st.update(raw)
	return raw, nil
}

// stayOnBugcrowd follows redirects only within bugcrowd.com over https.
func stayOnBugcrowd(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("too many redirects")
	}
	if !onBugcrowd(req.URL.String()) {
		return http.ErrUseLastResponse
	}
	return nil
}

func onBugcrowd(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h == "bugcrowd.com" || strings.HasSuffix(h, ".bugcrowd.com")
}

// jarHeader is every bugcrowd.com cookie as one Cookie header.
func jarHeader(jar http.CookieJar) string {
	u, _ := url.Parse(siteURL)
	seen := map[string]bool{}
	var parts []string
	for _, ck := range jar.Cookies(u) {
		if !seen[ck.Name] && ck.Value != "" {
			seen[ck.Name] = true
			parts = append(parts, ck.Name+"="+ck.Value)
		}
	}
	return strings.Join(parts, "; ")
}

var (
	authorizeRE  = regexp.MustCompile(`https://login\.hackers\.bugcrowd\.com/oauth2/[^"'\s]+`)
	stateTokenRE = regexp.MustCompile(`"stateToken":"([^"]+)"`)
	hexEscapeRE  = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
)

// decodeOktaEscapes undoes the \xNN / \uNNNN escaping Okta uses in the page.
func decodeOktaEscapes(s string) string {
	if s == "" {
		return ""
	}
	u := strings.ReplaceAll(hexEscapeRE.ReplaceAllString(s, `\\u00$1`), `\\u`, `\u`)
	if out, err := strconv.Unquote(`"` + u + `"`); err == nil {
		return out
	}
	return s
}

// oktaState is the IDX state each step sends back.
type oktaState struct{ handle, token string }

func (s *oktaState) update(body string) {
	if v := gjson.Get(body, "stateHandle").String(); v != "" {
		s.handle = decodeOktaEscapes(v)
	}
	if v := gjson.Get(body, "stateToken").String(); v != "" {
		s.token = decodeOktaEscapes(v)
	}
	if s.token == "" {
		if v := gjson.Get(body, "token").String(); v != "" {
			s.token = decodeOktaEscapes(v)
		}
	}
}

func (s *oktaState) add(m map[string]any) {
	if s.handle != "" {
		m["stateHandle"] = s.handle
	}
	if s.token != "" {
		m["stateToken"] = s.token
	}
}

// redirectToken is the state token for /login/token/redirect when Okta's
// answer has no success.href: the part of the handle before "~".
func (s *oktaState) redirectToken(body string) string {
	if v := gjson.Get(body, "sessionToken").String(); v != "" {
		return v
	}
	if s.token != "" {
		return s.token
	}
	h, _, _ := strings.Cut(s.handle, "~")
	return h
}

func hasRemediation(body, name string) bool {
	found := false
	gjson.Get(body, "remediation.value").ForEach(func(_, v gjson.Result) bool {
		found = strings.EqualFold(v.Get("name").String(), name)
		return !found
	})
	return found
}

// requiresPassword: Okta is asking for the password (not a 2FA code).
func requiresPassword(body string) bool {
	typ := strings.ToLower(gjson.Get(body, "currentAuthenticatorEnrollment.value.type").String())
	if typ == "" {
		typ = strings.ToLower(gjson.Get(body, "currentAuthenticatorEnrollment.type").String())
	}
	key := strings.ToLower(gjson.Get(body, "currentAuthenticatorEnrollment.value.key").String())
	if key == "" {
		key = strings.ToLower(gjson.Get(body, "currentAuthenticatorEnrollment.key").String())
	}
	if typ == "password" || key == "password" || key == "okta_password" {
		return true
	}
	found := false
	gjson.Get(body, "remediation.value").ForEach(func(_, rem gjson.Result) bool {
		if strings.EqualFold(rem.Get("name").String(), "challenge-authenticator") {
			rem.Get("value").ForEach(func(_, field gjson.Result) bool {
				if field.Get("name").String() == "credentials" {
					field.Get("form.value").ForEach(func(_, f gjson.Result) bool {
						found = strings.Contains(strings.ToLower(f.Get("label").String()), "password")
						return !found
					})
				}
				return !found
			})
		}
		return !found
	})
	return found
}

// otpAuthenticator finds the authenticator-app option in Okta's
// select-authenticator step: its URL and id. Okta labels it "Google
// Authenticator" (key google_otp), so the reliable signals are the key and the
// option's methodType=otp form field; the label is a fallback.
func otpAuthenticator(body string) (href, id string) {
	gjson.Get(body, "remediation.value").ForEach(func(_, rem gjson.Result) bool {
		if !strings.EqualFold(rem.Get("name").String(), "select-authenticator-authenticate") {
			return true
		}
		href = rem.Get("href").String()
		rem.Get("value").ForEach(func(_, field gjson.Result) bool {
			if field.Get("name").String() != "authenticator" {
				return true
			}
			field.Get("options").ForEach(func(_, opt gjson.Result) bool {
				if isOTPOption(opt) {
					id = optionID(opt)
				}
				return id == ""
			})
			return id == ""
		})
		return id == ""
	})
	if href == "" {
		href = oktaURL + "/idp/idx/challenge"
	}
	return href, id
}

func isOTPOption(opt gjson.Result) bool {
	if strings.EqualFold(opt.Get("relatesTo.key").String(), "google_otp") {
		return true
	}
	otp := false
	opt.Get("value.form.value").ForEach(func(_, f gjson.Result) bool {
		otp = f.Get("name").String() == "methodType" && strings.EqualFold(f.Get("value").String(), "otp")
		return !otp
	})
	if otp {
		return true
	}
	label := strings.ToLower(opt.Get("label").String())
	return strings.Contains(label, "otp") || strings.Contains(label, "google authenticator")
}

func optionID(opt gjson.Result) string {
	if v := opt.Get("value.id").String(); v != "" {
		return v
	}
	if v := opt.Get("relatesTo.id").String(); v != "" {
		return v
	}
	id := ""
	opt.Get("value.form.value").ForEach(func(_, f gjson.Result) bool {
		if f.Get("name").String() == "id" {
			id = f.Get("value").String()
		}
		return id == ""
	})
	return id
}

// oktaMessage is the error Okta put in a JSON answer, or "".
func oktaMessage(body string) string {
	if !gjson.Valid(body) {
		return ""
	}
	for _, p := range []string{"errorSummary", "messages.value.0.message", "error_description", "error"} {
		if msg := gjson.Get(body, p).String(); msg != "" {
			return msg
		}
	}
	return ""
}

func oktaError(body string, status int) string {
	if msg := oktaMessage(body); msg != "" {
		return msg
	}
	return fmt.Sprintf("Okta returned status %d", status)
}
