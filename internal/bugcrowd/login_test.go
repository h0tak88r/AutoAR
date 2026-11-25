package bugcrowd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/h0tak88r/AutoAR/internal/totp"
)

const testSeed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// fakeBugcrowd plays identity.bugcrowd.com, Okta and bugcrowd.com, routed by
// Host, through a transport that sends every https request to the test server.
type fakeBugcrowd struct {
	password  string
	waf       bool   // identity answers 403
	noMFA     bool   // the password step finishes the sign-in
	successTo string // overrides the final success.href
	steps     []string
}

func (f *fakeBugcrowd) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.steps = append(f.steps, r.Method+" "+r.Host+r.URL.Path)
	var in map[string]any
	if r.Method == "POST" {
		_ = json.NewDecoder(r.Body).Decode(&in)
	}
	js := func(code int, s string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		fmt.Fprint(w, s)
	}
	switch r.Host + r.URL.Path {
	case "identity.bugcrowd.com/login":
		if f.waf {
			w.WriteHeader(403)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "csrf-token", Value: "c1", Path: "/"})
	case "identity.bugcrowd.com/login/hacker/oauth2/authorization/hacker":
		http.Redirect(w, r, "https://login.hackers.bugcrowd.com/oauth2/default/v1/authorize?client_id=x&state=y", 302)
	case "login.hackers.bugcrowd.com/oauth2/default/v1/authorize":
		fmt.Fprint(w, `<script>var cfg = {"stateToken":"st\x2D1","baseUrl":"https://login.hackers.bugcrowd.com/oauth2/default/v1/authorize?client_id=x"};</script>`)
	case "login.hackers.bugcrowd.com/idp/idx/introspect":
		if in["stateToken"] != "st-1" {
			js(400, `{"messages":{"value":[{"message":"bad state token"}]}}`)
			return
		}
		js(200, `{"stateHandle":"h1~c.x","remediation":{"value":[{"name":"identify"}]}}`)
	case "login.hackers.bugcrowd.com/idp/idx/identify":
		if in["identifier"] != "me@example.com" || in["stateHandle"] != "h1~c.x" {
			js(400, `{"errorSummary":"bad identify"}`)
			return
		}
		js(200, `{"stateHandle":"h2","currentAuthenticatorEnrollment":{"type":"object","value":{"type":"password","key":"okta_password"}},"remediation":{"value":[{"name":"challenge-authenticator"}]}}`)
	case "login.hackers.bugcrowd.com/idp/idx/challenge/answer":
		pass, _ := in["credentials"].(map[string]any)["passcode"].(string)
		switch in["stateHandle"] {
		case "h2":
			if pass != f.password {
				js(401, `{"messages":{"value":[{"message":"Password is incorrect"}]}}`)
				return
			}
			if f.noMFA {
				js(200, `{"success":{"href":"https://login.hackers.bugcrowd.com/login/token/redirect?stateToken=tok-5"}}`)
				return
			}
			js(200, `{"stateHandle":"h3","remediation":{"value":[{"name":"select-authenticator-authenticate","href":"https://login.hackers.bugcrowd.com/idp/idx/challenge","value":[{"name":"authenticator","options":[
				{"label":"Email","value":{"form":{"value":[{"name":"id","value":"email-id"},{"name":"methodType","value":"email"}]}}},
				{"label":"Google Authenticator","relatesTo":{"key":"google_otp","id":"otp-id"},"value":{"form":{"value":[{"name":"id","value":"otp-id"}]}}}]}]}]}}`)
		case "h4":
			now, _ := totp.Code(testSeed, time.Now())
			prev, _ := totp.Code(testSeed, time.Now().Add(-30*time.Second))
			if pass != now && pass != prev {
				js(403, `{"messages":{"value":[{"message":"Invalid code. Try again."}]}}`)
				return
			}
			to := "https://login.hackers.bugcrowd.com/login/token/redirect?stateToken=tok-5"
			if f.successTo != "" {
				to = f.successTo
			}
			js(200, `{"success":{"href":"`+to+`"}}`)
		default:
			js(400, `{"errorSummary":"bad state"}`)
		}
	case "login.hackers.bugcrowd.com/idp/idx/challenge":
		if in["authenticator"].(map[string]any)["id"] != "otp-id" || in["stateHandle"] != "h3" {
			js(400, `{"errorSummary":"wrong authenticator"}`)
			return
		}
		js(200, `{"stateHandle":"h4","currentAuthenticatorEnrollment":{"value":{"type":"app","key":"google_otp"}},"remediation":{"value":[{"name":"challenge-authenticator"}]}}`)
	case "login.hackers.bugcrowd.com/login/token/redirect":
		if r.URL.Query().Get("stateToken") != "tok-5" {
			w.WriteHeader(400)
			return
		}
		http.Redirect(w, r, "https://bugcrowd.com/user/auth/hacker/callback?code=c", 302)
	case "bugcrowd.com/user/auth/hacker/callback":
		http.SetCookie(w, &http.Cookie{Name: "_bugcrowd_session", Value: "SESSION", Path: "/", Secure: true, HttpOnly: true})
		http.Redirect(w, r, "https://bugcrowd.com/dashboard", 302)
	case "bugcrowd.com/dashboard":
		if !strings.Contains(r.Header.Get("Cookie"), "_bugcrowd_session=SESSION") {
			http.Redirect(w, r, "https://identity.bugcrowd.com/login", 302)
			return
		}
		fmt.Fprint(w, "dashboard")
	default:
		w.WriteHeader(404)
	}
}

type rewrite struct{ to *url.URL }

func (rw rewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.Host = r.URL.Host
	r2.URL.Scheme, r2.URL.Host = "http", rw.to.Host
	return http.DefaultTransport.RoundTrip(r2)
}

func useFake(t *testing.T, f *fakeBugcrowd) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	oT, oP := Transport, Pace
	Transport, Pace = rewrite{u}, 0
	t.Cleanup(func() { Transport, Pace = oT, oP })
}

func TestLoginWithTOTP(t *testing.T) {
	f := &fakeBugcrowd{password: "pw-fixture"}
	useFake(t, f)
	tok, err := Login(" me@example.com ", "pw-fixture", "otpauth://totp/Bugcrowd:me?secret="+testSeed+"&issuer=Bugcrowd")
	if err != nil {
		t.Fatalf("login: %v\nsteps: %v", err, f.steps)
	}
	if !strings.Contains(tok, "_bugcrowd_session=SESSION") || CookieHeader(tok) != tok {
		t.Fatalf("session: %q", tok)
	}
	if st, _ := CheckSession(tok); st != "valid" {
		t.Fatalf("check: %s", st)
	}
	if st, _ := CheckSession("SESSION"); st != "valid" {
		t.Fatal("a bare session value is sent as _bugcrowd_session")
	}
	if st, _ := CheckSession("expired"); st != "invalid" {
		t.Fatalf("expired: %s", st)
	}
	// The authenticator app was picked, not the e-mail factor.
	if !strings.Contains(strings.Join(f.steps, "\n"), "POST login.hackers.bugcrowd.com/idp/idx/challenge\n") {
		t.Fatalf("steps: %v", f.steps)
	}
}

func TestLoginWithoutMFA(t *testing.T) {
	useFake(t, &fakeBugcrowd{password: "pw-fixture", noMFA: true})
	if tok, err := Login("me@example.com", "pw-fixture", ""); err != nil || !strings.Contains(tok, "SESSION") {
		t.Fatalf("%q %v", tok, err)
	}
}

func TestLoginFailures(t *testing.T) {
	for name, c := range map[string]struct {
		f       fakeBugcrowd
		pw, otp string
		want    string
	}{
		"wrong password": {fakeBugcrowd{password: "pw-fixture"}, "nope", testSeed, "password rejected: Password is incorrect"},
		"no TOTP secret": {fakeBugcrowd{password: "pw-fixture"}, "pw-fixture", "", "no TOTP secret"},
		"wrong TOTP":     {fakeBugcrowd{password: "pw-fixture"}, "pw-fixture", "JBSWY3DPEHPK3PXP", "2FA code rejected: Invalid code"},
		"bad TOTP seed":  {fakeBugcrowd{password: "pw-fixture"}, "pw-fixture", "not base32!", "invalid base32"},
		"WAF":            {fakeBugcrowd{password: "pw-fixture", waf: true}, "pw-fixture", testSeed, "WAF"},
		"off-site hop":   {fakeBugcrowd{password: "pw-fixture", successTo: "https://evil.example/steal"}, "pw-fixture", testSeed, "unexpected sign-in redirect"},
	} {
		f := c.f
		useFake(t, &f)
		_, err := Login("me@example.com", c.pw, c.otp)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
		if name == "WAF" && !errors.Is(err, ErrWAF) {
			t.Errorf("WAF error is not ErrWAF: %v", err)
		}
	}
	if _, err := Login("", "x", testSeed); err == nil {
		t.Error("empty email accepted")
	}
}

func TestHelpers(t *testing.T) {
	if got := decodeOktaEscapes(`a\x2Db-c`); got != "a-b-c" {
		t.Errorf("decode: %q", got)
	}
	for u, want := range map[string]bool{
		"https://bugcrowd.com/x": true, "https://login.hackers.bugcrowd.com/y": true,
		"http://bugcrowd.com/": false, "https://bugcrowd.com.evil.io/": false, "https://evilbugcrowd.com/": false,
	} {
		if onBugcrowd(u) != want {
			t.Errorf("onBugcrowd(%s) != %v", u, want)
		}
	}
	if CookieHeader(" abc ") != "_bugcrowd_session=abc" || CookieHeader("a=b; c=d") != "a=b; c=d" {
		t.Error("CookieHeader")
	}
}
