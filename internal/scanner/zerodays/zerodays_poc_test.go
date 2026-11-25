package zerodays

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/h0tak88r/AutoAR/internal/tools/next88"
)

func TestReact2ShellFindingText(t *testing.T) {
	cases := map[string]string{
		"normal":                 "RCE exploitation path",
		"":                       "RCE exploitation path",
		"waf-bypass":             "WAF bypass",
		"vercel-waf-bypass":      "WAF bypass",
		"dos-test":               "denial-of-service path",
		"source-exposure":        "source-code / source-map exposure",
		"normal,dos-test":        "RCE exploitation path + denial-of-service path",
		"normal,source-exposure": "source-code / source-map exposure",
	}
	for vtype, want := range cases {
		got := react2ShellFindingText(vtype)
		if !strings.Contains(got, "CVE-2025-55182") {
			t.Errorf("%q: missing CVE in %q", vtype, got)
		}
		if !strings.Contains(got, want) {
			t.Errorf("react2ShellFindingText(%q) = %q, want substring %q", vtype, got, want)
		}
	}
	// dos-only must NOT claim an RCE path
	if strings.Contains(react2ShellFindingText("dos-test"), "RCE") {
		t.Errorf("dos-only finding should not mention RCE")
	}
}

func TestCapPoC(t *testing.T) {
	if got := capPoC("  hello  "); got != "hello" {
		t.Fatalf("capPoC trim: got %q", got)
	}
	big := strings.Repeat("a", 9000)
	out := capPoC(big)
	if !strings.Contains(out, "truncated") {
		t.Fatalf("capPoC should mark truncation for oversized input")
	}
	if len(out) > 8100 {
		t.Fatalf("capPoC did not cap length: got %d", len(out))
	}
}

func TestLeakProof(t *testing.T) {
	out := leakProof([]byte{0x41, 0x00, 0x42})
	if !strings.Contains(out, "41 00 42") || strings.Contains(out, "discarded") {
		t.Fatalf("leakProof small: got %q", out)
	}
	// Only the first leakProofBytes are kept; a secret past that must not leak
	// into the stored proof.
	big := append(make([]byte, leakProofBytes), []byte("SECRET-PII-TAIL")...)
	out = leakProof(big)
	if strings.Contains(out, "SECRET") || !strings.Contains(out, "discarded") {
		t.Fatalf("leakProof must cap to %d bytes: got %q", leakProofBytes, out)
	}
	if strings.Count(out, "\n") > leakProofBytes/16+1 {
		t.Fatalf("leakProof too long: %d lines", strings.Count(out, "\n"))
	}
}

func TestMongoReadCap(t *testing.T) {
	if got := mongoReadCap(65536); got != 65536+64<<10 {
		t.Fatalf("mongoReadCap(64K) = %d", got)
	}
	// A hostile 4 GB length header can never exceed the hard cap.
	if got := mongoReadCap(1 << 31); got != maxMongoLeakBytes {
		t.Fatalf("mongoReadCap(2G) = %d, want %d", got, maxMongoLeakBytes)
	}
}

func TestReact2ShellSafeByDefault(t *testing.T) {
	t.Setenv(envExploitChecks, "")
	if exploitChecksAllowed() {
		t.Fatal("exploit checks must be off by default")
	}
	t.Setenv(envExploitChecks, "true")
	if !exploitChecksAllowed() {
		t.Fatal("opt-in env not honoured")
	}
	got := react2ShellFindingText("safe-check")
	if !strings.Contains(got, "no code executed") || strings.Contains(got, "RCE exploitation") {
		t.Fatalf("safe-check finding text = %q", got)
	}
}

func TestNext88EvidenceHelpers(t *testing.T) {
	code := 500
	r := next88.ScanResult{
		StatusCode:   &code,
		Request:      "POST / HTTP/1.1",
		Response:     "HTTP/1.1 500",
		RequestBody:  "fallback-req",
		ResponseBody: "fallback-resp",
	}
	if next88StatusCode(r) != 500 {
		t.Fatalf("status code: got %d", next88StatusCode(r))
	}
	if next88Request(r) != "POST / HTTP/1.1" {
		t.Fatalf("request prefers full Request: got %q", next88Request(r))
	}
	// Falls back to *Body when the full capture is empty.
	r2 := next88.ScanResult{RequestBody: "only-body", ResponseBody: "only-resp"}
	if next88Request(r2) != "only-body" || next88Response(r2) != "only-resp" {
		t.Fatalf("fallback to body failed: req=%q resp=%q", next88Request(r2), next88Response(r2))
	}
	if next88StatusCode(next88.ScanResult{}) != 0 {
		t.Fatalf("nil status code should be 0")
	}
}

// TestRunNext88ScanSafeByDefault drives the real next88 path against a local
// server: without the opt-in, even a "-smart-scan" request must send only the
// non-executing safe payload — and the signature hit must still surface.
func TestRunNext88ScanSafeByDefault(t *testing.T) {
	t.Setenv(envExploitChecks, "")
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "0:{\"a\":\"$@1\"}\n1:E{\"digest\":\"2971658870\"}")
	}))
	defer srv.Close()

	res, err := runNext88Scan(context.Background(), []string{srv.URL}, []string{"-smart-scan"}, 1, true)
	if err != nil {
		t.Fatalf("runNext88Scan: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) == 0 {
		t.Fatal("no request reached the server")
	}
	for _, b := range bodies {
		if strings.Contains(b, "execSync") || strings.Contains(b, "child_process") {
			t.Fatalf("exploit payload sent without opt-in: %q", b)
		}
	}
	r, ok := res[srv.URL]
	if !ok {
		t.Fatalf("safe-check signature hit not reported: %+v", res)
	}
	if r.VulnType != "safe-check" {
		t.Fatalf("VulnType = %q, want safe-check", r.VulnType)
	}
}
