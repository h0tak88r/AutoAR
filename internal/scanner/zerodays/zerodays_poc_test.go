package zerodays

import (
	"strings"
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

func TestPreviewLeak(t *testing.T) {
	// 'A', NUL, 'B', newline, tab → printable kept, non-printable shown as '.'
	out := previewLeak([]byte{0x41, 0x00, 0x42, 0x0a, 0x09})
	if out != "A.B\n\t" {
		t.Fatalf("previewLeak: got %q want %q", out, "A.B\n\t")
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
