package jsmonitor

import (
	"strings"
	"testing"
)

// TestMaskSecretCandidates: monitor alerts go to Discord — secret candidates
// must be masked and target-derived text escaped.
func TestMaskSecretCandidates(t *testing.T) {
	in := []string{
		"AWS Access Key: AKIAIOSFODNN7EXAMPLE",
		"Generic_Token: `@everyone` sk_live_0123456789abcdefXYZ",
		"no-separator-value-1234567890",
	}
	out := maskSecretCandidates(in)
	if len(out) != len(in) {
		t.Fatalf("got %d items", len(out))
	}
	if !strings.HasPrefix(out[0], "AWS Access Key: AKIA…MPLE") || strings.Contains(out[0], "IOSFODNN7") {
		t.Fatalf("not masked: %q", out[0])
	}
	if strings.Contains(out[1], "0123456789abcdef") || strings.Contains(strings.ReplaceAll(out[1], "\\`", ""), "`") {
		t.Fatalf("value leaked or backtick unescaped: %q", out[1])
	}
	if !strings.HasPrefix(out[1], `Generic\_Token: `) {
		t.Fatalf("detector name not escaped: %q", out[1])
	}
	if !strings.HasPrefix(out[2], "secret: ") || strings.Contains(out[2], "value-1234") {
		t.Fatalf("separator-less candidate not masked: %q", out[2])
	}
}

func TestEscapeAll(t *testing.T) {
	got := escapeAll([]string{"/api/[x](https://evil)", strings.Repeat("a", 500)}, 200)
	if strings.Contains(got[0], "](") {
		t.Fatalf("markdown link not escaped: %q", got[0])
	}
	if len([]rune(got[1])) > 201 {
		t.Fatalf("not truncated: %d", len([]rune(got[1])))
	}
}
