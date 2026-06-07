package depconfusion

import (
	"testing"
)

func TestNormalizeTargetURLEmpty(t *testing.T) {
	if got := normalizeTargetURL(""); got != "" {
		t.Errorf("normalizeTargetURL() = %q, want empty", got)
	}
}

func TestNormalizeTargetURLHTTPS(t *testing.T) {
	got := normalizeTargetURL("https://example.com")
	want := "https://example.com"
	if got != want {
		t.Errorf("normalizeTargetURL() = %q, want %q", got, want)
	}
}

func TestNormalizeTargetURLHTTP(t *testing.T) {
	got := normalizeTargetURL("http://example.com")
	want := "http://example.com"
	if got != want {
		t.Errorf("normalizeTargetURL() = %q, want %q", got, want)
	}
}

func TestNormalizeTargetURLNoProtocol(t *testing.T) {
	got := normalizeTargetURL("example.com")
	want := "https://example.com"
	if got != want {
		t.Errorf("normalizeTargetURL() = %q, want %q", got, want)
	}
}

func TestNormalizeTargetURLMalformedColonSeparator(t *testing.T) {
	got := normalizeTargetURL("www.fasttest.com:package.json")
	want := "https://www.fasttest.com/package.json"
	if got != want {
		t.Errorf("normalizeTargetURL() = %q, want %q", got, want)
	}
}

func TestNormalizeTargetURLMalformedWithHTTPS(t *testing.T) {
	got := normalizeTargetURL("https://www.fasttest.com:package.json")
	want := "https://www.fasttest.com/package.json"
	if got != want {
		t.Errorf("normalizeTargetURL() = %q, want %q", got, want)
	}
}

func TestNormalizeTargetURLMalformedWithHTTP(t *testing.T) {
	got := normalizeTargetURL("http://www.example.com:app.js")
	want := "http://www.example.com/app.js"
	if got != want {
		t.Errorf("normalizeTargetURL() = %q, want %q", got, want)
	}
}

func TestNormalizeTargetURLWithPath(t *testing.T) {
	got := normalizeTargetURL("www.fasttest.com/package.json")
	want := "https://www.fasttest.com/package.json"
	if got != want {
		t.Errorf("normalizeTargetURL() = %q, want %q", got, want)
	}
}

func TestNormalizeTargetURLWithPort(t *testing.T) {
	got := normalizeTargetURL("https://example.com:8080")
	// Port numbers pass through (contain digits after colon, not dot-filename pattern)
	want := "https://example.com:8080"
	if got != want {
		t.Errorf("normalizeTargetURL() = %q, want %q", got, want)
	}
}

func TestNormalizeTargetURLAlreadyHasProtocol(t *testing.T) {
	got := normalizeTargetURL("http://example.com")
	want := "http://example.com"
	if got != want {
		t.Errorf("normalizeTargetURL() = %q, want %q", got, want)
	}
}

func TestNormalizeTargetURLNoProtocolColonWithPath(t *testing.T) {
	// When afterColon contains both dot and slash, not treated as malformed
	got := normalizeTargetURL("example.com:path/file.json")
	want := "https://example.com:path/file.json"
	if got != want {
		t.Errorf("normalizeTargetURL() = %q, want %q", got, want)
	}
}

func TestNormalizeTargetURLNoProtocolWithPort(t *testing.T) {
	got := normalizeTargetURL("example.com:8080")
	want := "https://example.com:8080"
	if got != want {
		t.Errorf("normalizeTargetURL() = %q, want %q", got, want)
	}
}
