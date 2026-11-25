package utils

import (
	"strings"
	"testing"
)

func TestDiscordEscape(t *testing.T) {
	got := DiscordEscape("@everyone [nvd.nist.gov](https://evil) `x` <@123>")
	if strings.Contains(got, "@everyone") || strings.Contains(got, "<@123>") {
		t.Fatalf("mention not defused: %q", got)
	}
	if strings.Contains(got, "[nvd.nist.gov](https") {
		t.Fatalf("masked link not escaped: %q", got)
	}
	if strings.Contains(got, " `x` ") {
		t.Fatalf("code span not escaped: %q", got)
	}
	if DiscordEscape("plain text 1.2.3") != "plain text 1.2.3" {
		t.Fatal("plain text should pass through")
	}
}

func TestDiscordEscapeTrunc(t *testing.T) {
	got := DiscordEscapeTrunc(strings.Repeat("a", 50), 10)
	if got != strings.Repeat("a", 10)+"…" {
		t.Fatalf("got %q", got)
	}
}
