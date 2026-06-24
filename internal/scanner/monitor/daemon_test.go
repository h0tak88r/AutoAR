package monitor

import "testing"

func TestMaxRegexMatchAndCompare(t *testing.T) {
	cases := []struct {
		name    string
		matches []string
		want    string
	}{
		// ISO YYYY-MM-DD: lexical = chronological, picks the latest date.
		{"iso latest wins", []string{"2026-06-23", "2026-06-24", "2026-06-23"}, "2026-06-24"},
		{"iso single", []string{"2026-06-24"}, "2026-06-24"},

		// "Jan 2, 2006" form: lexical Jul<Jun (because 'l'<'n'), so without
		// date-aware compare we'd pick Jun. The fix should pick Jul.
		{"month name across months", []string{"Jun 30, 2026", "Jul 1, 2026"}, "Jul 1, 2026"},
		{"month name within month", []string{"Jun 23, 2026", "Jun 24, 2026"}, "Jun 24, 2026"},

		// Non-date values: lexical fallback is fine.
		{"version-ish", []string{"v1.2.3", "v1.10.0"}, "v1.2.3"}, // lexical: "1.2" > "1.1"
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := maxRegexMatch(tc.matches)
			if got != tc.want {
				t.Fatalf("maxRegexMatch(%v) = %q, want %q", tc.matches, got, tc.want)
			}
		})
	}
}

// The flapping bug reproduced: simulate two sequential pages where the freshest
// date appears in different positions. With FindString (old behaviour) the
// baseline would flip; with maxRegexMatch the baseline stays on the latest date.
func TestNoFlappingOnReorderedMatches(t *testing.T) {
	// Page A lists posts in order [24, 23], page B reorders to [23, 24].
	pageAMatches := []string{"2026-06-24", "2026-06-23"}
	pageBMatches := []string{"2026-06-23", "2026-06-24"}

	a := maxRegexMatch(pageAMatches)
	b := maxRegexMatch(pageBMatches)
	if a != b {
		t.Fatalf("expected stable max across re-ordered pages, got A=%q B=%q", a, b)
	}
}

// Forward-only watermark: a backward "match" returned by a single check should
// compareWatchValue negative against the current baseline, so the caller skips.
func TestCompareWatchValueChronological(t *testing.T) {
	if compareWatchValue("2026-06-24", "2026-06-23") <= 0 {
		t.Fatal("expected 24 > 23")
	}
	if compareWatchValue("Jul 1, 2026", "Jun 30, 2026") <= 0 {
		t.Fatal("expected Jul 1 > Jun 30 (date-aware, not lexical)")
	}
	if compareWatchValue("2026-06-23", "2026-06-23") != 0 {
		t.Fatal("expected equal")
	}
}
