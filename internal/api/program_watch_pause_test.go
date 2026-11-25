package api

import "testing"

func TestPauseNormalize(t *testing.T) {
	cases := map[string]string{
		"":                    "",
		"open":                "open",
		"OPEN":                "open",
		"paused":              "paused",
		"Paused":              "paused",
		"auto_pause":          "paused",
		"suspended":           "paused",
		"closed":              "closed",
		"Closed":              "closed",
		"archived":            "closed",
		"ended":               "closed",
		"out_of_verification": "closed",
		"public_mode":         "open",
		"soft_launched":       "open",
		"V":                   "open",
		"pending":             "open", // whole tokens: "pending" is not "end" → closed
		"pending_review":      "open",
		"disabled":            "closed",
		"temporarily_paused":  "paused",
	}
	for raw, want := range cases {
		if got := pauseNormalize(raw); got != want {
			t.Errorf("pauseNormalize(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestPauseTransition(t *testing.T) {
	cases := []struct {
		prev, cur, want string
	}{
		{"", "open", ""},     // first sighting: silent baseline
		{"", "paused", ""},   // first sighting even if paused
		{"open", "open", ""}, // unchanged
		{"open", "paused", "paused"},
		{"open", "closed", "paused"},
		{"paused", "open", "returned"},
		{"closed", "open", "returned"},
		{"paused", "closed", ""}, // wobble: record, don't alert
		{"closed", "paused", ""}, // wobble: record, don't alert
		{"open", "", ""},         // state vanished: no alert
	}
	for _, tc := range cases {
		if got := pauseTransition(tc.prev, tc.cur); got != tc.want {
			t.Errorf("pauseTransition(%q, %q) = %q, want %q", tc.prev, tc.cur, got, tc.want)
		}
	}
}

func TestVisibleAccountsLine(t *testing.T) {
	cases := []struct {
		name    string
		sources []string
		want    string
	}{
		{"none", nil, ""},
		{"only empty labels", []string{"", " "}, ""},
		{"one label", []string{"0x88"}, "\n• Visible to: `0x88`"},
		{"two labels", []string{"0x88", "h0x88"}, "\n• Visible to: `0x88`, `h0x88`"},
		{"empty skipped", []string{"", "h0x88"}, "\n• Visible to: `h0x88`"},
		{"backtick sanitized", []string{"a`b"}, "\n• Visible to: `a'b`"},
	}
	for _, tc := range cases {
		if got := visibleAccountsLine(ProgramSummary{Sources: tc.sources}); got != tc.want {
			t.Errorf("%s: visibleAccountsLine(%v) = %q, want %q", tc.name, tc.sources, got, tc.want)
		}
	}
}
