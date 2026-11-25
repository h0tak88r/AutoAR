package huntermonitor

import "testing"

// TestDecodeRelayNumericID covers the base64 GraphQL Relay Global-ID decoder.
// Fixtures were generated with base64.StdEncoding over the plaintext GIDs shown
// in each comment, so the decode path is exercised end to end.
func TestDecodeRelayNumericID(t *testing.T) {
	tests := []struct {
		name    string
		gid     string
		want    string
		wantErr bool
	}{
		{
			// base64("gid://hackerone/User/2508920") — the canonical case from
			// the doc comment on decodeRelayNumericID.
			name: "canonical hackerone user gid",
			gid:  "Z2lkOi8vaGFja2Vyb25lL1VzZXIvMjUwODkyMA==",
			want: "2508920",
		},
		{
			// Not valid standard-base64 input at all: '!' and ' ' are outside
			// the base64 alphabet, so DecodeString returns an error and the
			// function must surface it.
			name:    "non-base64 input errors",
			gid:     "!!!! not base64 !!!!",
			wantErr: true,
		},
		{
			// base64("gid://hackerone/User/") — decodes cleanly but the trailing
			// segment after the final '/' is empty, which the function rejects.
			name:    "trailing slash yields empty numeric id",
			gid:     "Z2lkOi8vaGFja2Vyb25lL1VzZXIv",
			wantErr: true,
		},
		{
			// base64("gid://hackerone/User/abc") — a non-numeric trailing
			// segment. The function does not validate numeric-ness; it returns
			// the last path element verbatim.
			name: "non-numeric trailing segment returned as-is",
			gid:  "Z2lkOi8vaGFja2Vyb25lL1VzZXIvYWJj",
			want: "abc",
		},
		{
			// base64("justastring") — no '/' at all, so the whole decoded string
			// is the last (only) segment and is returned unchanged.
			name: "no slash returns whole decoded string",
			gid:  "anVzdGFzdHJpbmc=",
			want: "justastring",
		},
		{
			// Empty input decodes to an empty string, whose last segment is
			// empty — treated the same as the trailing-slash case.
			name:    "empty input yields empty numeric id",
			gid:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeRelayNumericID(tt.gid)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("decodeRelayNumericID(%q) = %q, want error", tt.gid, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeRelayNumericID(%q) unexpected error: %v", tt.gid, err)
			}
			if got != tt.want {
				t.Errorf("decodeRelayNumericID(%q) = %q, want %q", tt.gid, got, tt.want)
			}
		})
	}
}

// TestResolvedReportIsResolved verifies that both landing actions
// (BugResolved and BountyAwarded) count as resolved/alertable, while any other
// action does not.
func TestResolvedReportIsResolved(t *testing.T) {
	tests := []struct {
		name   string
		action string
		want   bool
	}{
		{"bug resolved is resolved", ActionBugResolved, true},
		{"bounty awarded is resolved", ActionBountyAwarded, true},
		{"unrelated activity is not resolved", "Activities::Comment", false},
		{"report became public is not resolved", "Activities::ReportBecamePublic", false},
		{"empty action is not resolved", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ResolvedReport{Action: tt.action}
			if got := r.IsResolved(); got != tt.want {
				t.Errorf("ResolvedReport{Action:%q}.IsResolved() = %v, want %v", tt.action, got, tt.want)
			}
		})
	}
}

// TestResolvedReportActionLabel verifies the Discord-facing label for each
// action, including the default branch that strips the "Activities::" prefix
// for unknown actions.
func TestResolvedReportActionLabel(t *testing.T) {
	tests := []struct {
		name   string
		action string
		want   string
	}{
		{"bounty awarded label", ActionBountyAwarded, "bounty awarded"},
		{"bug resolved label", ActionBugResolved, "resolved"},
		{"unknown activity strips prefix", "Activities::ReportBecamePublic", "ReportBecamePublic"},
		{"action without known prefix passes through", "SomethingElse", "SomethingElse"},
		{"empty action stays empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ResolvedReport{Action: tt.action}
			if got := r.ActionLabel(); got != tt.want {
				t.Errorf("ResolvedReport{Action:%q}.ActionLabel() = %q, want %q", tt.action, got, tt.want)
			}
		})
	}
}
