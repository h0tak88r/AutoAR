package zerodays

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// vulnerable marker response: 207 with all three route-confusion codes, the
// middle one (block_cannot_read) at the spacer position — the desync signature.
const vulnMarkerResp = `{"responses":[` +
	`{"body":{"code":"parse_path_failed"},"status":400},` +
	`{"body":{"code":"block_cannot_read"},"status":401},` +
	`{"body":{"code":"rest_batch_not_allowed"},"status":400},` +
	`{"body":{"code":"rest_batch_not_allowed"},"status":400}]}`

// patched marker response: arrays realigned, so the spacer hits the real posts
// handler (rest_cannot_create) — block_cannot_read is absent.
const patchedMarkerResp = `{"responses":[` +
	`{"body":{"code":"parse_path_failed"},"status":400},` +
	`{"body":{"code":"rest_cannot_create"},"status":401},` +
	`{"body":{"code":"rest_batch_not_allowed"},"status":400},` +
	`{"body":{"code":"rest_batch_not_allowed"},"status":400}]}`

func TestWP2ShellMarkerDiscrimination(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}

	cases := []struct {
		name     string
		status   int
		body     string
		wantVuln bool
	}{
		{"vulnerable", 207, vulnMarkerResp, true},
		{"patched", 207, patchedMarkerResp, false},
		{"not-wordpress-404", 404, "Not Found", false},
		{"wrong-status", 200, vulnMarkerResp, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			ok, status, _, _ := wp2shellMarker(client, srv.URL)
			if ok != tc.wantVuln {
				t.Fatalf("wp2shellMarker(%s) ok=%v; want %v", tc.name, ok, tc.wantVuln)
			}
			if tc.wantVuln && status != 207 {
				t.Fatalf("vulnerable status=%d; want 207", status)
			}
		})
	}
}

func TestCheckWP2ShellReportsFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(207)
		_, _ = w.Write([]byte(vulnMarkerResp))
	}))
	defer srv.Close()

	findings, scanned, err := checkWP2Shell(Options{URLs: []string{srv.URL}, Threads: 2, Silent: true})
	if err != nil {
		t.Fatalf("checkWP2Shell error: %v", err)
	}
	if scanned != 1 {
		t.Fatalf("scanned=%d; want 1", scanned)
	}
	if len(findings) != 1 {
		t.Fatalf("findings=%d; want 1", len(findings))
	}
	if findings[0].Level != "route-confusion" || findings[0].Severity != "high" {
		t.Fatalf("finding level=%q sev=%q; want route-confusion/high", findings[0].Level, findings[0].Severity)
	}
}

func TestCheckWP2ShellSilentOnPatched(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(207)
		_, _ = w.Write([]byte(patchedMarkerResp))
	}))
	defer srv.Close()

	findings, _, err := checkWP2Shell(Options{URLs: []string{srv.URL}, Threads: 2, Silent: true})
	if err != nil {
		t.Fatalf("checkWP2Shell error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("patched host produced %d findings; want 0", len(findings))
	}
}
