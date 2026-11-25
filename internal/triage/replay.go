package triage

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/internal/utils"
)

// ReplayResult is what one safe re-check of a hit returned.
type ReplayResult struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	Server      string `json:"server,omitempty"`
	Body        string `json:"body,omitempty"`
	Error       string `json:"error,omitempty"`
}

const replayBodyBytes = 3000

// Replayable reports whether a finding may be re-checked: only HTTP hits whose
// original request was itself a plain GET/HEAD to an http(s) URL. Anything that
// changed state (POST/PUT/...), carried a body, or used another protocol is
// never re-sent.
func Replayable(f Finding) bool {
	if f.Type != "" && f.Type != "http" {
		return false
	}
	u := strings.ToLower(f.MatchedAt)
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return false
	}
	method := ""
	if line, _, _ := strings.Cut(strings.TrimSpace(f.Request), "\n"); line != "" {
		method, _, _ = strings.Cut(line, " ")
	}
	return method == "GET" || method == "HEAD"
}

// SafeReplay re-requests the matched URL once with GET through the
// SSRF-guarded client. It returns nil when the finding isn't Replayable.
func SafeReplay(ctx context.Context, f Finding) *ReplayResult {
	if !Replayable(f) {
		return nil
	}
	if err := utils.ValidatePublicHTTPURL(f.MatchedAt); err != nil {
		return &ReplayResult{Error: "not replayed: " + err.Error()}
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.MatchedAt, nil)
	if err != nil {
		return &ReplayResult{Error: err.Error()}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; AutoAR-triage)")
	resp, err := utils.NewPublicHTTPClient(20 * time.Second).Do(req)
	if err != nil {
		return &ReplayResult{Error: clip(err.Error(), 300)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, replayBodyBytes))
	return &ReplayResult{
		Status:      resp.StatusCode,
		ContentType: clip(resp.Header.Get("Content-Type"), 120),
		Server:      clip(resp.Header.Get("Server"), 120),
		Body:        string(body),
	}
}
