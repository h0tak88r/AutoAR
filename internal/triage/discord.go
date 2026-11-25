package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

var sevEmoji = map[string]string{"critical": "🟣", "high": "🔴", "medium": "🟠", "low": "🟡"}

// DiscordMessage renders the alert text for a reportable verdict. Every value
// that came from the target, the template or the model is escaped, so a
// hostile page can't inject mentions or masked links into the channel.
func DiscordMessage(rec *db.TriageRecord, cfg Config) string {
	sev := rec.AISeverity
	if sev == "" || sev == "unknown" {
		sev = rec.Severity
	}
	esc := utils.DiscordEscapeTrunc
	var b strings.Builder
	fmt.Fprintf(&b, "🎯 **AI-validated finding** — %s %s · %s %d%%\n",
		sevEmoji[sev], strings.ToUpper(sev), strings.ReplaceAll(rec.Verdict, "_", " "), rec.Confidence)
	fmt.Fprintf(&b, "**%s**\n", esc(rec.Title, 150))
	fmt.Fprintf(&b, "Host: %s\n", esc(rec.Host, 200))
	fmt.Fprintf(&b, "Matched: %s\n", esc(rec.MatchedAt, 300))
	fmt.Fprintf(&b, "Template: %s\n", esc(rec.TemplateID, 120))
	switch rec.Scope {
	case "in":
		fmt.Fprintf(&b, "Scope: 🟢 in scope — %s\n", esc(rec.ScopeProgram, 120))
	default:
		b.WriteString("Scope: ⚪ unverified — check the program before filing\n")
	}
	fmt.Fprintf(&b, "Why: %s\n", esc(rec.Reason, 600))
	if cfg.DashboardURL != "" {
		fmt.Fprintf(&b, "Dashboard: %s/findings?id=%s · scan %s/scans/%s\n",
			cfg.DashboardURL, url.QueryEscape(rec.ID), cfg.DashboardURL, url.PathEscape(rec.ScanID))
	}
	b.WriteString("📝 Draft report attached — review and confirm scope before submitting.")
	out := b.String()
	if r := []rune(out); len(r) > 1900 {
		out = string(r[:1900]) + "…"
	}
	return out
}

// PostDiscord sends content plus an optional file attachment to a webhook,
// with mentions disabled and one retry on rate limiting.
func PostDiscord(ctx context.Context, webhookURL, content, fileName string, file []byte) error {
	if strings.TrimSpace(webhookURL) == "" {
		return fmt.Errorf("no findings webhook configured (Settings ▸ Notifications)")
	}
	payload, _ := json.Marshal(map[string]any{
		"content":          content,
		"allowed_mentions": map[string]any{"parse": []string{}},
	})
	for attempt := 0; attempt < 2; attempt++ {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		_ = mw.WriteField("payload_json", string(payload))
		if len(file) > 0 {
			fw, err := mw.CreateFormFile("files[0]", fileName)
			if err != nil {
				return err
			}
			_, _ = fw.Write(file)
		}
		_ = mw.Close()

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, &body)
		if err != nil {
			return fmt.Errorf("invalid webhook URL")
		}
		req.Header.Set("Content-Type", mw.FormDataContentType())
		resp, err := discordClient.Do(req)
		if err != nil {
			// *url.Error embeds the webhook URL (and its token) — don't surface it.
			return fmt.Errorf("discord request failed")
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests && attempt == 0 {
			wait := 2 * time.Second
			var rl struct {
				RetryAfter float64 `json:"retry_after"`
			}
			if json.Unmarshal(raw, &rl) == nil && rl.RetryAfter > 0 && rl.RetryAfter < 30 {
				wait = time.Duration(rl.RetryAfter*1000) * time.Millisecond
			} else if s, err := strconv.ParseFloat(resp.Header.Get("Retry-After"), 64); err == nil && s > 0 && s < 30 {
				wait = time.Duration(s*1000) * time.Millisecond
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return fmt.Errorf("discord returned HTTP %d: %s", resp.StatusCode, clip(strings.TrimSpace(string(raw)), 200))
		}
		return nil
	}
	return fmt.Errorf("discord rate limited")
}

var discordClient = &http.Client{Timeout: 30 * time.Second}

// NotifyDiscord is the production Notify dep: it posts to the findings
// channel (WEBHOOK_FINDINGS, falling back to the monitor webhook).
func NotifyDiscord(ctx context.Context, rec *db.TriageRecord, cfg Config) error {
	report := rec.ReportMD
	if report == "" {
		report = "(no report body)"
	}
	return PostDiscord(ctx, utils.PurposeWebhookURL("findings"), DiscordMessage(rec, cfg),
		"report-"+rec.ID+".md", []byte(report))
}
