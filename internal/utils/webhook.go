package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// scanWebhookQueueSize bounds the scans-channel backlog. A mass-hit scan
// enqueues faster than Discord accepts (~5 posts / 2s per webhook); past this
// depth messages are dropped with a log line instead of piling up goroutines.
const scanWebhookQueueSize = 500

type scanWebhookMsg struct{ url, content string }

var (
	scanWebhookOnce  sync.Once
	scanWebhookQueue = make(chan scanWebhookMsg, scanWebhookQueueSize)
)

// SendWebhook queues a scan-lifecycle/hit message for the scans webhook
// (WEBHOOK_SCANS, falling back to MONITOR_WEBHOOK_URL) if configured.
// The raw senders on this path are scan notifications and scan hits. One
// sender goroutine drains the queue through the chunking, 429-retrying
// postDiscordContent: concurrent hit goroutines used to post in parallel,
// trip Discord's per-webhook rate limit and get dropped, and >2000-char
// messages were rejected outright.
func SendWebhook(msg string) {
	webhookURL := PurposeWebhookURL("scans")
	if webhookURL == "" || strings.TrimSpace(msg) == "" {
		return
	}
	scanWebhookOnce.Do(func() { go scanWebhookSender() })
	select {
	case scanWebhookQueue <- scanWebhookMsg{url: webhookURL, content: msg}:
	default:
		GetLogger().Errorf("[WEBHOOK] scans queue full (%d pending) — dropping message", scanWebhookQueueSize)
	}
}

// scanWebhookSender delivers queued scans-channel messages one at a time.
func scanWebhookSender() {
	for m := range scanWebhookQueue {
		GuardedRun("webhook:scans-sender", func() {
			if err := sendDiscordChunks(m.url, m.content); err != nil {
				GetLogger().Errorf("[WEBHOOK] %v", err)
			}
		})
	}
}

// webhookTokenRE matches the secret token path segment of a Discord (or
// Discord-compatible) webhook URL.
var webhookTokenRE = regexp.MustCompile(`(/api/webhooks/[0-9]+/)[A-Za-z0-9._~-]+`)

// RedactWebhookURL masks webhook tokens inside s (a URL or an error string
// that embeds one, e.g. a *url.Error) so logs never carry a usable webhook.
func RedactWebhookURL(s string) string {
	return webhookTokenRE.ReplaceAllString(s, "${1}[redacted]")
}

// redactedErr wraps a transport error whose text embeds the webhook URL:
// Error() is redacted, Unwrap keeps errors.Is/As working.
type redactedErr struct{ err error }

func (e redactedErr) Error() string { return RedactWebhookURL(e.err.Error()) }
func (e redactedErr) Unwrap() error { return e.err }

// SendScanNotification formats and sends a scan event notification.
func SendScanNotification(event, scanID, target, scanType, status string, findings int) {
	var msg string
	switch event {
	case "start":
		msg = fmt.Sprintf(" **Scan Started**\n**Target:** `%s`\n**Type:** `%s`\n**ID:** `%s`", target, scanType, scanID)
	case "finish", "complete": // scan_runner.go emits "complete"; both mean the scan ended
		resultEmoji := ""
		if status == "failed" {
			resultEmoji = ""
		} else if status == "cancelled" {
			resultEmoji = "⏹"
		} else if status == "timed_out" {
			resultEmoji = "⏱"
		}
		
		findingsStr := "No findings"
		if findings > 0 {
			findingsStr = fmt.Sprintf(" **%d findings discovered**", findings)
		}
		
		msg = fmt.Sprintf("%s **Scan Finished**\n**Target:** `%s`\n**Type:** `%s`\n**Status:** `%s`\n**Result:** %s", 
			resultEmoji, target, scanType, status, findingsStr)
	}

	if msg != "" {
		go SendWebhook(msg)
	}
}

// SendWebhookLog sends a plain text log message to the configured scans
// webhook synchronously and returns the delivery error (nil when no webhook
// is configured).
func SendWebhookLog(msg string) error {
	webhookURL := PurposeWebhookURL("scans")
	if webhookURL == "" {
		return nil
	}
	return sendDiscordChunks(webhookURL, msg)
}

// SendWebhookLogAsync is an asynchronous version of SendWebhookLog.
func SendWebhookLogAsync(msg string) {
	go SendWebhook(msg)
}

// SendWebhookEmbed is a no-op stub — currently not implemented for generic webhooks.
func SendWebhookEmbed(_, _ string, _ int, _ []map[string]any) error { return nil }

// SendWebhookFile is a no-op stub — currently not implemented for generic webhooks.
func SendWebhookFile(_, _ string) error { return nil }

// SendWebhookFileAsync is a no-op stub — currently not implemented for generic webhooks.
func SendWebhookFileAsync(_, _ string) {}

// MonitorWebhookConfigured reports whether any monitoring webhook is set
// (dedicated WEBHOOK_MONITORING or the legacy MONITOR_WEBHOOK_URL fallback).
func MonitorWebhookConfigured() bool {
	return PurposeWebhookURL("monitoring") != ""
}

// SendMonitorWebhook posts msg to MONITOR_WEBHOOK_URL (logs the error on failure).
// Use SendMonitorWebhookErr when the caller needs the delivery error back.
func SendMonitorWebhook(msg string) {
	if err := SendMonitorWebhookErr(msg); err != nil {
		GetLogger().Errorf("[MONITOR] %v", err)
		return
	}
	GetLogger().Info("[MONITOR] Successfully sent monitor webhook alert.")
}

// discordContentLimit is Discord's hard cap on a webhook message's `content`
// field (2000). We chunk to a margin below it so a batched alert (e.g. the
// subdomain monitor listing many changed hosts) doesn't get rejected with a 400
// and silently vanish — which is exactly why bulk subdomain alerts never arrived
// while short per-URL alerts did.
const discordContentLimit = 1900

// PurposeWebhookURL resolves the Discord webhook URL for a purpose:
// "new_scopes" (program/scope announcements), "findings" (AI-validated
// findings), or "monitoring" (everything else). Each checks its dedicated
// key first — WEBHOOK_NEW_SCOPES / WEBHOOK_FINDINGS / WEBHOOK_MONITORING,
// all managed from the Settings page and DB-persisted — and falls back to
// MONITOR_WEBHOOK_URL so a single-channel setup keeps working unchanged.
func PurposeWebhookURL(purpose string) string {
	var dedicated string
	switch strings.ToLower(strings.TrimSpace(purpose)) {
	case "scans":
		dedicated = os.Getenv("WEBHOOK_SCANS")
	case "new_scopes", "scope":
		dedicated = os.Getenv("WEBHOOK_NEW_SCOPES")
	case "findings":
		dedicated = os.Getenv("WEBHOOK_FINDINGS")
	default:
		dedicated = os.Getenv("WEBHOOK_MONITORING")
	}
	if u := strings.TrimSpace(dedicated); u != "" {
		return u
	}
	return strings.TrimSpace(os.Getenv("MONITOR_WEBHOOK_URL"))
}

// SendPurposeWebhookErr posts msg to the webhook configured for the purpose
// (see PurposeWebhookURL) and returns the delivery error.
func SendPurposeWebhookErr(purpose, msg string) error {
	webhookURL := PurposeWebhookURL(purpose)
	if webhookURL == "" {
		return fmt.Errorf("no webhook configured for purpose %q", purpose)
	}
	return sendDiscordChunks(webhookURL, msg)
}

// sendDiscordChunks posts msg as one or more ≤discordContentLimit messages.
func sendDiscordChunks(webhookURL, msg string) error {
	for _, chunk := range chunkDiscordContent(msg, discordContentLimit) {
		if err := postDiscordContent(webhookURL, chunk); err != nil {
			return err
		}
	}
	return nil
}

// SendScopeWebhookErr posts to the new-scopes channel (WEBHOOK_NEW_SCOPES,
// falling back to the monitor webhook). Used by the program/scope watcher.
func SendScopeWebhookErr(msg string) error { return SendPurposeWebhookErr("new_scopes", msg) }

// SendScopeWebhook is the fire-and-forget variant of SendScopeWebhookErr.
func SendScopeWebhook(msg string) { _ = SendScopeWebhookErr(msg) }

// SendFindingsWebhookErr posts to the AI-findings channel (WEBHOOK_FINDINGS,
// falling back to the monitor webhook).
func SendFindingsWebhookErr(msg string) error { return SendPurposeWebhookErr("findings", msg) }

// SendFindingsWebhook is the fire-and-forget variant of SendFindingsWebhookErr.
func SendFindingsWebhook(msg string) { _ = SendFindingsWebhookErr(msg) }

// SendMonitorWebhookErr posts msg to the monitoring webhook and returns the
// delivery error (or a "not configured" error). Messages longer than Discord's
// limit are split into multiple posts so nothing is dropped.
func SendMonitorWebhookErr(msg string) error {
	return SendPurposeWebhookErr("monitoring", msg)
}

// chunkDiscordContent splits content into pieces no larger than max, breaking on
// line boundaries where possible (a single over-long line is hard-split).
func chunkDiscordContent(msg string, max int) []string {
	msg = strings.TrimRight(msg, "\n")
	if msg == "" {
		return nil
	}
	if len(msg) <= max {
		return []string{msg}
	}
	var chunks []string
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			chunks = append(chunks, b.String())
			b.Reset()
		}
	}
	for _, line := range strings.Split(msg, "\n") {
		// Hard-split any single line longer than max (on a rune boundary, so a
		// multi-byte character is never cut into invalid UTF-8).
		for len(line) > max {
			flush()
			cut := max
			for cut > 1 && !utf8.RuneStart(line[cut]) {
				cut--
			}
			chunks = append(chunks, line[:cut])
			line = line[cut:]
		}
		need := len(line)
		if b.Len() > 0 {
			need++ // for the joining newline
		}
		if b.Len()+need > max {
			flush()
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(line)
	}
	flush()
	return chunks
}

// discordPayload builds the webhook body. allowed_mentions {"parse": []}
// disables every mention type: alerts embed untrusted text (template names,
// repo descriptions, program names), and an "@everyone" in any of them must
// never ping the channel.
func discordPayload(content string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"content":          content,
		"allowed_mentions": map[string]any{"parse": []string{}},
	})
}

func postDiscordContent(webhookURL, content string) error {
	jsonData, err := discordPayload(content)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	// Retry on 429 honoring Retry-After. A multi-chunk bulk alert (the subdomain
	// monitor listing many changes) posts chunks back-to-back; Discord rate-limits
	// and returns 429, and previously the caller aborted the loop — silently
	// dropping every remaining chunk. Retrying here keeps the whole alert intact.
	// Transport errors and 5xx get the same bounded retry with a short backoff.
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
		if err != nil {
			return fmt.Errorf("failed to create webhook POST request: %w", redactedErr{err})
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			// *url.Error embeds the full webhook URL (token included) — redact.
			lastErr = fmt.Errorf("failed to send webhook alert: %w", redactedErr{err})
			time.Sleep(time.Duration(attempt+1) * time.Second)
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			wait := parseRetryAfter(resp.Header.Get("Retry-After"))
			resp.Body.Close()
			lastErr = fmt.Errorf("webhook still rate-limited after retries")
			time.Sleep(wait)
			continue
		}
		if resp.StatusCode >= 500 {
			resp.Body.Close()
			lastErr = fmt.Errorf("webhook returned status %d", resp.StatusCode)
			time.Sleep(time.Duration(attempt+1) * time.Second)
			continue
		}
		if resp.StatusCode >= 400 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, RedactWebhookURL(string(b)))
		}
		resp.Body.Close()
		return nil
	}
	return lastErr
}

// parseRetryAfter reads Discord's Retry-After header (seconds, may be fractional),
// clamped to a sane range so a bad value can't stall or busy-loop the sender.
func parseRetryAfter(h string) time.Duration {
	secs, err := strconv.ParseFloat(strings.TrimSpace(h), 64)
	if err != nil || secs <= 0 {
		secs = 1
	}
	if secs > 10 {
		secs = 10
	}
	return time.Duration(secs*1000) * time.Millisecond
}
