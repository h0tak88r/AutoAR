package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// SendWebhook sends a generic JSON payload to the MONITOR_WEBHOOK_URL if configured.
func SendWebhook(msg string) {
	webhookURL := strings.TrimSpace(os.Getenv("MONITOR_WEBHOOK_URL"))
	if webhookURL == "" {
		return
	}

	payload := map[string]any{"content": msg}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		GetLogger().Errorf("[WEBHOOK] Failed to marshal payload: %v", err)
		return
	}

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		GetLogger().Errorf("[WEBHOOK] Failed to create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		GetLogger().Errorf("[WEBHOOK] Failed to send: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		GetLogger().Errorf("[WEBHOOK] Error %d: %s", resp.StatusCode, string(b))
	}
}

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

// SendWebhookLog sends a plain text log message to the configured webhook.
func SendWebhookLog(msg string) error {
	SendWebhook(msg)
	return nil
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
		// Hard-split any single line longer than max.
		for len(line) > max {
			flush()
			chunks = append(chunks, line[:max])
			line = line[max:]
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

func postDiscordContent(webhookURL, content string) error {
	payload := map[string]any{"content": content}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	// Retry on 429 honoring Retry-After. A multi-chunk bulk alert (the subdomain
	// monitor listing many changes) posts chunks back-to-back; Discord rate-limits
	// and returns 429, and previously the caller aborted the loop — silently
	// dropping every remaining chunk. Retrying here keeps the whole alert intact.
	for attempt := 0; attempt < 4; attempt++ {
		req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
		if err != nil {
			return fmt.Errorf("failed to create webhook POST request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to send webhook alert: %w", err)
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			wait := parseRetryAfter(resp.Header.Get("Retry-After"))
			resp.Body.Close()
			time.Sleep(wait)
			continue
		}
		if resp.StatusCode >= 400 {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(b))
		}
		resp.Body.Close()
		return nil
	}
	return fmt.Errorf("webhook still rate-limited after retries")
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
