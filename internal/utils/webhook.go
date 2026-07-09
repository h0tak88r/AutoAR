package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
	case "finish":
		resultEmoji := ""
		if status == "failed" {
			resultEmoji = ""
		} else if status == "cancelled" {
			resultEmoji = "⏹"
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

// MonitorWebhookConfigured reports whether MONITOR_WEBHOOK_URL is set.
func MonitorWebhookConfigured() bool {
	return strings.TrimSpace(os.Getenv("MONITOR_WEBHOOK_URL")) != ""
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

// SendMonitorWebhookErr posts msg to MONITOR_WEBHOOK_URL and returns the delivery
// error (or a "not configured" error). Messages longer than Discord's limit are
// split into multiple posts so nothing is dropped.
func SendMonitorWebhookErr(msg string) error {
	webhookURL := strings.TrimSpace(os.Getenv("MONITOR_WEBHOOK_URL"))
	if webhookURL == "" {
		return fmt.Errorf("MONITOR_WEBHOOK_URL is not set")
	}
	for _, chunk := range chunkDiscordContent(msg, discordContentLimit) {
		if err := postDiscordContent(webhookURL, chunk); err != nil {
			return err
		}
	}
	return nil
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

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create webhook POST request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook alert: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}
