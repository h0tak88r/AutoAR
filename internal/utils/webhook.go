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
		msg = fmt.Sprintf("🚀 **Scan Started**\n**Target:** `%s`\n**Type:** `%s`\n**ID:** `%s`", target, scanType, scanID)
	case "finish":
		resultEmoji := "✅"
		if status == "failed" {
			resultEmoji = "❌"
		} else if status == "cancelled" {
			resultEmoji = "⏹️"
		}
		
		findingsStr := "No findings"
		if findings > 0 {
			findingsStr = fmt.Sprintf("🛡️ **%d findings discovered**", findings)
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

// SendMonitorWebhook sends an alert to the MONITOR_WEBHOOK_URL if configured.
func SendMonitorWebhook(msg string) {
	webhookURL := strings.TrimSpace(os.Getenv("MONITOR_WEBHOOK_URL"))
	if webhookURL == "" {
		return
	}

	payload := map[string]any{"content": msg}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		GetLogger().Errorf("[MONITOR] Failed to marshal webhook payload: %v", err)
		return
	}

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		GetLogger().Errorf("[MONITOR] Failed to create webhook POST request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		GetLogger().Errorf("[MONITOR] Failed to send webhook alert: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		GetLogger().Errorf("[MONITOR] Webhook returned status %d: %s", resp.StatusCode, string(b))
	} else {
		GetLogger().Info("[MONITOR] Successfully sent monitor webhook alert.")
	}
}
