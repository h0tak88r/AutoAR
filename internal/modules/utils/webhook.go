package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// SendWebhook sends a generic JSON payload to the MONITOR_WEBHOOK_URL if configured.
func SendWebhook(msg string) {
	webhookURL := strings.TrimSpace(os.Getenv("MONITOR_WEBHOOK_URL"))
	if webhookURL == "" {
		// Fallback to DISCORD_WEBHOOK if MONITOR_WEBHOOK_URL is not set
		webhookURL = strings.TrimSpace(os.Getenv("DISCORD_WEBHOOK"))
	}
	if webhookURL == "" {
		return
	}

	payload := map[string]interface{}{"content": msg}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[WEBHOOK] Failed to marshal payload: %v", err)
		return
	}

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("[WEBHOOK] Failed to create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[WEBHOOK] Failed to send: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		log.Printf("[WEBHOOK] Error %d: %s", resp.StatusCode, string(b))
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

// SendWebhookLog is a no-op stub or fallback — mapping to SendWebhook.
func SendWebhookLog(msg string) error {
	SendWebhook(msg)
	return nil
}

// SendWebhookLogAsync is a no-op stub or fallback — mapping to SendWebhook.
func SendWebhookLogAsync(msg string) {
	go SendWebhook(msg)
}

// SendWebhookEmbed is a no-op stub — currently not implemented for generic webhooks.
func SendWebhookEmbed(_, _ string, _ int, _ []map[string]interface{}) error { return nil }

// SendWebhookFile is a no-op stub — currently not implemented for generic webhooks.
func SendWebhookFile(_, _ string) error { return nil }

// SendWebhookFileAsync is a no-op stub — currently not implemented for generic webhooks.
func SendWebhookFileAsync(_, _ string) {}
