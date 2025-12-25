package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// SendWebhookLog sends a log message to Discord webhook
func SendWebhookLog(message string) error {
	webhookURL := os.Getenv("DISCORD_WEBHOOK")
	if webhookURL == "" {
		// No webhook configured, skip silently
		return nil
	}

	// Create webhook payload
	payload := map[string]interface{}{
		"content": message,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	// Send HTTP request
	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[WEBHOOK] Failed to send webhook: %v", err)
		return fmt.Errorf("failed to send webhook request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("[WEBHOOK] Webhook returned status %d: %s", resp.StatusCode, string(bodyBytes))
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// SendWebhookLogAsync sends a log message to Discord webhook asynchronously (non-blocking)
func SendWebhookLogAsync(message string) {
	go func() {
		if err := SendWebhookLog(message); err != nil {
			// Log error but don't block
			log.Printf("[WEBHOOK] [ERROR] Failed to send async webhook: %v", err)
		}
	}()
}

// SendWebhookEmbed sends a formatted embed message to Discord webhook
func SendWebhookEmbed(title, description string, color int, fields []map[string]interface{}) error {
	webhookURL := os.Getenv("DISCORD_WEBHOOK")
	if webhookURL == "" {
		return nil
	}

	embed := map[string]interface{}{
		"title":       title,
		"description": description,
		"color":       color,
		"timestamp":   time.Now().Format(time.RFC3339),
	}

	if len(fields) > 0 {
		embed["fields"] = fields
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{embed},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// SendWebhookFile sends a file to Discord webhook
func SendWebhookFile(filePath, description string) error {
	webhookURL := os.Getenv("DISCORD_WEBHOOK")
	if webhookURL == "" {
		// No webhook configured, skip silently
		return nil
	}

	// Check if file exists
	fileInfo, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", filePath)
	} else if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	} else if fileInfo.Size() == 0 {
		return fmt.Errorf("file is empty: %s", filePath)
	}

	// Read file
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Create multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add file
	fileName := filepath.Base(filePath)
	filePart, err := writer.CreateFormFile("file", fileName)
	if err != nil {
		return fmt.Errorf("failed to create form file: %w", err)
	}
	if _, err := filePart.Write(fileData); err != nil {
		return fmt.Errorf("failed to write file data: %w", err)
	}

	// Add description/content
	if description == "" {
		description = fmt.Sprintf("📁 %s", fileName)
	}
	if err := writer.WriteField("content", description); err != nil {
		return fmt.Errorf("failed to write content field: %w", err)
	}

	writer.Close()

	// Send HTTP request
	req, err := http.NewRequest("POST", webhookURL, body)
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[WEBHOOK] Failed to send webhook file: %v", err)
		return fmt.Errorf("failed to send webhook request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("[WEBHOOK] Webhook file returned status %d: %s", resp.StatusCode, string(bodyBytes))
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// SendWebhookFileAsync sends a file to Discord webhook asynchronously (non-blocking)
func SendWebhookFileAsync(filePath, description string) {
	go func() {
		if err := SendWebhookFile(filePath, description); err != nil {
			// Log error but don't block
			log.Printf("[WEBHOOK] [ERROR] Failed to send async webhook file: %v", err)
		}
	}()
}

