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
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/modules/envloader"
)

var (
	envLoadedOnce sync.Once
)

// ensureEnvLoaded ensures .env file is loaded (only once)
func ensureEnvLoaded() {
	envLoadedOnce.Do(func() {
		if err := envloader.LoadEnv(); err != nil {
			log.Printf("[WEBHOOK] [WARN] Failed to load .env file: %v", err)
		}
	})
}

// getWebhookURL gets the webhook URL from environment, loading .env if needed
func getWebhookURL() string {
	ensureEnvLoaded()
	return os.Getenv("DISCORD_WEBHOOK")
}

// SendWebhookLog sends a log message to Discord webhook with rate limit handling
func SendWebhookLog(message string) error {
	webhookURL := getWebhookURL()
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

	// Retry logic for rate limiting
	maxRetries := 3
	for attempt := 0; attempt < maxRetries; attempt++ {
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

		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// Handle rate limiting (429)
		if resp.StatusCode == http.StatusTooManyRequests {
			var rateLimitResp struct {
				RetryAfter float64 `json:"retry_after"`
			}
			if err := json.Unmarshal(bodyBytes, &rateLimitResp); err == nil && rateLimitResp.RetryAfter > 0 {
				waitTime := time.Duration(rateLimitResp.RetryAfter*1000) * time.Millisecond
				if waitTime < 100*time.Millisecond {
					waitTime = 100 * time.Millisecond // Minimum 100ms
				}
				if waitTime > 5*time.Second {
					waitTime = 5 * time.Second // Maximum 5s
				}
				log.Printf("[WEBHOOK] Rate limited, waiting %v before retry (attempt %d/%d)", waitTime, attempt+1, maxRetries)
				time.Sleep(waitTime)
				continue // Retry
			}
			// If we can't parse retry_after, wait a default amount
			if attempt < maxRetries-1 {
				waitTime := time.Duration(attempt+1) * 500 * time.Millisecond
				log.Printf("[WEBHOOK] Rate limited, waiting %v before retry (attempt %d/%d)", waitTime, attempt+1, maxRetries)
				time.Sleep(waitTime)
				continue
			}
		}

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
			return nil
		}

		// For other errors, don't retry
		log.Printf("[WEBHOOK] Webhook returned status %d: %s", resp.StatusCode, string(bodyBytes))
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return fmt.Errorf("webhook rate limited after %d retries", maxRetries)
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
	webhookURL := getWebhookURL()
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

// SendWebhookFile sends a file to Discord webhook with rate limit handling
func SendWebhookFile(filePath, description string) error {
	webhookURL := getWebhookURL()
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

	fileName := filepath.Base(filePath)
	
	// Retry logic for rate limiting
	maxRetries := 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		// Create multipart form
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		// Add file
		filePart, err := writer.CreateFormFile("file", fileName)
		if err != nil {
			writer.Close()
			return fmt.Errorf("failed to create form file: %w", err)
		}
		if _, err := filePart.Write(fileData); err != nil {
			writer.Close()
			return fmt.Errorf("failed to write file data: %w", err)
		}

		// Add description/content (simplified to just file name)
		if description == "" {
			description = fileName
		}
		if err := writer.WriteField("content", description); err != nil {
			writer.Close()
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

		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// Handle rate limiting (429)
		if resp.StatusCode == http.StatusTooManyRequests {
			var rateLimitResp struct {
				RetryAfter float64 `json:"retry_after"`
			}
			if err := json.Unmarshal(bodyBytes, &rateLimitResp); err == nil && rateLimitResp.RetryAfter > 0 {
				waitTime := time.Duration(rateLimitResp.RetryAfter*1000) * time.Millisecond
				if waitTime < 100*time.Millisecond {
					waitTime = 100 * time.Millisecond // Minimum 100ms
				}
				if waitTime > 5*time.Second {
					waitTime = 5 * time.Second // Maximum 5s
				}
				log.Printf("[WEBHOOK] Rate limited, waiting %v before retry (attempt %d/%d)", waitTime, attempt+1, maxRetries)
				time.Sleep(waitTime)
				continue // Retry
			}
			// If we can't parse retry_after, wait a default amount
			if attempt < maxRetries-1 {
				waitTime := time.Duration(attempt+1) * 500 * time.Millisecond
				log.Printf("[WEBHOOK] Rate limited, waiting %v before retry (attempt %d/%d)", waitTime, attempt+1, maxRetries)
				time.Sleep(waitTime)
				continue
			}
		}

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
			return nil
		}

		// For other errors, don't retry
		log.Printf("[WEBHOOK] Webhook file returned status %d: %s", resp.StatusCode, string(bodyBytes))
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return fmt.Errorf("webhook rate limited after %d retries", maxRetries)
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

