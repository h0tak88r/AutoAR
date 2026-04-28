package db

import (
	"fmt"
	"log"
)

// GetSetting retrieves a setting value by key.
// Returns ("", nil) if the key doesn't exist.
func GetSetting(key string) (string, error) {
	if err := Init(); err != nil {
		return "", err
	}
	return dbInstance.GetSetting(key)
}

// SetSetting stores a setting key/value, creating or overwriting it.
func SetSetting(key, value string) error {
	if err := Init(); err != nil {
		return err
	}
	return dbInstance.SetSetting(key, value)
}

// GetAllSettings returns all settings as a key→value map.
func GetAllSettings() (map[string]string, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	return dbInstance.GetAllSettings()
}

// BulkSetSettings stores multiple key/value pairs atomically.
func BulkSetSettings(settings map[string]string) error {
	if err := Init(); err != nil {
		return err
	}
	var lastErr error
	for k, v := range settings {
		if err := dbInstance.SetSetting(k, v); err != nil {
			log.Printf("[WARN] Failed to save setting %s: %v", k, err)
			lastErr = err
		}
	}
	return lastErr
}

// GetSettingOr returns the setting value or the provided default if not found.
func GetSettingOr(key, defaultVal string) string {
	v, err := GetSetting(key)
	if err != nil || v == "" {
		return defaultVal
	}
	return v
}

// GetSettingInt returns the setting value as an integer or the provided default.
func GetSettingInt(key string, defaultVal int) int {
	v, err := GetSetting(key)
	if err != nil || v == "" {
		return defaultVal
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n < 0 {
		return defaultVal
	}
	return n
}
