package utils

import "os"

// GetEnv is a helper to read an environment variable or return a fallback.
func GetEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
