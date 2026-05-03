package utils

import "os"

// GetEnv retrieves the value of the environment variable named by the key.
// It returns the value, which will be the fallback if the variable is not set.
func GetEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
