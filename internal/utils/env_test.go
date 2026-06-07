package utils

import (
	"os"
	"testing"
)

func TestGetEnv(t *testing.T) {
	const testKey = "AUTOAR_TEST_ENV_VAR_12345"
	const fallback = "fallback_value"

	// Ensure the key is not set before testing
	os.Unsetenv(testKey)

	if got := GetEnv(testKey, fallback); got != fallback {
		t.Errorf("GetEnv(unset, %q) = %q, want %q", fallback, got, fallback)
	}

	os.Setenv(testKey, "custom_value")
	defer os.Unsetenv(testKey)

	if got := GetEnv(testKey, fallback); got != "custom_value" {
		t.Errorf("GetEnv(set, %q) = %q, want %q", fallback, got, "custom_value")
	}

	// Empty string in env should fall back
	os.Setenv(testKey, "")
	if got := GetEnv(testKey, fallback); got != fallback {
		t.Errorf("GetEnv(empty, %q) = %q, want %q", fallback, got, fallback)
	}
}
