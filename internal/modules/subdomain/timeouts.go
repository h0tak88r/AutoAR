package subdomain

import (
	"os"
	"strconv"
)

// zerodaysTimeout returns the zerodays phase timeout in seconds.
// Override with AUTOAR_TIMEOUT_ZERODAYS env var.
// Set to 0 to disable the cap entirely (useful for large/slow targets).
// Default: 600s (10 minutes).
func zerodaysTimeout() int {
	return envTimeoutOr("AUTOAR_TIMEOUT_ZERODAYS", 600)
}

// nucleiTimeout returns the nuclei phase timeout in seconds.
// Override with AUTOAR_TIMEOUT_NUCLEI env var.
// Set to 0 to disable the cap entirely.
// Default: 1200s (20 minutes).
func nucleiTimeout() int {
	return envTimeoutOr("AUTOAR_TIMEOUT_NUCLEI", 1200)
}

// envTimeoutOr reads an integer env var, returning fallback if unset or invalid.
// A value of "0" disables the timeout (returns 0 → no cap).
func envTimeoutOr(name string, fallback int) int {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return fallback
	}
	return n // 0 means unlimited
}
