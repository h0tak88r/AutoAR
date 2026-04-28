package utils

import (
	"log"
	"os"
	"strconv"
)

// GetTimeout returns the configured timeout for a scan phase key.
//
// Resolution order (first non-empty / non-negative wins):
//  1. DB settings table  (key = "timeout_<key>")  — set via the dashboard Settings page
//  2. Environment variable  (AUTOAR_TIMEOUT_<KEY>)  — set in .env / Docker
//  3. defaultVal  — compile-time fallback
//
// A value of 0 disables the timeout entirely (RunWorkflowPhase cap = 0 means unlimited).
// A negative value is ignored and falls through to the next source.
//
// dbGetSetting is injected so this package doesn't import db (avoid circular deps).
// Call InitTimeoutDB once at startup to wire it up.
var dbGetSetting func(key string) (string, error)

// InitTimeoutDB wires the DB lookup so GetTimeout can read from the settings table.
// Call this from main/gobot after the DB is initialised.
func InitTimeoutDB(fn func(key string) (string, error)) {
	dbGetSetting = fn
}

// GetTimeout resolves a timeout for the given logical key (e.g. "nuclei", "backup", "zerodays").
func GetTimeout(key string, defaultVal int) int {
	envKey := "AUTOAR_TIMEOUT_" + upperKey(key)
	dbKey := "timeout_" + lowerKey(key)

	// 1. DB settings (survives redeployments)
	if dbGetSetting != nil {
		if v, err := dbGetSetting(dbKey); err == nil && v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				return n
			}
		}
	}

	// 2. Environment variable
	if v := os.Getenv(envKey); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
		log.Printf("[WARN] Invalid value for %s: %q — using default %d", envKey, v, defaultVal)
	}

	// 3. Hardcoded default
	return defaultVal
}

func upperKey(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

func lowerKey(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
