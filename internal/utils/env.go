package utils

import (
	"os"
	"strings"
	"unicode"
)

// GetEnv retrieves the value of the environment variable named by the key.
// It returns the value, which will be the fallback if the variable is not set.
func GetEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

// ParseKeyList splits a raw multi-key setting (comma, semicolon, newline, or
// whitespace separated) into a clean, deduplicated list of keys. Surrounding
// quotes are stripped so values pasted from YAML/JSON still parse.
func ParseKeyList(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || unicode.IsSpace(r)
	})
	seen := make(map[string]bool, len(fields))
	keys := make([]string, 0, len(fields))
	for _, f := range fields {
		k := strings.Trim(strings.TrimSpace(f), `"'`)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		keys = append(keys, k)
	}
	return keys
}
