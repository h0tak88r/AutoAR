package utils

import (
	"os"
	"path/filepath"
	"strings"
)

// GetAutoarScriptPath returns the path to the autoar binary
func GetAutoarScriptPath() string {
	if p := os.Getenv("AUTOAR_SCRIPT_PATH"); p != "" {
		return p
	}
	// Try current directory
	if cwd, err := os.Getwd(); err == nil {
		path := filepath.Join(cwd, "autoar")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	// Default to /usr/local/bin/autoar (Docker path)
	return "/usr/local/bin/autoar"
}

// ExtractFirstHTTPURL extracts the first http(s) URL from a string
func ExtractFirstHTTPURL(s string) string {
	idx := strings.Index(s, "http")
	if idx == -1 {
		return ""
	}
	end := strings.IndexAny(s[idx:], " \n\t\r\"'")
	if end == -1 {
		return s[idx:]
	}
	return s[idx : idx+end]
}

// ExtractR2ZipURLFromOutput extracts the R2 zip URL from scan output
func ExtractR2ZipURLFromOutput(output string) string {
	if len(output) == 0 {
		return ""
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "Results zip uploaded:") ||
			strings.Contains(line, "Zip file uploaded:") {
			if u := ExtractFirstHTTPURL(line); u != "" {
				return u
			}
		}
	}
	return ""
}
