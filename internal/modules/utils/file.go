package utils

import (
	"os"
	"path/filepath"
	"strings"
)

// WriteLines writes lines to a file (one per line)
// Creates parent directories if they don't exist
func WriteLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data := strings.Join(lines, "\n")
	if len(lines) > 0 {
		data += "\n"
	}
	return os.WriteFile(path, []byte(data), 0644)
}

// ReadLines reads lines from a file
func ReadLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	// Remove empty last line if present
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines, nil
}
