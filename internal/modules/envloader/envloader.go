package envloader

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadEnv loads environment variables from a .env file
// It looks for .env in the current directory or project root
func LoadEnv() error {
	// Try to find .env file
	envPath := findEnvFile()
	if envPath == "" {
		// No .env file found, that's okay - use environment variables directly
		return nil
	}

	file, err := os.Open(envPath)
	if err != nil {
		return fmt.Errorf("failed to open .env file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=VALUE
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue // Skip malformed lines
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes if present
		if len(value) >= 2 {
			if (strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`)) ||
				(strings.HasPrefix(value, `'`) && strings.HasSuffix(value, `'`)) {
				value = value[1 : len(value)-1]
			}
		}

		// Always set from .env file (override any existing environment variables)
		// This ensures .env file is the source of truth
		os.Setenv(key, value)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading .env file: %w", err)
	}

	return nil
}

// findEnvFile looks for .env file in current directory and parent directories
func findEnvFile() string {
	// Try current directory first
	cwd, err := os.Getwd()
	if err == nil {
		envPath := filepath.Join(cwd, ".env")
		if _, err := os.Stat(envPath); err == nil {
			return envPath
		}
	}

	// Try executable directory
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		envPath := filepath.Join(exeDir, ".env")
		if _, err := os.Stat(envPath); err == nil {
			return envPath
		}
	}

	// Try parent directories (up to 3 levels)
	if cwd != "" {
		dir := cwd
		for i := 0; i < 3; i++ {
			envPath := filepath.Join(dir, ".env")
			if _, err := os.Stat(envPath); err == nil {
				return envPath
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break // Reached root
			}
			dir = parent
		}
	}

	return ""
}
