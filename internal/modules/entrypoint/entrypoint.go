package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	fmt.Println("[entrypoint] AutoAR starting...")

	// Get the mode from environment variable (default: discord)
	mode := os.Getenv("AUTOAR_MODE")
	if mode == "" {
		mode = "discord"
	}

	fmt.Printf("[entrypoint] Mode: %s\n", mode)

	// Load configuration
	fmt.Println("[entrypoint] Loading configuration...")
	os.Setenv("AUTOAR_ROOT", "/app")
	os.Setenv("AUTOAR_RESULTS_DIR", "/app/new-results")
	os.Setenv("AUTOAR_CONFIG_FILE", "/app/autoar.yaml")
	os.Setenv("AUTOAR_ENV", "docker")
	fmt.Println("[entrypoint] Configuration loaded successfully")
	
	// Debug: Print IPATOOL environment variables (masked for security)
	fmt.Println("[entrypoint] Checking IPATOOL environment variables...")
	if val := os.Getenv("IPATOOL_EMAIL"); val != "" {
		fmt.Printf("[entrypoint] IPATOOL_EMAIL is set (length: %d)\n", len(val))
	} else {
		fmt.Println("[entrypoint] IPATOOL_EMAIL is NOT set")
	}
	if val := os.Getenv("IPATOOL_PASSWORD"); val != "" {
		fmt.Printf("[entrypoint] IPATOOL_PASSWORD is set (length: %d)\n", len(val))
	} else {
		fmt.Println("[entrypoint] IPATOOL_PASSWORD is NOT set")
	}
	if val := os.Getenv("IPATOOL_KEYCHAIN_PASSPHRASE"); val != "" {
		fmt.Printf("[entrypoint] IPATOOL_KEYCHAIN_PASSPHRASE is set (length: %d)\n", len(val))
	} else {
		fmt.Println("[entrypoint] ⚠️  IPATOOL_KEYCHAIN_PASSPHRASE is NOT set - iOS downloads will fail!")
	}
	if val := os.Getenv("IPATOOL_AUTH_CODE"); val != "" {
		fmt.Printf("[entrypoint] IPATOOL_AUTH_CODE is set (length: %d)\n", len(val))
	} else {
		fmt.Println("[entrypoint] IPATOOL_AUTH_CODE is not set (optional)")
	}

	// Initialize database schema (only if database is configured)
	if os.Getenv("DB_HOST") != "" && os.Getenv("DB_USER") != "" {
		fmt.Println("[entrypoint] Initializing database schema")
		cmd := exec.Command("/usr/local/bin/autoar", "db", "init-schema")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = os.Environ()
		if err := cmd.Run(); err != nil {
			fmt.Println("[entrypoint] Database schema initialization completed with warnings")
		} else {
			fmt.Println("[entrypoint] Database schema initialized successfully")
		}
	} else {
		fmt.Println("[entrypoint] Database not configured, skipping schema initialization")
	}

	// Optionally run tool check/installation at container start
	if os.Getenv("RUN_SETUP") == "true" {
		fmt.Println("[entrypoint] RUN_SETUP=true -> executing check-tools (Go)")
		cmd := exec.Command("/usr/local/bin/autoar", "check-tools")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = os.Environ()
		if err := cmd.Run(); err != nil {
			fmt.Println("[entrypoint] check-tools finished with warnings")
		} else {
			fmt.Println("[entrypoint] check-tools completed successfully")
		}
	}

	// Create results dir
	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "/app/new-results"
	}
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		fmt.Printf("[entrypoint] Warning: Failed to create results directory: %v\n", err)
	}

	// Validate mandatory envs and files based on mode
	if mode == "discord" || mode == "both" {
		if os.Getenv("DISCORD_BOT_TOKEN") == "" {
			fmt.Fprintf(os.Stderr, "[entrypoint] Error: DISCORD_BOT_TOKEN is not set (required for discord/both mode)\n")
			os.Exit(1)
		}
	}

	// Check if autoar binary exists
	if _, err := os.Stat("/usr/local/bin/autoar"); err != nil {
		fmt.Fprintf(os.Stderr, "[entrypoint] Error: AutoAR binary not found at /usr/local/bin/autoar\n")
		os.Exit(1)
	}

	// Launch based on mode
	var cmd *exec.Cmd
	switch mode {
	case "discord":
		fmt.Println("[entrypoint] Launching Discord Bot only (Go)...")
		cmd = exec.Command("/usr/local/bin/autoar", "bot")
	case "api":
		fmt.Println("[entrypoint] Launching API Server only (Go)...")
		cmd = exec.Command("/usr/local/bin/autoar", "api")
	case "both":
		fmt.Println("[entrypoint] Launching both Discord Bot and API Server (Go)...")
		cmd = exec.Command("/usr/local/bin/autoar", "both")
	default:
		fmt.Fprintf(os.Stderr, "[entrypoint] Error: Invalid AUTOAR_MODE '%s'\n", mode)
		fmt.Fprintf(os.Stderr, "[entrypoint] Valid modes: discord, api, both\n")
		os.Exit(1)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[entrypoint] Error: %v\n", err)
		os.Exit(1)
	}
}
