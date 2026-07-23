package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	fmt.Println("[entrypoint] AutoAR starting...")

	mode := os.Getenv("AUTOAR_MODE")
	if mode == "" {
		mode = "api"
	}

	fmt.Printf("[entrypoint] Mode: %s\n", mode)

	fmt.Println("[entrypoint] Loading configuration...")
	os.Setenv("AUTOAR_ROOT", "/app")
	os.Setenv("AUTOAR_RESULTS_DIR", "/app/new-results")
	os.Setenv("AUTOAR_CONFIG_FILE", "/app/autoar.yaml")
	os.Setenv("AUTOAR_ENV", "docker")
	fmt.Println("[entrypoint] Configuration loaded successfully")

	// ipatool (iOS .ipa downloads) is OPTIONAL — only relevant if the operator
	// configured IPATOOL_* credentials. Don't emit a scary "iOS downloads will
	// fail" error line when the feature is simply unused (the common case).
	switch {
	case os.Getenv("IPATOOL_EMAIL") == "" && os.Getenv("IPATOOL_KEYCHAIN_PASSPHRASE") == "":
		fmt.Println("[entrypoint] ipatool (iOS downloads) not configured — optional, skipping")
	case os.Getenv("IPATOOL_EMAIL") != "" && os.Getenv("IPATOOL_PASSWORD") != "" && os.Getenv("IPATOOL_KEYCHAIN_PASSPHRASE") != "":
		fmt.Println("[entrypoint] ipatool (iOS downloads) configured")
	default:
		fmt.Println("[entrypoint] ipatool partially configured — set IPATOOL_EMAIL, IPATOOL_PASSWORD and IPATOOL_KEYCHAIN_PASSPHRASE to enable iOS downloads")
	}

	fmt.Println("[entrypoint] Database schema initialization delegated to API/Bot startup")

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

	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "/app/new-results"
	}
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		fmt.Printf("[entrypoint] Warning: Failed to create results directory: %v\n", err)
	}

	if strings.TrimSpace(os.Getenv("APKX_WORKERS")) == "" {
		_ = os.Setenv("APKX_WORKERS", "2")
		fmt.Println("[entrypoint] APKX_WORKERS not set; defaulting to 2 for stability")
	}

	if _, err := os.Stat("/usr/local/bin/autoar"); err != nil {
		fmt.Fprintf(os.Stderr, "[entrypoint] Error: AutoAR binary not found at /usr/local/bin/autoar\n")
		os.Exit(1)
	}

	var cmd *exec.Cmd
	switch mode {
	case "api", "discord", "both":
		fmt.Println("[entrypoint] Launching API Server...")
		cmd = exec.Command("/usr/local/bin/autoar", "api")
	default:
		fmt.Fprintf(os.Stderr, "[entrypoint] Error: Invalid AUTOAR_MODE '%s'\n", mode)
		fmt.Fprintf(os.Stderr, "[entrypoint] Valid modes: api\n")
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
