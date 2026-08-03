package main

import (
	"fmt"
	"os"
	"os/exec"
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
