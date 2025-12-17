package misconfig

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Options for misconfig scan
type Options struct {
	Target    string
	ServiceID string
	Delay     int
	Action    string // "scan", "list", "update", "service"
}

// Run executes misconfig command based on action
func Run(opts Options) error {
	if opts.Action == "" {
		return fmt.Errorf("action is required")
	}

	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "new-results"
	}

	switch opts.Action {
	case "list":
		return handleList()
	case "update":
		return handleUpdate()
	case "scan":
		if opts.Target == "" {
			return fmt.Errorf("target is required for scan action")
		}
		return handleScan(opts, resultsDir)
	case "service":
		if opts.Target == "" || opts.ServiceID == "" {
			return fmt.Errorf("target and service-id are required for service action")
		}
		return handleService(opts, resultsDir)
	default:
		return fmt.Errorf("unknown action: %s", opts.Action)
	}
}

func handleList() error {
	// List available services from misconfig-mapper
	mapperPath, err := exec.LookPath("misconfig-mapper")
	if err != nil {
		return fmt.Errorf("misconfig-mapper not found in PATH: %v", err)
	}

	cmd := exec.Command(mapperPath, "list")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func handleUpdate() error {
	// Update templates
	mapperPath, err := exec.LookPath("misconfig-mapper")
	if err != nil {
		return fmt.Errorf("misconfig-mapper not found in PATH: %v", err)
	}

	cmd := exec.Command(mapperPath, "update")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func handleScan(opts Options, resultsDir string) error {
	mapperPath, err := exec.LookPath("misconfig-mapper")
	if err != nil {
		return fmt.Errorf("misconfig-mapper not found in PATH: %v", err)
	}

	outputDir := filepath.Join(resultsDir, "misconfig", opts.Target)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	outputFile := filepath.Join(outputDir, "scan-results.txt")
	logFile := filepath.Join(outputDir, "scan.log")

	// Build command
	args := []string{"scan", opts.Target}
	if opts.Delay > 0 {
		args = append(args, "--delay", fmt.Sprintf("%d", opts.Delay))
	}
	if opts.ServiceID != "" {
		args = append(args, "--service", opts.ServiceID)
	}

	cmd := exec.Command(mapperPath, args...)
	
	// Open output files
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outFile.Close()

	logFileHandle, err := os.Create(logFile)
	if err != nil {
		return fmt.Errorf("failed to create log file: %v", err)
	}
	defer logFileHandle.Close()

	cmd.Stdout = outFile
	cmd.Stderr = logFileHandle

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("misconfig-mapper scan failed: %v", err)
	}

	fmt.Printf("[OK] Misconfig scan completed for %s\n", opts.Target)
	fmt.Printf("[INFO] Results saved to: %s\n", outputFile)
	fmt.Printf("[INFO] Log saved to: %s\n", logFile)
	return nil
}

func handleService(opts Options, resultsDir string) error {
	mapperPath, err := exec.LookPath("misconfig-mapper")
	if err != nil {
		return fmt.Errorf("misconfig-mapper not found in PATH: %v", err)
	}

	outputDir := filepath.Join(resultsDir, "misconfig", opts.Target)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	outputFile := filepath.Join(outputDir, fmt.Sprintf("service-%s-results.txt", opts.ServiceID))
	logFile := filepath.Join(outputDir, fmt.Sprintf("service-%s.log", opts.ServiceID))

	cmd := exec.Command(mapperPath, "service", opts.Target, opts.ServiceID)
	
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outFile.Close()

	logFileHandle, err := os.Create(logFile)
	if err != nil {
		return fmt.Errorf("failed to create log file: %v", err)
	}
	defer logFileHandle.Close()

	cmd.Stdout = outFile
	cmd.Stderr = logFileHandle

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("misconfig-mapper service scan failed: %v", err)
	}

	fmt.Printf("[OK] Misconfig service scan completed for %s (service: %s)\n", opts.Target, opts.ServiceID)
	fmt.Printf("[INFO] Results saved to: %s\n", outputFile)
	fmt.Printf("[INFO] Log saved to: %s\n", logFile)
	return nil
}
