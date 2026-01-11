package misconfig

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	mmapi "github.com/h0tak88r/AutoAR/v3/internal/tools/misconfigmapper"
)

// Options for misconfig scan
type Options struct {
	Target        string
	ServiceID     string
	Delay         int
	Action        string // "scan", "list", "update", "service"
	Threads       int    // Concurrency for scanning subdomains
	Timeout       int    // Timeout in seconds
	LiveHostsFile string // Optional: path to live hosts file (avoids enumeration)
	EnablePerms   bool   // Enable permutations (generates many targets, slower but more thorough)
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

	// Get project root directory (where templates/ directory is located)
	root := os.Getenv("AUTOAR_ROOT")
	if root == "" {
		if cwd, err := os.Getwd(); err == nil {
			root = cwd
		} else {
			root = "/app"
		}
	}

	switch opts.Action {
	case "list":
		return handleList(root)
	case "update":
		return handleUpdate(root)
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

func templatesDir(root string) string {
	return filepath.Join(root, "templates")
}

func handleList(root string) error {
	tplDir := templatesDir(root)
	infos, err := mmapi.ListServices(tplDir)
	if err != nil {
		return fmt.Errorf("failed to list misconfig services: %w", err)
	}
	fmt.Println("ID\tService\tName")
	for _, s := range infos {
		fmt.Printf("%d\t%s\t%s\n", s.ID, s.Service, s.ServiceName)
	}
	return nil
}

func handleUpdate(root string) error {
	tplDir := templatesDir(root)
	if err := mmapi.UpdateTemplates(tplDir); err != nil {
		return fmt.Errorf("failed to update misconfig-mapper templates: %w", err)
	}
	fmt.Printf("[OK] Misconfig-mapper templates updated in %s\n", tplDir)
	return nil
}

func handleScan(opts Options, resultsDir string) error {
	// Save results under the target directory
	outputDir := filepath.Join(resultsDir, opts.Target, "misconfig")
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Create file with renamed output for Discord
	outputFile := filepath.Join(outputDir, "misconfig-scan-results.txt")

	root := os.Getenv("AUTOAR_ROOT")
	if root == "" {
		if cwd, err := os.Getwd(); err == nil {
			root = cwd
		} else {
			root = "/app"
		}
	}
	tplDir := templatesDir(root)

	// Extract company name from domain (remove TLD and subdomains)
	// Example: "subdomain.example.com" -> "example", "example.com" -> "example"
	target := opts.Target
	if strings.Contains(target, ".") {
		parts := strings.Split(target, ".")
		// Take the second-to-last part as company name (e.g., "example" from "example.com")
		if len(parts) >= 2 {
			target = parts[len(parts)-2]
		} else {
			target = parts[0]
		}
	}

	log.Printf("[INFO] Scanning for misconfigurations using target: %s (extracted from %s)", target, opts.Target)

	// Set defaults for performance
	delay := opts.Delay
	if delay == 0 {
		delay = 50 // 50ms delay between requests to avoid hammering services
	}
	timeout := 3000 // 3 seconds timeout (reduced from 7 for faster scanning)

	// Run misconfig scan - the original tool handles everything
	// EnablePerms can be enabled via flag for more thorough scanning (generates permutations)
	// AsDomain=false means replace {TARGET} in baseURL (correct for services like {TARGET}.atlassian.net)
	allResults, err := mmapi.Scan(mmapi.ScanOptions{
		Target:        target, // Pass company name, not full domain
		ServiceID:     opts.ServiceID,
		Delay:         delay,
		TemplatesPath: tplDir,
		AsDomain:      false, // false = replace {TARGET} in baseURL (correct for services like {TARGET}.atlassian.net)
		EnablePerms:   opts.EnablePerms, // Use flag value (default: false for speed)
		SkipChecks:    false,
		Timeout:       timeout,
		MaxRedirects:  5,
		SkipSSL:       false,
	})
	if err != nil {
		return fmt.Errorf("failed to scan for misconfigurations: %w", err)
	}

	log.Printf("[OK] Completed misconfig scan")

	// Always write results to file (even if empty)
	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	vulnerableCount := 0
	if len(allResults) > 0 {
		for _, r := range allResults {
			status := "EXISTS"
			if r.Vulnerable {
				status = "VULNERABLE"
				vulnerableCount++
			}
			line := fmt.Sprintf("[%s] %s (%s - %s)\n", status, r.URL, r.ServiceID, r.ServiceName)
			if _, err := f.WriteString(line); err != nil {
				return fmt.Errorf("failed to write result: %w", err)
			}
		}
	} else {
		// Write "no results" message to file
		f.WriteString("No misconfiguration findings found.\n")
	}

	fmt.Printf("[OK] Misconfig scan completed for %s (%d findings)\n", opts.Target, len(allResults))
	fmt.Printf("[INFO] Results saved to: %s\n", outputFile)
	
	// Webhook sending removed - files are sent via utils.SendPhaseFiles from phase functions
	
	return nil
}

func handleService(opts Options, resultsDir string) error {
	// Service-specific scan is just a filtered scan with ServiceID set.
	return handleScan(opts, resultsDir)
}
