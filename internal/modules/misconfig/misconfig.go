package misconfig

import (
	"fmt"
	"os"
	"path/filepath"

	mmapi "github.com/h0tak88r/AutoAR/internal/tools/misconfigmapper"
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
		return handleList(resultsDir)
	case "update":
		return handleUpdate(resultsDir)
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
	outputDir := filepath.Join(resultsDir, "misconfig", opts.Target)
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	outputFile := filepath.Join(outputDir, "scan-results.txt")

	root := os.Getenv("AUTOAR_ROOT")
	if root == "" {
		if cwd, err := os.Getwd(); err == nil {
			root = cwd
		} else {
			root = "/app"
		}
	}
	tplDir := templatesDir(root)

	results, err := mmapi.Scan(mmapi.ScanOptions{
		Target:        opts.Target,
		ServiceID:     opts.ServiceID,
		Delay:         opts.Delay,
		TemplatesPath: tplDir,
	})
	if err != nil {
		return fmt.Errorf("misconfig-mapper scan failed: %w", err)
	}

	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	for _, r := range results {
		status := "EXISTS"
		if r.Vulnerable {
			status = "VULNERABLE"
		}
		line := fmt.Sprintf("[%s] %s (%s - %s)\n", status, r.URL, r.ServiceID, r.ServiceName)
		if _, err := f.WriteString(line); err != nil {
			return fmt.Errorf("failed to write result: %w", err)
		}
	}

	fmt.Printf("[OK] Misconfig scan completed for %s (%d findings)\n", opts.Target, len(results))
	fmt.Printf("[INFO] Results saved to: %s\n", outputFile)
	return nil
}

func handleService(opts Options, resultsDir string) error {
	// Service-specific scan is just a filtered scan with ServiceID set.
	return handleScan(opts, resultsDir)
}
