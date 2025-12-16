package s3

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Options for s3 commands
type Options struct {
	Bucket  string
	Root    string
	Region  string
	Action  string // "scan", "enum"
	Verbose bool
}

// Run executes s3 command based on action
func Run(opts Options) error {
	if opts.Action == "" {
		return fmt.Errorf("action is required")
	}

	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "new-results"
	}

	switch opts.Action {
	case "enum":
		return handleEnum(opts, resultsDir)
	case "scan":
		return handleScan(opts, resultsDir)
	default:
		return fmt.Errorf("unknown action: %s", opts.Action)
	}
}

func handleEnum(opts Options, resultsDir string) error {
	if opts.Root == "" {
		return fmt.Errorf("root domain is required for enum action")
	}

	outputDir := filepath.Join(resultsDir, "s3", opts.Root)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	outputFile := filepath.Join(outputDir, "buckets.txt")
	logFile := filepath.Join(outputDir, "enum.log")

	// Use aws cli or s3scanner for enumeration
	// Try s3scanner first, fallback to aws cli
	var cmd *exec.Cmd
	s3scannerPath, err := exec.LookPath("s3scanner")
	if err == nil {
		// Use s3scanner if available
		args := []string{"--no-color"}
		if opts.Verbose {
			args = append(args, "--verbose")
		}
		args = append(args, opts.Root)
		cmd = exec.Command(s3scannerPath, args...)
	} else {
		// Fallback: Use aws cli with common bucket name patterns
		// Generate potential bucket names based on root domain
		bucketPatterns := generateBucketNames(opts.Root)
		
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

		// Check each potential bucket name
		awsPath, err := exec.LookPath("aws")
		if err != nil {
			return fmt.Errorf("neither s3scanner nor aws cli found in PATH")
		}

		for _, bucketName := range bucketPatterns {
			checkCmd := exec.Command(awsPath, "s3", "ls", fmt.Sprintf("s3://%s", bucketName))
			checkCmd.Stdout = outFile
			checkCmd.Stderr = logFileHandle
			if err := checkCmd.Run(); err == nil {
				fmt.Fprintf(outFile, "%s\n", bucketName)
			}
		}

		fmt.Printf("[OK] S3 enumeration completed for %s\n", opts.Root)
		fmt.Printf("[INFO] Results saved to: %s\n", outputFile)
		fmt.Printf("[INFO] Log saved to: %s\n", logFile)
		return nil
	}

	// Execute s3scanner
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
		return fmt.Errorf("s3scanner failed: %v", err)
	}

	fmt.Printf("[OK] S3 enumeration completed for %s\n", opts.Root)
	fmt.Printf("[INFO] Results saved to: %s\n", outputFile)
	fmt.Printf("[INFO] Log saved to: %s\n", logFile)
	return nil
}

func handleScan(opts Options, resultsDir string) error {
	if opts.Bucket == "" {
		return fmt.Errorf("bucket name is required for scan action")
	}

	outputDir := filepath.Join(resultsDir, "s3", opts.Bucket)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	outputFile := filepath.Join(outputDir, "scan-results.txt")
	logFile := filepath.Join(outputDir, "scan.log")

	awsPath, err := exec.LookPath("aws")
	if err != nil {
		return fmt.Errorf("aws cli not found in PATH")
	}

	args := []string{"s3", "ls", fmt.Sprintf("s3://%s", opts.Bucket), "--recursive"}
	if opts.Region != "" {
		args = append(args, "--region", opts.Region)
	}

	cmd := exec.Command(awsPath, args...)

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
		return fmt.Errorf("aws s3 ls failed: %v", err)
	}

	fmt.Printf("[OK] S3 scan completed for bucket: %s\n", opts.Bucket)
	fmt.Printf("[INFO] Results saved to: %s\n", outputFile)
	fmt.Printf("[INFO] Log saved to: %s\n", logFile)
	return nil
}

// generateBucketNames generates potential S3 bucket names from a root domain
func generateBucketNames(root string) []string {
	// Remove common TLDs and clean the domain
	root = strings.ToLower(root)
	root = strings.TrimSuffix(root, ".com")
	root = strings.TrimSuffix(root, ".net")
	root = strings.TrimSuffix(root, ".org")
	root = strings.TrimSuffix(root, ".io")
	
	// Common patterns
	patterns := []string{
		root,
		fmt.Sprintf("%s-backup", root),
		fmt.Sprintf("%s-backups", root),
		fmt.Sprintf("%s-dev", root),
		fmt.Sprintf("%s-development", root),
		fmt.Sprintf("%s-prod", root),
		fmt.Sprintf("%s-production", root),
		fmt.Sprintf("%s-staging", root),
		fmt.Sprintf("%s-test", root),
		fmt.Sprintf("%s-testing", root),
		fmt.Sprintf("%s-www", root),
		fmt.Sprintf("%s-uploads", root),
		fmt.Sprintf("%s-files", root),
		fmt.Sprintf("%s-assets", root),
		fmt.Sprintf("%s-media", root),
		fmt.Sprintf("%s-static", root),
		fmt.Sprintf("%s-public", root),
		fmt.Sprintf("%s-private", root),
		fmt.Sprintf("www.%s", root),
		fmt.Sprintf("s3.%s", root),
		fmt.Sprintf("storage.%s", root),
		fmt.Sprintf("cdn.%s", root),
	}

	return patterns
}
