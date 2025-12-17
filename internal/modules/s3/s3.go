package s3

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
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

	// Use s3scanner if available, otherwise fallback to AWS SDK enumeration
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
		// Fallback: use AWS SDK with common bucket name patterns
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

		ctx := context.Background()
		s3Client, err := newS3Client(ctx, opts.Region)
		if err != nil {
			return fmt.Errorf("failed to create S3 client: %v", err)
		}

		for _, bucketName := range bucketPatterns {
			_, err := s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
				Bucket: aws.String(bucketName),
			})
			if err == nil {
				// Bucket exists and is reachable with current credentials
				if _, werr := fmt.Fprintf(outFile, "%s\n", bucketName); werr != nil {
					return fmt.Errorf("failed to write bucket name: %v", werr)
				}
			} else if opts.Verbose {
				fmt.Fprintf(logFileHandle, "bucket %s: %v\n", bucketName, err)
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

	ctx := context.Background()
	s3Client, err := newS3Client(ctx, opts.Region)
	if err != nil {
		return fmt.Errorf("failed to create S3 client: %v", err)
	}

	paginator := s3.NewListObjectsV2Paginator(s3Client, &s3.ListObjectsV2Input{
		Bucket: aws.String(opts.Bucket),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			fmt.Fprintf(logFileHandle, "error listing objects: %v\n", err)
			return fmt.Errorf("failed to list objects: %w", err)
		}
		for _, obj := range page.Contents {
			t := aws.ToTime(obj.LastModified)
			line := fmt.Sprintf("%s %12d %s\n", t.Format("2006-01-02 15:04:05"), obj.Size, aws.ToString(obj.Key))
			if _, err := outFile.WriteString(line); err != nil {
				return fmt.Errorf("failed to write output: %w", err)
			}
		}
	}

	fmt.Printf("[OK] S3 scan completed for bucket: %s\n", opts.Bucket)
	fmt.Printf("[INFO] Results saved to: %s\n", outputFile)
	fmt.Printf("[INFO] Log saved to: %s\n", logFile)
	return nil
}

// newS3Client creates an S3 client using default AWS configuration and
// optionally overrides the region if provided.
func newS3Client(ctx context.Context, region string) (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	if region != "" {
		cfg.Region = region
	}
	return s3.NewFromConfig(cfg), nil
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
