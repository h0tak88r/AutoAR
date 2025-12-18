package s3

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

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
		// Fallback: use AWS SDK or unauthenticated HTTP testing
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

		// Check if credentials are available
		hasCredentials := os.Getenv("AWS_ACCESS_KEY_ID") != "" && os.Getenv("AWS_SECRET_ACCESS_KEY") != ""
		
		if hasCredentials {
			// Try authenticated enumeration
			ctx := context.Background()
			s3Client, err := newS3Client(ctx, opts.Region)
			if err == nil {
				fmt.Fprintf(logFileHandle, "[INFO] Using authenticated S3 client for enumeration\n")
				for _, bucketName := range bucketPatterns {
					_, err := s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
						Bucket: aws.String(bucketName),
					})
					if err == nil {
						// Bucket exists and is reachable with current credentials
						if _, werr := fmt.Fprintf(outFile, "%s\n", bucketName); werr != nil {
							return fmt.Errorf("failed to write bucket name: %v", werr)
						}
						fmt.Fprintf(logFileHandle, "[OK] Found bucket (authenticated): %s\n", bucketName)
					} else if opts.Verbose {
						fmt.Fprintf(logFileHandle, "bucket %s: %v\n", bucketName, err)
					}
				}
			} else {
				fmt.Fprintf(logFileHandle, "[WARN] Authenticated client failed: %v, falling back to unauthenticated testing\n", err)
				hasCredentials = false
			}
		}

		// If no credentials or authenticated test failed, try unauthenticated HTTP testing
		if !hasCredentials {
			fmt.Fprintf(logFileHandle, "[INFO] No AWS credentials found, using unauthenticated HTTP testing\n")
			fmt.Printf("[INFO] Testing buckets without authentication (public access check)...\n")
			
			regions := []string{"us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"}
			if opts.Region != "" {
				regions = []string{opts.Region}
			}
			
			for _, bucketName := range bucketPatterns {
				found := false
				for _, region := range regions {
					// Test different S3 endpoint formats
					urls := []string{
						fmt.Sprintf("https://%s.s3.amazonaws.com/", bucketName),
						fmt.Sprintf("https://%s.s3-%s.amazonaws.com/", bucketName, region),
						fmt.Sprintf("https://s3.amazonaws.com/%s/", bucketName),
						fmt.Sprintf("https://s3-%s.amazonaws.com/%s/", region, bucketName),
						fmt.Sprintf("http://%s.s3.amazonaws.com/", bucketName),
						fmt.Sprintf("http://%s.s3-%s.amazonaws.com/", bucketName, region),
					}
					
					for _, testURL := range urls {
						if testBucketPublicAccess(testURL, bucketName) {
							if _, werr := fmt.Fprintf(outFile, "%s\n", bucketName); werr != nil {
								return fmt.Errorf("failed to write bucket name: %v", werr)
							}
							fmt.Fprintf(logFileHandle, "[OK] Found publicly accessible bucket: %s (via %s)\n", bucketName, testURL)
							found = true
							break
						}
					}
					if found {
						break
					}
				}
				if !found && opts.Verbose {
					fmt.Fprintf(logFileHandle, "[INFO] Bucket %s: not publicly accessible\n", bucketName)
				}
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

		// Check if credentials are available
		hasCredentials := os.Getenv("AWS_ACCESS_KEY_ID") != "" && os.Getenv("AWS_SECRET_ACCESS_KEY") != ""
		scanSuccess := false
		
		if hasCredentials {
			// Try authenticated scan
			ctx := context.Background()
			s3Client, err := newS3Client(ctx, opts.Region)
			if err == nil {
				fmt.Fprintf(logFileHandle, "[INFO] Using authenticated S3 client for scanning\n")
				paginator := s3.NewListObjectsV2Paginator(s3Client, &s3.ListObjectsV2Input{
					Bucket: aws.String(opts.Bucket),
				})

				objectCount := 0
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil {
						fmt.Fprintf(logFileHandle, "[WARN] Authenticated scan failed: %v, falling back to unauthenticated testing\n", err)
						break
					}
					for _, obj := range page.Contents {
						t := aws.ToTime(obj.LastModified)
						line := fmt.Sprintf("%s %12d %s\n", t.Format("2006-01-02 15:04:05"), obj.Size, aws.ToString(obj.Key))
						if _, err := outFile.WriteString(line); err != nil {
							return fmt.Errorf("failed to write output: %w", err)
						}
						objectCount++
					}
					scanSuccess = true
				}
				
				if scanSuccess {
					fmt.Printf("[OK] S3 scan completed for bucket: %s (authenticated, found objects)\n", opts.Bucket)
					fmt.Printf("[INFO] Results saved to: %s\n", outputFile)
					fmt.Printf("[INFO] Log saved to: %s\n", logFile)
					return nil
				}
			} else {
				fmt.Fprintf(logFileHandle, "[WARN] Failed to create authenticated client: %v, falling back to unauthenticated testing\n", err)
			}
		}

	// Fallback to unauthenticated HTTP testing if no credentials or authenticated scan failed
	if !hasCredentials || !scanSuccess {
		if !hasCredentials {
			fmt.Fprintf(logFileHandle, "[INFO] No AWS credentials found, using unauthenticated HTTP testing\n")
		} else {
			fmt.Fprintf(logFileHandle, "[INFO] Authenticated scan failed, trying unauthenticated HTTP testing\n")
		}
		fmt.Printf("[INFO] Testing bucket %s without authentication (public access check)...\n", opts.Bucket)
		
		regions := []string{"us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"}
		if opts.Region != "" {
			regions = []string{opts.Region}
		}
		
		var foundURL string
		for _, region := range regions {
			urls := []string{
				fmt.Sprintf("https://%s.s3.amazonaws.com/?list-type=2", opts.Bucket),
				fmt.Sprintf("https://%s.s3-%s.amazonaws.com/?list-type=2", opts.Bucket, region),
				fmt.Sprintf("https://s3.amazonaws.com/%s/?list-type=2", opts.Bucket),
				fmt.Sprintf("https://s3-%s.amazonaws.com/%s/?list-type=2", region, opts.Bucket),
			}
			
			for _, testURL := range urls {
				if objects := scanBucketPublicAccess(testURL, opts.Bucket, outFile, logFileHandle); len(objects) > 0 {
					foundURL = testURL
					break
				}
			}
			if foundURL != "" {
				break
			}
		}
		
		if foundURL == "" {
			fmt.Fprintf(logFileHandle, "[INFO] Bucket %s is not publicly accessible or does not exist\n", opts.Bucket)
			fmt.Printf("[WARN] Could not access bucket %s without authentication. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY for authenticated access.\n", opts.Bucket)
		}
	}

	fmt.Printf("[OK] S3 scan completed for bucket: %s\n", opts.Bucket)
	fmt.Printf("[INFO] Results saved to: %s\n", outputFile)
	fmt.Printf("[INFO] Log saved to: %s\n", logFile)
	return nil
}

// newS3Client creates an S3 client using AWS configuration.
// It prioritizes environment variables and disables IMDS when not on EC2.
func newS3Client(ctx context.Context, region string) (*s3.Client, error) {
	// Check if credentials are provided via environment variables
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	
	// Disable IMDS to avoid 404 errors when not running on EC2
	// This prevents the SDK from trying to use EC2 instance metadata
	if os.Getenv("AWS_EC2_METADATA_DISABLED") == "" {
		os.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	}
	
	var cfg aws.Config
	var err error
	
	if accessKey != "" && secretKey != "" {
		// Use explicit credentials from environment variables
		cfg, err = config.LoadDefaultConfig(ctx,
			config.WithCredentialsProvider(aws.NewCredentialsCache(
				aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
					return aws.Credentials{
						AccessKeyID:     accessKey,
						SecretAccessKey: secretKey,
						SessionToken:    os.Getenv("AWS_SESSION_TOKEN"), // Optional
					}, nil
				}),
			)),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to load AWS config with explicit credentials: %w", err)
		}
	} else {
		// Try default config (will check shared credentials file, etc.)
		cfg, err = config.LoadDefaultConfig(ctx)
		if err != nil {
			// Check if error is related to IMDS/EC2
			errStr := err.Error()
			if strings.Contains(errStr, "IMDS") || 
			   strings.Contains(errStr, "EC2") || 
			   strings.Contains(errStr, "getToken") ||
			   strings.Contains(errStr, "GetMetadata") ||
			   strings.Contains(errStr, "no EC2 IMDS role found") {
				return nil, fmt.Errorf("AWS credentials not found. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables in Dokploy. IMDS is disabled in Docker environments")
			}
			return nil, fmt.Errorf("failed to load AWS config: %w", err)
		}
	}
	
	// Set region
	if region != "" {
		cfg.Region = region
	} else if cfg.Region == "" {
		// Use default region from environment or fallback
		if envRegion := os.Getenv("AWS_DEFAULT_REGION"); envRegion != "" {
			cfg.Region = envRegion
		} else {
			cfg.Region = "us-east-1" // Default fallback
		}
	}
	
	return s3.NewFromConfig(cfg), nil
}

// testBucketPublicAccess tests if an S3 bucket is publicly accessible via HTTP
func testBucketPublicAccess(url, bucketName string) bool {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	// Check for successful responses (200, 403 means bucket exists but not public, 404 means doesn't exist)
	// 200 or certain error responses indicate the bucket exists
	if resp.StatusCode == http.StatusOK {
		return true
	}
	
	// Sometimes 403 with specific error codes means bucket exists
	if resp.StatusCode == http.StatusForbidden {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		bodyStr := string(body)
		// If we get an AWS error XML, the bucket exists (just not public)
		if strings.Contains(bodyStr, "AccessDenied") || strings.Contains(bodyStr, "InvalidAccessKeyId") {
			return false // Bucket exists but not public
		}
	}
	
	return false
}

// scanBucketPublicAccess attempts to list objects in a publicly accessible S3 bucket via HTTP
func scanBucketPublicAccess(url, bucketName string, outFile *os.File, logFile *os.File) []string {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	
	// Parse XML response (S3 ListObjectsV2 XML format)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	
	// Parse XML response (S3 ListBucketResult XML format)
	// Look for <Contents> blocks with <Key>, <LastModified>, and <Size>
	var objects []string
	bodyStr := string(body)
	
	// Split by <Contents> to process each object
	contents := strings.Split(bodyStr, "<Contents>")
	for i := 1; i < len(contents); i++ {
		content := contents[i]
		
		// Extract Key
		keyStart := strings.Index(content, "<Key>")
		keyEnd := strings.Index(content, "</Key>")
		if keyStart == -1 || keyEnd == -1 || keyEnd <= keyStart {
			continue
		}
		key := strings.TrimSpace(content[keyStart+5 : keyEnd])
		
		// Extract LastModified
		modStart := strings.Index(content, "<LastModified>")
		modEnd := strings.Index(content, "</LastModified>")
		lastModified := ""
		if modStart != -1 && modEnd != -1 && modEnd > modStart {
			lastModified = strings.TrimSpace(content[modStart+14 : modEnd])
		}
		
		// Extract Size
		sizeStart := strings.Index(content, "<Size>")
		sizeEnd := strings.Index(content, "</Size>")
		size := "0"
		if sizeStart != -1 && sizeEnd != -1 && sizeEnd > sizeStart {
			size = strings.TrimSpace(content[sizeStart+6 : sizeEnd])
		}
		
		objects = append(objects, key)
		
		// Format: timestamp size key (matching authenticated format)
		line := fmt.Sprintf("%s %12s %s\n", lastModified, size, key)
		if _, err := outFile.WriteString(line); err == nil {
			fmt.Fprintf(logFile, "[OK] Found object: %s (size: %s, modified: %s)\n", key, size, lastModified)
		}
	}
	
	if len(objects) > 0 {
		fmt.Fprintf(logFile, "[OK] Found %d publicly accessible objects in bucket %s\n", len(objects), bucketName)
	}
	
	return objects
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
