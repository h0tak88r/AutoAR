package s3

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/sa7mon/s3scanner/bucket"
	"github.com/sa7mon/s3scanner/provider"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
)

// Options for s3 commands
type Options struct {
	Bucket   string
	Root     string
	Region   string
	Action   string // "scan", "enum"
	Verbose  bool
	Threads  int    // Number of concurrent threads for enumeration (default: 50)
	Subdomain string // Subdomain for directory structure (optional)
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

// bucketResult holds the result of testing a single bucket
type bucketResult struct {
	bucketName string
	found      bool
	url        string
}

func handleEnum(opts Options, resultsDir string) error {
	if opts.Root == "" {
		return fmt.Errorf("root domain is required for enum action")
	}

	// Use Subdomain for directory structure if provided, otherwise use root domain
	var outputDir string
	if opts.Subdomain != "" {
		outputDir = filepath.Join(resultsDir, opts.Subdomain, "s3")
	} else {
		outputDir = filepath.Join(resultsDir, "s3", opts.Root)
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	outputFile := filepath.Join(outputDir, "buckets.txt")
	logFile := filepath.Join(outputDir, "enum.log")

	log.Printf("[INFO] S3 enumeration: Starting enumeration for root domain: %s", opts.Root)
	log.Printf("[INFO] S3 enumeration: Output directory: %s", outputDir)
	log.Printf("[INFO] S3 enumeration: Results will be saved to: %s", outputFile)

	// Use S3Scanner package for enumeration
	log.Printf("[INFO] S3 enumeration: Using S3Scanner package for enumeration")
	
	// Generate bucket name patterns
	bucketPatterns := generateBucketNames(opts.Root)
	log.Printf("[INFO] S3 enumeration: Generated %d bucket name patterns to test", len(bucketPatterns))
	
	// Create output files
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

	// Create S3Scanner provider (AWS by default)
	storageProvider, err := provider.NewProvider("aws")
	if err != nil {
		return fmt.Errorf("failed to create S3Scanner provider: %w", err)
	}

	// Set up threading
	threads := opts.Threads
	if threads <= 0 {
		threads = 50 // Default to 50 concurrent requests
	}
	log.Printf("[INFO] S3 enumeration: Using %d concurrent threads for bucket testing", threads)

	// Create channels for bucket processing
	bucketsChan := make(chan bucket.Bucket, threads)
	var wg sync.WaitGroup
	var mu sync.Mutex
	foundCount := 0

	// Start worker goroutines using S3Scanner worker
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Process buckets using S3Scanner worker
			for b := range bucketsChan {
				// Check if bucket exists
				result, err := storageProvider.BucketExists(&b)
				if err != nil {
					if opts.Verbose {
						fmt.Fprintf(logFileHandle, "[ERROR] Error checking bucket %s: %v\n", b.Name, err)
					}
					continue
				}

				// Scan permissions
				scanErr := storageProvider.Scan(result, false)
				if scanErr != nil && opts.Verbose {
					fmt.Fprintf(logFileHandle, "[WARN] Error scanning bucket %s: %v\n", result.Name, scanErr)
				}

				// Write results
				if result.Exists == bucket.BucketExists {
					mu.Lock()
					if _, werr := fmt.Fprintf(outFile, "%s\n", result.Name); werr != nil {
						mu.Unlock()
						log.Printf("[ERROR] Failed to write bucket name: %v", werr)
						continue
					}
					fmt.Fprintf(logFileHandle, "[OK] Found bucket: %s (region: %s)\n", result.Name, result.Region)
					log.Printf("[OK] S3 enumeration: Found bucket: %s (region: %s)", result.Name, result.Region)
					foundCount++
					mu.Unlock()
				} else if opts.Verbose {
					fmt.Fprintf(logFileHandle, "[INFO] Bucket %s: does not exist\n", result.Name)
				}
			}
		}()
	}

	// Send bucket names to workers
	go func() {
		for _, bucketName := range bucketPatterns {
			b := bucket.NewBucket(bucketName)
			bucketsChan <- b
		}
		close(bucketsChan)
	}()

	// Wait for all workers to complete
	wg.Wait()

	log.Printf("[INFO] S3 enumeration: Found %d bucket(s) out of %d tested", foundCount, len(bucketPatterns))
	fmt.Printf("[OK] S3 enumeration completed for %s\n", opts.Root)
	fmt.Printf("[INFO] Buckets found: %d out of %d tested\n", foundCount, len(bucketPatterns))
	fmt.Printf("[INFO] Results saved to: %s\n", outputFile)
	fmt.Printf("[INFO] Log saved to: %s\n", logFile)
	
	// Note: Webhook sending is handled by the calling workflow (subdomain/domain)
	// Only send webhooks if NOT called from a workflow (check for workflow indicator)
	// When called from workflow, the workflow's SendPhaseFiles will handle webhook messages
	if os.Getenv("AUTOAR_CURRENT_CHANNEL_ID") == "" && os.Getenv("AUTOAR_CURRENT_SCAN_ID") == "" {
		// Standalone mode - send webhooks directly
		if foundCount > 0 {
			log.Printf("[INFO] S3 enumeration: Sending results to Discord webhook (if configured)")
			utils.SendWebhookFileAsync(outputFile, fmt.Sprintf("S3 Enumeration Results - %s (%d buckets found)", opts.Root, foundCount))
			utils.SendWebhookLogAsync(fmt.Sprintf("[ + ]S3 enumeration completed for: `%s`\n**Buckets found:** %d out of %d tested", opts.Root, foundCount, len(bucketPatterns)))
		} else {
			log.Printf("[INFO] S3 enumeration: No buckets found, sending status message to Discord webhook (if configured)")
			utils.SendWebhookLogAsync(fmt.Sprintf("[-] S3 enumeration completed for: `%s`\n**Buckets found:** 0 out of %d tested", opts.Root, len(bucketPatterns)))
		}
	}
	
	log.Printf("[OK] S3 enumeration completed for %s (results: %s, log: %s)", opts.Root, outputFile, logFile)
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

	log.Printf("[INFO] S3 scan: Starting scan for bucket: %s", opts.Bucket)
	log.Printf("[INFO] S3 scan: Output directory: %s", outputDir)
	log.Printf("[INFO] S3 scan: Results will be saved to: %s", outputFile)
	utils.SendWebhookLogAsync(fmt.Sprintf("🔍 Starting S3 scan for bucket: `%s`", opts.Bucket))

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
	log.Printf("[INFO] S3 scan: AWS credentials available: %v", hasCredentials)
	fmt.Fprintf(logFileHandle, "[INFO] S3 scan: AWS credentials available: %v\n", hasCredentials)
	
	scanSuccess := false
	objectCount := 0
	var scanMethod string
	
	if hasCredentials {
		// Try authenticated scan
		log.Printf("[INFO] S3 scan: Attempting authenticated scan using AWS SDK")
		fmt.Fprintf(logFileHandle, "[INFO] Attempting authenticated scan using AWS SDK\n")
		ctx := context.Background()
		s3Client, err := newS3Client(ctx, opts.Region)
		if err == nil {
			log.Printf("[INFO] S3 scan: Authenticated S3 client created successfully")
			fmt.Fprintf(logFileHandle, "[INFO] Using authenticated S3 client for scanning\n")
			paginator := s3.NewListObjectsV2Paginator(s3Client, &s3.ListObjectsV2Input{
				Bucket: aws.String(opts.Bucket),
			})

			pageCount := 0
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					log.Printf("[WARN] S3 scan: Authenticated scan failed on page %d: %v", pageCount+1, err)
					fmt.Fprintf(logFileHandle, "[WARN] Authenticated scan failed on page %d: %v, falling back to unauthenticated testing\n", pageCount+1, err)
					break
				}
				pageCount++
				log.Printf("[INFO] S3 scan: Processing page %d (found %d objects so far)", pageCount, objectCount)
				
				for _, obj := range page.Contents {
					t := aws.ToTime(obj.LastModified)
					line := fmt.Sprintf("%s %12d %s\n", t.Format("2006-01-02 15:04:05"), obj.Size, aws.ToString(obj.Key))
					if _, err := outFile.WriteString(line); err != nil {
						return fmt.Errorf("failed to write output: %w", err)
					}
					objectCount++
					if objectCount%100 == 0 {
						log.Printf("[INFO] S3 scan: Processed %d objects...", objectCount)
					}
				}
				scanSuccess = true
			}
			
			if scanSuccess {
				scanMethod = "authenticated"
				log.Printf("[OK] S3 scan: Authenticated scan completed successfully - found %d object(s)", objectCount)
				fmt.Fprintf(logFileHandle, "[OK] Authenticated scan completed - found %d object(s)\n", objectCount)
			}
		} else {
			log.Printf("[WARN] S3 scan: Failed to create authenticated client: %v", err)
			fmt.Fprintf(logFileHandle, "[WARN] Failed to create authenticated client: %v, falling back to unauthenticated testing\n", err)
		}
	}

	// Fallback to unauthenticated HTTP testing if no credentials or authenticated scan failed
	if !hasCredentials || !scanSuccess {
		if !hasCredentials {
			log.Printf("[INFO] S3 scan: No AWS credentials found, using unauthenticated HTTP testing")
			fmt.Fprintf(logFileHandle, "[INFO] No AWS credentials found, using unauthenticated HTTP testing\n")
		} else {
			log.Printf("[INFO] S3 scan: Authenticated scan failed, trying unauthenticated HTTP testing")
			fmt.Fprintf(logFileHandle, "[INFO] Authenticated scan failed, trying unauthenticated HTTP testing\n")
		}
		fmt.Printf("[INFO] Testing bucket %s without authentication (public access check)...\n", opts.Bucket)
		
		regions := []string{"us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"}
		if opts.Region != "" {
			regions = []string{opts.Region}
		}
		log.Printf("[INFO] S3 scan: Testing %d region(s) for public access", len(regions))
		
		var foundURL string
		totalURLsTested := 0
		for _, region := range regions {
			urls := []string{
				fmt.Sprintf("https://%s.s3.amazonaws.com/?list-type=2", opts.Bucket),
				fmt.Sprintf("https://%s.s3-%s.amazonaws.com/?list-type=2", opts.Bucket, region),
				fmt.Sprintf("https://s3.amazonaws.com/%s/?list-type=2", opts.Bucket),
				fmt.Sprintf("https://s3-%s.amazonaws.com/%s/?list-type=2", region, opts.Bucket),
			}
			
			log.Printf("[INFO] S3 scan: Testing region %s (%d URL format(s))", region, len(urls))
			for _, testURL := range urls {
				totalURLsTested++
				log.Printf("[DEBUG] S3 scan: Testing URL: %s", testURL)
				if objects := scanBucketPublicAccess(testURL, opts.Bucket, outFile, logFileHandle); len(objects) > 0 {
					foundURL = testURL
					objectCount = len(objects)
					scanMethod = "unauthenticated (public)"
					log.Printf("[OK] S3 scan: Found publicly accessible bucket via %s - %d object(s)", testURL, len(objects))
					fmt.Fprintf(logFileHandle, "[OK] Found publicly accessible bucket via %s - %d object(s)\n", testURL, len(objects))
					break
				}
			}
			if foundURL != "" {
				break
			}
		}
		
		if foundURL == "" {
			log.Printf("[WARN] S3 scan: Bucket %s is not publicly accessible or does not exist (tested %d URL(s))", opts.Bucket, totalURLsTested)
			fmt.Fprintf(logFileHandle, "[INFO] Bucket %s is not publicly accessible or does not exist (tested %d URL(s))\n", opts.Bucket, totalURLsTested)
			fmt.Printf("[WARN] Could not access bucket %s without authentication. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY for authenticated access.\n", opts.Bucket)
			scanMethod = "none (not accessible)"
		}
	}

	// Check if results file has content
	fileInfo, err := os.Stat(outputFile)
	hasResults := err == nil && fileInfo.Size() > 0

	// Note: Webhook sending is handled by the calling workflow (subdomain/domain)
	// Only send webhooks if NOT called from a workflow (check for workflow indicator)
	// When called from workflow, the workflow's SendPhaseFiles will handle webhook messages
	if os.Getenv("AUTOAR_CURRENT_CHANNEL_ID") == "" && os.Getenv("AUTOAR_CURRENT_SCAN_ID") == "" {
		// Standalone mode - send webhooks directly
		if hasResults {
			log.Printf("[INFO] S3 scan: Sending results to Discord webhook (if configured)")
			utils.SendWebhookFileAsync(outputFile, fmt.Sprintf("S3 Scan Results - %s (%s, %d objects)", opts.Bucket, scanMethod, objectCount))
			utils.SendWebhookLogAsync(fmt.Sprintf("[ + ]S3 scan completed for bucket: `%s`\n**Method:** %s\n**Objects found:** %d", opts.Bucket, scanMethod, objectCount))
		} else {
			log.Printf("[INFO] S3 scan: No results found, sending status message to Discord webhook (if configured)")
			utils.SendWebhookLogAsync(fmt.Sprintf("[-] S3 scan completed for bucket: `%s`\n**Method:** %s\n**Objects found:** 0", opts.Bucket, scanMethod))
		}
	}

	fmt.Printf("[OK] S3 scan completed for bucket: %s\n", opts.Bucket)
	fmt.Printf("[INFO] Scan method: %s\n", scanMethod)
	fmt.Printf("[INFO] Objects found: %d\n", objectCount)
	fmt.Printf("[INFO] Results saved to: %s\n", outputFile)
	fmt.Printf("[INFO] Log saved to: %s\n", logFile)
	log.Printf("[OK] S3 scan completed for bucket: %s (method: %s, objects: %d, results: %s, log: %s)", opts.Bucket, scanMethod, objectCount, outputFile, logFile)
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
		log.Printf("[DEBUG] S3 scan: Failed to create request for %s: %v", url, err)
		return nil
	}
	
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[DEBUG] S3 scan: Request failed for %s: %v", url, err)
		return nil
	}
	defer resp.Body.Close()
	
	log.Printf("[DEBUG] S3 scan: Response status for %s: %d", url, resp.StatusCode)
	
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	
	// Parse XML response (S3 ListObjectsV2 XML format)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[WARN] S3 scan: Failed to read response body for %s: %v", url, err)
		return nil
	}
	
	// Parse XML response (S3 ListBucketResult XML format)
	// Look for <Contents> blocks with <Key>, <LastModified>, and <Size>
	var objects []string
	bodyStr := string(body)
	
	// Split by <Contents> to process each object
	contents := strings.Split(bodyStr, "<Contents>")
	log.Printf("[DEBUG] S3 scan: Found %d object entry(ies) in XML response", len(contents)-1)
	
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
		log.Printf("[OK] S3 scan: Found %d publicly accessible object(s) in bucket %s via %s", len(objects), bucketName, url)
		fmt.Fprintf(logFile, "[OK] Found %d publicly accessible objects in bucket %s via %s\n", len(objects), bucketName, url)
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
