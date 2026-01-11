package r2storage

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var (
	r2Client   *s3.Client
	r2Config   *R2Config
	isEnabled  bool
)

// R2Config holds Cloudflare R2 configuration
type R2Config struct {
	Enabled      bool
	BucketName   string
	AccountID    string
	AccessKeyID  string
	SecretKey    string
	PublicURL    string
	Endpoint     string
}

// LoadConfig loads R2 configuration from environment variables
func LoadConfig() *R2Config {
	useR2 := os.Getenv("USE_R2_STORAGE")
	if useR2 != "true" && useR2 != "1" {
		return &R2Config{Enabled: false}
	}

	config := &R2Config{
		Enabled:     true,
		BucketName:  os.Getenv("R2_BUCKET_NAME"),
		AccountID:   os.Getenv("R2_ACCOUNT_ID"),
		AccessKeyID: os.Getenv("R2_ACCESS_KEY_ID"),
		SecretKey:   os.Getenv("R2_SECRET_KEY"),
		PublicURL:   os.Getenv("R2_PUBLIC_URL"),
	}

	// Build R2 endpoint URL
	if config.AccountID != "" {
		config.Endpoint = fmt.Sprintf("https://%s.r2.cloudflarestorage.com", config.AccountID)
	}

	// Validate required fields
	if config.BucketName == "" || config.AccessKeyID == "" || config.SecretKey == "" {
		log.Printf("[R2] ⚠️  R2 storage enabled but missing required configuration")
		config.Enabled = false
		return config
	}

	isEnabled = true
	r2Config = config

	// Initialize R2 client
	if err := initR2Client(); err != nil {
		log.Printf("[R2] ⚠️  Failed to initialize R2 client: %v", err)
		config.Enabled = false
		isEnabled = false
		return config
	}

	log.Printf("[R2] [ + ]R2 storage initialized (bucket: %s)", config.BucketName)
	return config
}

// initR2Client initializes the S3-compatible R2 client
func initR2Client() error {
	if r2Config == nil || !r2Config.Enabled {
		return fmt.Errorf("R2 not enabled or not configured")
	}

	// Create custom resolver for R2 endpoint
	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		if service == s3.ServiceID {
			return aws.Endpoint{
				URL:           r2Config.Endpoint,
				SigningRegion: "auto",
			}, nil
		}
		return aws.Endpoint{}, fmt.Errorf("unknown endpoint requested")
	})

	// Load AWS config with R2 credentials
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithEndpointResolverWithOptions(customResolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			r2Config.AccessKeyID,
			r2Config.SecretKey,
			"",
		)),
		config.WithRegion("auto"),
	)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	r2Client = s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})

	return nil
}

// IsEnabled returns whether R2 storage is enabled
func IsEnabled() bool {
	if r2Config == nil {
		r2Config = LoadConfig()
	}
	return isEnabled && r2Config != nil && r2Config.Enabled
}

// UploadFile uploads a file to R2 and returns the public URL
// If skipTimestamp is true, the file is uploaded without a timestamp prefix (for cache/backups)
func UploadFile(filePath, objectKey string, skipTimestamp bool) (string, error) {
	if !IsEnabled() {
		return "", fmt.Errorf("R2 storage is not enabled")
	}

	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Get file info
	fileInfo, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to stat file: %w", err)
	}

	// If objectKey is empty, use file name
	if objectKey == "" {
		objectKey = filepath.Base(filePath)
	}

	// Ensure objectKey doesn't start with /
	if strings.HasPrefix(objectKey, "/") {
		objectKey = objectKey[1:]
	}

	// Add timestamp prefix only if not skipping (for cache/backups, we want predictable paths)
	if !skipTimestamp {
		timestamp := time.Now().Format("20060102-150405")
		objectKey = fmt.Sprintf("%s/%s", timestamp, objectKey)
	}

	log.Printf("[R2] 📤 Uploading file to R2: %s (%d bytes)", objectKey, fileInfo.Size())

	// Upload file
	_, err = r2Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:        aws.String(r2Config.BucketName),
		Key:           aws.String(objectKey),
		Body:          file,
		ContentLength: aws.Int64(fileInfo.Size()),
		ContentType:   aws.String(getContentType(filePath)),
	})

	if err != nil {
		return "", fmt.Errorf("failed to upload file to R2: %w", err)
	}

	// Generate public URL
	var publicURL string
	if r2Config.PublicURL != "" {
		// Use custom public URL if provided
		publicURL = strings.TrimSuffix(r2Config.PublicURL, "/") + "/" + objectKey
	} else {
		// Use default R2 public URL format
		publicURL = fmt.Sprintf("https://pub-%s.r2.dev/%s", r2Config.AccountID, objectKey)
	}

	log.Printf("[R2] [ + ]File uploaded successfully: %s", publicURL)
	return publicURL, nil
}

// UploadFileWithReader uploads a file from an io.Reader to R2
// If skipTimestamp is true, the file is uploaded without a timestamp prefix (for cache/backups)
func UploadFileWithReader(reader io.Reader, objectKey string, size int64, contentType string, skipTimestamp bool) (string, error) {
	if !IsEnabled() {
		return "", fmt.Errorf("R2 storage is not enabled")
	}

	// Add timestamp prefix only if not skipping
	if !skipTimestamp {
		timestamp := time.Now().Format("20060102-150405")
		if strings.HasPrefix(objectKey, "/") {
			objectKey = objectKey[1:]
		}
		objectKey = fmt.Sprintf("%s/%s", timestamp, objectKey)
	} else {
		if strings.HasPrefix(objectKey, "/") {
			objectKey = objectKey[1:]
		}
	}

	log.Printf("[R2] 📤 Uploading file to R2: %s (%d bytes)", objectKey, size)

	// Upload file
	_, err := r2Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:        aws.String(r2Config.BucketName),
		Key:           aws.String(objectKey),
		Body:          reader,
		ContentLength: aws.Int64(size),
		ContentType:   aws.String(contentType),
	})

	if err != nil {
		return "", fmt.Errorf("failed to upload file to R2: %w", err)
	}

	// Generate public URL
	var publicURL string
	if r2Config.PublicURL != "" {
		publicURL = strings.TrimSuffix(r2Config.PublicURL, "/") + "/" + objectKey
	} else {
		publicURL = fmt.Sprintf("https://pub-%s.r2.dev/%s", r2Config.AccountID, objectKey)
	}

	log.Printf("[R2] [ + ]File uploaded successfully: %s", publicURL)
	return publicURL, nil
}

// UploadDatabaseBackup uploads a database backup file to R2
// Backups are stored in backups/ directory with timestamp for versioning
func UploadDatabaseBackup(dbPath, backupType string) (string, error) {
	if !IsEnabled() {
		return "", fmt.Errorf("R2 storage is not enabled")
	}

	// Create backup filename with timestamp (we want to keep multiple backup versions)
	timestamp := time.Now().Format("20060102-150405")
	backupName := fmt.Sprintf("backups/%s-%s-%s", backupType, timestamp, filepath.Base(dbPath))

	// Use skipTimestamp=false because we want timestamped backups for versioning
	return UploadFile(dbPath, backupName, false)
}

// getContentType determines the content type based on file extension
func getContentType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	contentTypes := map[string]string{
		".json": "application/json",
		".txt":  "text/plain",
		".log":  "text/plain",
		".html": "text/html",
		".xml":  "application/xml",
		".apk":  "application/vnd.android.package-archive",
		".ipa":  "application/octet-stream",
		".zip":  "application/zip",
		".tar":  "application/x-tar",
		".gz":   "application/gzip",
		".db":   "application/x-sqlite3",
		".sql":  "application/sql",
		".pdf":  "application/pdf",
		".png":  "image/png",
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
	}

	if ct, ok := contentTypes[ext]; ok {
		return ct
	}
	return "application/octet-stream"
}

// GetFileSizeLimit returns the file size limit for direct Discord uploads (25MB)
func GetFileSizeLimit() int64 {
	return 25 * 1024 * 1024 // 25MB in bytes
}

// ShouldUseR2 checks if a file should be uploaded to R2 based on size
func ShouldUseR2(filePath string) bool {
	if !IsEnabled() {
		return false
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return false
	}

	// Use R2 for files larger than 20MB (Discord limit is 25MB, but we want some buffer)
	return info.Size() > 20*1024*1024
}

// FileExists checks if a file already exists in R2
func FileExists(objectKey string) (bool, error) {
	if !IsEnabled() {
		return false, fmt.Errorf("R2 storage is not enabled")
	}

	// Ensure objectKey doesn't start with /
	if strings.HasPrefix(objectKey, "/") {
		objectKey = objectKey[1:]
	}

	// Check if file exists
	_, err := r2Client.HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: aws.String(r2Config.BucketName),
		Key:    aws.String(objectKey),
	})

	if err != nil {
		// Check if error indicates file doesn't exist (404)
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "NotFound") || strings.Contains(err.Error(), "NoSuchKey") {
			return false, nil // File doesn't exist, not an error
		}
		return false, err
	}

	return true, nil
}

// FindExistingFile searches for an existing file in R2 by filename (without timestamp)
// Returns the full object key if found, empty string if not found
func FindExistingFile(fileName string) (string, error) {
	if !IsEnabled() {
		return "", fmt.Errorf("R2 storage is not enabled")
	}

	// List objects with the filename
	listInput := &s3.ListObjectsV2Input{
		Bucket: aws.String(r2Config.BucketName),
		Prefix: aws.String(""), // Search all
	}

	paginator := s3.NewListObjectsV2Paginator(r2Client, listInput)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			return "", fmt.Errorf("failed to list R2 objects: %w", err)
		}

		for _, obj := range page.Contents {
			// Check if object key ends with the filename
			if strings.HasSuffix(*obj.Key, "/"+fileName) || *obj.Key == fileName {
				return *obj.Key, nil
			}
		}
	}

	return "", nil // Not found
}

// FindCachedVersion searches R2 for any cached version of a package
// packagePrefix should be like "apkx/cache/com_example_app_"
// Returns the version found (without the package prefix) or empty string
func FindCachedVersion(packagePrefix string) (string, error) {
	if !IsEnabled() {
		return "", fmt.Errorf("R2 storage is not enabled")
	}

	// List objects with the package prefix
	listInput := &s3.ListObjectsV2Input{
		Bucket: aws.String(r2Config.BucketName),
		Prefix: aws.String(packagePrefix),
	}

	paginator := s3.NewListObjectsV2Paginator(r2Client, listInput)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			return "", fmt.Errorf("failed to list R2 objects: %w", err)
		}

		for _, obj := range page.Contents {
			// Check if this is a results.json file
			if strings.HasSuffix(*obj.Key, "/results.json") {
				// Extract version from path
				// Format: apkx/cache/{package}_{version}/results.json
				keyWithoutSuffix := strings.TrimSuffix(*obj.Key, "/results.json")
				parts := strings.Split(keyWithoutSuffix, "/")
				if len(parts) >= 3 {
					cacheKey := parts[len(parts)-1] // Last part is {package}_{version}
					// Extract version (everything after the last underscore)
					// But we need to know the package name to extract version properly
					// So we'll return the full cache key and let the caller extract the version
					// Actually, we can extract it: if packagePrefix is "apkx/cache/com_example_app_"
					// and cacheKey is "com_example_app_7_10", then version is "7_10"
					packagePrefixBase := strings.TrimPrefix(packagePrefix, "apkx/cache/")
					if strings.HasPrefix(cacheKey, packagePrefixBase) {
						version := strings.TrimPrefix(cacheKey, packagePrefixBase)
						// Convert back from filesystem-safe format (7_10 -> 7.10)
						version = strings.ReplaceAll(version, "_", ".")
						return version, nil
					}
				}
			}
		}
	}

	return "", nil // Not found
}

// UploadFileIfNotExists uploads a file only if it doesn't already exist in R2
// Returns the public URL and whether the file was newly uploaded
func UploadFileIfNotExists(filePath, objectKey string) (string, bool, error) {
	if !IsEnabled() {
		return "", false, fmt.Errorf("R2 storage is not enabled")
	}

	// If objectKey is empty, use file name
	if objectKey == "" {
		objectKey = filepath.Base(filePath)
	}

	// Check if file already exists (search by filename)
	existingKey, err := FindExistingFile(filepath.Base(filePath))
	if err == nil && existingKey != "" {
		// File exists, return existing URL
		var publicURL string
		if r2Config.PublicURL != "" {
			publicURL = strings.TrimSuffix(r2Config.PublicURL, "/") + "/" + existingKey
		} else {
			publicURL = fmt.Sprintf("https://pub-%s.r2.dev/%s", r2Config.AccountID, existingKey)
		}
		log.Printf("[R2] [ + ]File already exists in R2: %s", publicURL)
		return publicURL, false, nil
	}

	// File doesn't exist, upload it (use timestamp for regular files)
	publicURL, err := UploadFile(filePath, objectKey, false)
	if err != nil {
		return "", false, err
	}

	return publicURL, true, nil
}

// UploadDirectory uploads an entire directory structure to R2, preserving the directory structure
// basePath is the local base directory, r2Prefix is the R2 prefix (e.g., "apkx/cache/com_example_app_1.0")
// skipTimestamp: if true, files are uploaded without timestamp prefix (for cache/backups)
// Returns map of local file path -> R2 URL
func UploadDirectory(basePath, r2Prefix string, skipTimestamp bool) (map[string]string, error) {
	if !IsEnabled() {
		return nil, fmt.Errorf("R2 storage is not enabled")
	}

	urls := make(map[string]string)

	// Ensure r2Prefix doesn't start with /
	if strings.HasPrefix(r2Prefix, "/") {
		r2Prefix = r2Prefix[1:]
	}
	if !strings.HasSuffix(r2Prefix, "/") && r2Prefix != "" {
		r2Prefix += "/"
	}

	err := filepath.Walk(basePath, func(localPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Calculate relative path from basePath
		relPath, err := filepath.Rel(basePath, localPath)
		if err != nil {
			return err
		}

		// Create R2 object key
		r2Key := r2Prefix + strings.ReplaceAll(relPath, string(filepath.Separator), "/")

		// Upload file (skipTimestamp for cache/backups, use timestamp for regular results)
		publicURL, err := UploadFile(localPath, r2Key, skipTimestamp)
		if err != nil {
			log.Printf("[R2] ⚠️  Failed to upload %s: %v", localPath, err)
			return nil // Continue with other files
		}

		urls[localPath] = publicURL
		log.Printf("[R2] [ + ]Uploaded: %s -> %s", relPath, publicURL)

		return nil
	})

	return urls, err
}

// UploadResultsDirectory uploads the results directory structure to R2 and optionally removes local files
// domain is the domain name (e.g., "example.com"), resultsPath is the full local path to results
// removeLocal: if true, removes local files after successful upload
func UploadResultsDirectory(domain, resultsPath string, removeLocal bool) (map[string]string, error) {
	if !IsEnabled() {
		return nil, fmt.Errorf("R2 storage is not enabled")
	}

	// Create R2 prefix: results/domain/
	r2Prefix := fmt.Sprintf("results/%s", domain)

	log.Printf("[R2] 📤 Uploading results directory to R2: %s -> %s", resultsPath, r2Prefix)

	// Upload directory (use timestamp for regular results to allow multiple versions)
	urls, err := UploadDirectory(resultsPath, r2Prefix, false)
	// Return URLs even if there was an error (e.g., missing file), as long as we have some successful uploads
	if err != nil && len(urls) == 0 {
		return nil, fmt.Errorf("failed to upload directory: %w", err)
	}
	// If we have URLs but also an error, log the error but return the URLs
	if err != nil {
		log.Printf("[R2] ⚠️  Some files failed to upload, but %d files were uploaded successfully", len(urls))
	}

	// Remove local files if requested
	if removeLocal && len(urls) > 0 {
		log.Printf("[R2] 🗑️  Removing local files after successful upload...")
		for localPath := range urls {
			if err := os.Remove(localPath); err != nil {
				log.Printf("[R2] ⚠️  Failed to remove local file %s: %v", localPath, err)
			}
		}
		// Try to remove empty directories
		filepath.Walk(resultsPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				os.Remove(path) // Remove if empty, ignore errors
			}
			return nil
		})
		log.Printf("[R2] [ + ]Local files removed")
	}

	return urls, nil
}

// DownloadDirectory downloads a directory from R2 to a local path
// r2Prefix: R2 object key prefix (e.g., "apkx/cache/com_example_app_1_0")
// localPath: Local directory path to download to
func DownloadDirectory(r2Prefix, localPath string) error {
	if !IsEnabled() {
		return fmt.Errorf("R2 storage is not enabled")
	}

	// Ensure r2Prefix doesn't start with /
	if strings.HasPrefix(r2Prefix, "/") {
		r2Prefix = r2Prefix[1:]
	}
	// Ensure r2Prefix ends with / for prefix matching
	if !strings.HasSuffix(r2Prefix, "/") {
		r2Prefix = r2Prefix + "/"
	}

	log.Printf("[R2] 📥 Downloading directory from R2: %s -> %s", r2Prefix, localPath)

	// Create local directory
	if err := os.MkdirAll(localPath, 0755); err != nil {
		return fmt.Errorf("failed to create local directory: %w", err)
	}

	// List objects with the prefix
	listInput := &s3.ListObjectsV2Input{
		Bucket: aws.String(r2Config.BucketName),
		Prefix: aws.String(r2Prefix),
	}

	downloadedCount := 0
	paginator := s3.NewListObjectsV2Paginator(r2Client, listInput)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			return fmt.Errorf("failed to list R2 objects: %w", err)
		}

		for _, obj := range page.Contents {
			// Get object key relative to prefix
			relativeKey := strings.TrimPrefix(*obj.Key, r2Prefix)
			if relativeKey == "" {
				continue // Skip the prefix itself
			}

			// Build local file path
			localFilePath := filepath.Join(localPath, relativeKey)

			// Create parent directories
			if err := os.MkdirAll(filepath.Dir(localFilePath), 0755); err != nil {
				log.Printf("[R2] ⚠️  Failed to create directory for %s: %v", localFilePath, err)
				continue
			}

			// Download object
			getInput := &s3.GetObjectInput{
				Bucket: aws.String(r2Config.BucketName),
				Key:    obj.Key,
			}

			result, err := r2Client.GetObject(context.TODO(), getInput)
			if err != nil {
				log.Printf("[R2] ⚠️  Failed to download %s: %v", *obj.Key, err)
				continue
			}
			defer result.Body.Close()

			// Create local file
			localFile, err := os.Create(localFilePath)
			if err != nil {
				log.Printf("[R2] ⚠️  Failed to create local file %s: %v", localFilePath, err)
				result.Body.Close()
				continue
			}

			// Copy object content to local file
			if _, err := io.Copy(localFile, result.Body); err != nil {
				log.Printf("[R2] ⚠️  Failed to write to local file %s: %v", localFilePath, err)
				localFile.Close()
				result.Body.Close()
				continue
			}

			localFile.Close()
			result.Body.Close()
			downloadedCount++
		}
	}

	if downloadedCount == 0 {
		return fmt.Errorf("no files found in R2 with prefix %s", r2Prefix)
	}

	log.Printf("[R2] [ + ]Downloaded %d files from R2 to %s", downloadedCount, localPath)
	return nil
}

// ZipAndUploadDirectory creates a zip file of the directory and uploads it to R2
// Returns the public URL of the uploaded zip file
func ZipAndUploadDirectory(domain, dirPath string) (string, error) {
	if !IsEnabled() {
		return "", fmt.Errorf("R2 storage is not enabled")
	}

	// Convert to absolute path to avoid working directory issues
	if absPath, err := filepath.Abs(dirPath); err == nil {
		dirPath = absPath
		log.Printf("[R2] Using absolute path: %s", dirPath)
	}

	// Verify directory exists and has files
	dirInfo, err := os.Stat(dirPath)
	if err != nil {
		return "", fmt.Errorf("directory does not exist: %s: %w", dirPath, err)
	}
	if !dirInfo.IsDir() {
		return "", fmt.Errorf("path is not a directory: %s", dirPath)
	}

	// Count files in directory before creating zip
	fileCount := 0
	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			fileCount++
		}
		return nil
	})
	if err != nil {
		log.Printf("[R2] Warning: error counting files: %v", err)
	}
	log.Printf("[R2] Found %d files in directory: %s", fileCount, dirPath)

	if fileCount == 0 {
		return "", fmt.Errorf("directory is empty: %s", dirPath)
	}

	// Create temporary zip file
	zipFile, err := os.CreateTemp("", fmt.Sprintf("%s-*.zip", domain))
	if err != nil {
		return "", fmt.Errorf("failed to create temp zip file: %w", err)
	}
	zipPath := zipFile.Name()
	zipFile.Close()
	defer os.Remove(zipPath) // Clean up temp file

	// List some files in directory for debugging
	log.Printf("[R2] Checking files in directory: %s", dirPath)
	filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			relPath, _ := filepath.Rel(dirPath, path)
			log.Printf("[R2] Found file: %s (size: %d)", relPath, info.Size())
		}
		return nil
	})

	// Create zip archive
	log.Printf("[R2] Creating zip archive: %s", dirPath)
	if err := createZipArchive(dirPath, zipPath); err != nil {
		return "", fmt.Errorf("failed to create zip archive: %w", err)
	}

	// Get zip file size
	zipInfo, err := os.Stat(zipPath)
	if err != nil {
		return "", fmt.Errorf("failed to stat zip file: %w", err)
	}
	log.Printf("[R2] Zip archive created: %s (%d bytes)", zipPath, zipInfo.Size())

	// Upload zip to R2
	timestamp := time.Now().Format("20060102-150405")
	r2Key := fmt.Sprintf("results/%s/%s-results.zip", domain, timestamp)
	
	publicURL, err := UploadFile(zipPath, r2Key, true) // skipTimestamp=true since we already included it
	if err != nil {
		return "", fmt.Errorf("failed to upload zip file: %w", err)
	}

	log.Printf("[R2] Zip file uploaded: %s", publicURL)
	return publicURL, nil
}

// createZipArchive creates a zip file containing all files in the directory
func createZipArchive(sourceDir, zipPath string) error {
	// Check if source directory exists
	if info, err := os.Stat(sourceDir); err != nil {
		return fmt.Errorf("source directory does not exist: %w", err)
	} else if !info.IsDir() {
		return fmt.Errorf("source path is not a directory: %s", sourceDir)
	}

	zipFile, err := os.Create(zipPath)
	if err != nil {
		return fmt.Errorf("failed to create zip file: %w", err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	fileCount := 0
	// Walk the directory and add all files to the zip
	err = filepath.Walk(sourceDir, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			// Log but continue with other files
			log.Printf("[R2] Warning: error accessing %s: %v", filePath, err)
			return nil
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Calculate relative path from source directory
		relPath, err := filepath.Rel(sourceDir, filePath)
		if err != nil {
			log.Printf("[R2] Warning: failed to get relative path for %s: %v", filePath, err)
			return nil
		}

		// Use forward slashes in zip (zip standard)
		zipEntryPath := strings.ReplaceAll(relPath, string(filepath.Separator), "/")

		// Open the file
		file, err := os.Open(filePath)
		if err != nil {
			log.Printf("[R2] Warning: failed to open file %s: %v", filePath, err)
			return nil
		}
		defer file.Close()

		// Create zip file header
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			log.Printf("[R2] Warning: failed to create zip header for %s: %v", filePath, err)
			return nil
		}
		header.Name = zipEntryPath
		header.Method = zip.Deflate

		// Write file header
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			log.Printf("[R2] Warning: failed to create zip entry for %s: %v", filePath, err)
			return nil
		}

		// Copy file content to zip
		_, err = io.Copy(writer, file)
		if err != nil {
			log.Printf("[R2] Warning: failed to copy file %s to zip: %v", filePath, err)
			return nil
		}

		fileCount++
		return nil
	})

	if err != nil {
		return fmt.Errorf("error walking directory: %w", err)
	}

	if fileCount == 0 {
		return fmt.Errorf("no files found in directory: %s", sourceDir)
	}

	log.Printf("[R2] Added %d files to zip archive", fileCount)
	return nil
}

