package livehosts

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/h0tak88r/AutoAR/gomodules/db"
	"github.com/h0tak88r/AutoAR/gomodules/subdomains"
	"github.com/h0tak88r/AutoAR/gomodules/utils"
)

// Result holds summary information for a livehosts run
type Result struct {
	Domain       string
	Threads      int
	TotalSubs    int
	LiveSubs     int
	SubsFile     string
	LiveSubsFile string
}

// FilterLiveHosts ensures subdomains exist for a domain and filters live hosts using httpx.
// It mirrors the behaviour of modules/livehosts.sh but implemented in Go.
func FilterLiveHosts(domain string, threads int, silent bool) (*Result, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	if threads <= 0 {
		threads = 100
	}

	// Initialize results directory structure
	domainDir, err := utils.DomainDirInit(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to init domain dir: %v", err)
	}

	subsDir := filepath.Join(domainDir, "subs")
	if err := utils.EnsureDir(subsDir); err != nil {
		return nil, fmt.Errorf("failed to ensure subs dir: %v", err)
	}

	subsFile := filepath.Join(subsDir, "all-subs.txt")
	liveFile := filepath.Join(subsDir, "live-subs.txt")

	// 1. Ensure subdomains exist (reuse Go subdomains module)
	totalSubs, err := ensureSubdomains(domain, threads, subsFile)
	if err != nil {
		return nil, err
	}

	// 2. Run httpx to filter live hosts
	liveCount, err := runHTTPX(domain, threads, subsFile, liveFile)
	if err != nil {
		return nil, err
	}

	log.Printf("[OK] Found %d live subdomains out of %d for %s", liveCount, totalSubs, domain)

	// 3. Update database with live host information (optional but desirable)
	if liveCount > 0 {
		if err := updateDatabase(domain, liveFile); err != nil {
			log.Printf("[WARN] Failed to update database with live hosts for %s: %v", domain, err)
		}
	}

	return &Result{
		Domain:       domain,
		Threads:      threads,
		TotalSubs:    totalSubs,
		LiveSubs:     liveCount,
		SubsFile:     subsFile,
		LiveSubsFile: liveFile,
	}, nil
}

// ensureSubdomains loads or re-generates subdomains for a domain.
// It returns the total number of subdomains.
func ensureSubdomains(domain string, threads int, subsFile string) (int, error) {
	// If file exists and has enough subdomains, reuse it
	if info, err := os.Stat(subsFile); err == nil && info.Size() > 0 {
		count, err := countLines(subsFile)
		if err == nil {
			log.Printf("[INFO] Using existing subdomains from %s (%d subdomains)", subsFile, count)
			// If very few, treat as potentially stale and re-enumerate
			if count >= 5 {
				return count, nil
			}
			log.Printf("[WARN] Very few subdomains found (%d), re-enumerating...", count)
		}
	}

	log.Printf("[INFO] Collecting subdomains for %s", domain)
	results, err := subdomains.EnumerateSubdomains(domain, threads)
	if err != nil {
		return 0, fmt.Errorf("failed to enumerate subdomains: %v", err)
	}

	// Write to file
	if err := writeLines(subsFile, results); err != nil {
		return 0, fmt.Errorf("failed to write subdomains file: %v", err)
	}

	total := len(results)
	log.Printf("[OK] Found %d unique subdomains for %s", total, domain)

	// Save to database if configured
	if os.Getenv("DB_HOST") != "" {
		if err := db.Init(); err == nil {
			// Ignore InitSchema errors here; it is already handled at startup
			_ = db.InitSchema()
			if err := db.BatchInsertSubdomains(domain, results, false); err != nil {
				log.Printf("[WARN] Failed to save subdomains to database: %v", err)
			}
		} else {
			log.Printf("[WARN] Database initialization failed, skipping subdomains save: %v", err)
		}
	}

	return total, nil
}

// runHTTPX executes httpx against the subdomains file and writes live hosts to liveFile.
// It returns the number of live hosts.
func runHTTPX(domain string, threads int, subsFile, liveFile string) (int, error) {
	if _, err := os.Stat(subsFile); err != nil {
		return 0, fmt.Errorf("subdomains file not found: %s", subsFile)
	}

	if _, err := exec.LookPath("httpx"); err != nil {
		log.Printf("[WARN] httpx not found in PATH, creating empty live hosts file")
		// Create empty file
		if err := writeLines(liveFile, nil); err != nil {
			return 0, fmt.Errorf("failed to create empty live hosts file: %v", err)
		}
		return 0, nil
	}

	log.Printf("[INFO] Filtering live hosts via httpx with %d threads", threads)

	// Open subs file as stdin
	subs, err := os.Open(subsFile)
	if err != nil {
		return 0, fmt.Errorf("failed to open subdomains file: %v", err)
	}
	defer subs.Close()

	cmd := exec.Command("httpx", "-silent", "-nc", "-threads", strconv.Itoa(threads), "-o", liveFile)
	cmd.Stdin = subs
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// httpx may exit non-zero for some URLs; treat as warning but continue
		log.Printf("[WARN] httpx finished with error: %v", err)
	}

	liveCount, err := countLines(liveFile)
	if err != nil {
		return 0, fmt.Errorf("failed to count live hosts: %v", err)
	}

	return liveCount, nil
}

// updateDatabase marks live hosts in the subdomains table using InsertSubdomain.
func updateDatabase(domain, liveFile string) error {
	if os.Getenv("DB_HOST") == "" {
		return nil
	}

	if err := db.Init(); err != nil {
		return err
	}

	if err := db.InitSchema(); err != nil {
		return err
	}

	file, err := os.Open(liveFile)
	if err != nil {
		return fmt.Errorf("failed to open live hosts file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// httpx output is usually full URL; extract host
		host := line
		if strings.HasPrefix(host, "http://") {
			host = strings.TrimPrefix(host, "http://")
		} else if strings.HasPrefix(host, "https://") {
			host = strings.TrimPrefix(host, "https://")
		}
		if idx := strings.Index(host, "/"); idx != -1 {
			host = host[:idx]
		}

		httpURL := "http://" + host
		httpsURL := "https://" + host

		if err := db.InsertSubdomain(domain, host, true, httpURL, httpsURL, 200, 200); err != nil {
			log.Printf("[WARN] Failed to insert live subdomain %s: %v", host, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read live hosts file: %v", err)
	}

	return nil
}

// countLines counts the number of non-empty lines in a file.
func countLines(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			count++
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return count, nil
}

// writeLines writes lines to a file (one per line).
func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return writer.Flush()
}
