package backup

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	fuzzulitool "github.com/h0tak88r/AutoAR/internal/tools/fuzzuli"
)

// Options controls how the backup scan runs.
// This is a Go port of modules/backup_scan.sh (domain / live-hosts modes only).
type Options struct {
	Domain        string
	LiveHostsFile string
	OutputDir     string
	Threads       int
	DelayMS       int
	Method        string   // Fuzzuli method: regular, withoutdots, withoutvowels, reverse, mixed, withoutdv, shuffle, all
	Extensions    []string // Custom file extensions (e.g., [".rar", ".zip"])
}

type Result struct {
	OutputDir      string
	ResultsFile    string
	LogFile        string
	FoundCount     int
	Duration       time.Duration
	LiveHostsCount int
}

// Run executes the backup scan using the embedded fuzzuli engine.
func Run(opts Options) (*Result, error) {
	if opts.Domain == "" && opts.LiveHostsFile == "" {
		return nil, fmt.Errorf("either Domain or LiveHostsFile must be provided")
	}
	if opts.Domain != "" && opts.LiveHostsFile != "" {
		return nil, fmt.Errorf("cannot specify both Domain and LiveHostsFile")
	}

	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "new-results"
	}

	// Normalize results directory path - if absolute path at root and not in Docker, convert to relative
	if filepath.IsAbs(resultsDir) && !strings.HasPrefix(resultsDir, "/app") {
		// Check if we're in Docker
		isDocker := false
		if _, err := os.Stat("/app"); err == nil {
			if err := os.MkdirAll("/app", 0755); err == nil {
				testPath := "/app/.test-write"
				if f, err := os.Create(testPath); err == nil {
					f.Close()
					os.Remove(testPath)
					isDocker = true
				}
			}
		}
		
		// If not in Docker and path is absolute (like /new-results), convert to relative
		if !isDocker {
			if cwd, err := os.Getwd(); err == nil {
				resultsDir = filepath.Join(cwd, "new-results")
			} else {
				resultsDir = "new-results"
			}
		}
	}

	// Determine output directory
	outDir := opts.OutputDir
	if outDir == "" {
		if opts.Domain != "" {
			outDir = filepath.Join(resultsDir, opts.Domain, "backup")
		} else {
			outDir = filepath.Join(resultsDir, "backup")
		}
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create output directory %s: %w", outDir, err)
	}

	resultsFile := filepath.Join(outDir, "fuzzuli-results.txt")
	logFile := filepath.Join(outDir, "fuzzuli-output.log")

	res := &Result{
		OutputDir:   outDir,
		ResultsFile: resultsFile,
		LogFile:     logFile,
	}

	resultsFH, err := os.Create(resultsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create results file: %w", err)
	}
	defer resultsFH.Close()

	logFH, err := os.Create(logFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create log file: %w", err)
	}
	defer logFH.Close()

	threads := opts.Threads
	if threads <= 0 {
		threads = 100
	}

	fuzzOpts := fuzzulitool.DefaultOptions()
	fuzzOpts.Workers = threads
	
	// Set method if provided
	if opts.Method != "" {
		fuzzOpts.Method = fuzzulitool.Method(opts.Method)
	}
	
	// Set custom extensions if provided
	if len(opts.Extensions) > 0 {
		fuzzOpts.Extensions = opts.Extensions
	}

	start := time.Now()

	var urls []string
	switch {
	case opts.Domain != "":
		u, err := fuzzulitool.ScanDomain(opts.Domain, fuzzOpts)
		if err != nil {
			return res, fmt.Errorf("fuzzuli scan failed: %w", err)
		}
		urls = u
	case opts.LiveHostsFile != "":
		u, err := fuzzulitool.ScanFromFile(opts.LiveHostsFile, fuzzOpts)
		if err != nil {
			return res, fmt.Errorf("fuzzuli scan failed: %w", err)
		}
		urls = u
	default:
		return nil, fmt.Errorf("invalid options")
	}

	for _, u := range urls {
		if strings.TrimSpace(u) == "" {
			continue
		}
		if _, err := resultsFH.WriteString(u + "\n"); err == nil {
			res.FoundCount++
		}
	}

	res.Duration = time.Since(start)

	// Count lines containing "http" in results file, similar to the bash module.
	f, err := os.Open(resultsFile)
	if err != nil {
		return res, fmt.Errorf("failed to open results file for counting: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "http") {
			res.FoundCount++
		}
	}
	_ = scanner.Err()

	// If we scanned a live-hosts file, record host count as well.
	if opts.LiveHostsFile != "" {
		if lf, err := os.Open(opts.LiveHostsFile); err == nil {
			defer lf.Close()
			ls := bufio.NewScanner(lf)
			for ls.Scan() {
				if strings.TrimSpace(ls.Text()) != "" {
					res.LiveHostsCount++
				}
			}
		}
	}

	return res, nil
}
