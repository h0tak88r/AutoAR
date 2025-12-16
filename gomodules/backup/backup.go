package backup

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Options controls how the backup scan runs.
// This is a Go port of modules/backup_scan.sh (domain / live-hosts modes only).
type Options struct {
	Domain        string
	LiveHostsFile string
	OutputDir     string
	Threads       int
	DelayMS       int
}

type Result struct {
	OutputDir      string
	ResultsFile    string
	LogFile        string
	FoundCount     int
	Duration       time.Duration
	LiveHostsCount int
}

// Run executes the backup scan using the fuzzuli CLI.
func Run(opts Options) (*Result, error) {
	if opts.Domain == "" && opts.LiveHostsFile == "" {
		return nil, fmt.Errorf("either Domain or LiveHostsFile must be provided")
	}
	if opts.Domain != "" && opts.LiveHostsFile != "" {
		return nil, fmt.Errorf("cannot specify both Domain and LiveHostsFile")
	}

	// Ensure fuzzuli is available
	if _, err := exec.LookPath("fuzzuli"); err != nil {
		return nil, fmt.Errorf("fuzzuli not found in PATH; install with: go install github.com/musana/fuzzuli@latest")
	}

	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "new-results"
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

	args := []string{"-mt", "all"}
	threads := opts.Threads
	if threads <= 0 {
		threads = 100
	}
	args = append(args, "-w", strconv.Itoa(threads))

	var cmd *exec.Cmd

	switch {
	case opts.Domain != "":
		// echo "https://domain" | fuzzuli ...
		cmd = exec.Command("fuzzuli", args...)
		cmd.Stdin = strings.NewReader("https://" + opts.Domain + "\n")
	case opts.LiveHostsFile != "":
		// fuzzuli -mt all -f live_hosts_file ...
		if _, err := os.Stat(opts.LiveHostsFile); err != nil {
			return nil, fmt.Errorf("live hosts file not found: %s", opts.LiveHostsFile)
		}
		args = append(args, "-f", opts.LiveHostsFile)
		cmd = exec.Command("fuzzuli", args...)
	default:
		return nil, fmt.Errorf("invalid options")
	}

	// Note: DelayMS is currently not wired through because fuzzuli's
	// public CLI doesn't expose a simple per-request delay flag.
	// We keep the field for future compatibility.
	cmd.Stdout = resultsFH
	cmd.Stderr = logFH

	start := time.Now()
	if err := cmd.Run(); err != nil {
		return res, fmt.Errorf("fuzzuli scan failed: %w", err)
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
