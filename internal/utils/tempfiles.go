package utils

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// WriteTempHostFile creates an ephemeral file containing live host URLs for the
// given domain, sourced from the database.
//
// Usage:
//
//	path, cleanup, err := utils.WriteTempHostFile(domain)
//	if err != nil { ... }
//	defer cleanup()
//	// pass path to tool
//
// The file is written to os.TempDir() and deleted by cleanup().
// Falls back to the on-disk live-subs.txt if the database has no entries.
func WriteTempHostFile(domain string) (path string, cleanup func(), err error) {
	cleanup = func() {} // safe no-op default

	var lines []string

	// Primary: query DB for live subdomains
	if dbErr := db.Init(); dbErr == nil {
		_ = db.InitSchema()
		if subs, dbErr := db.ListLiveSubdomains(domain); dbErr == nil && len(subs) > 0 {
			for _, sub := range subs {
				url := sub.HTTPSURL
				if url == "" {
					url = sub.HTTPURL
				}
				if url == "" {
					url = "https://" + sub.Subdomain
				}
				lines = append(lines, url)
			}
		}
	}

	// Fallback: read the on-disk file if DB had no data
	if len(lines) == 0 {
		resultsDir := GetResultsDir()
		candidates := []string{
			filepath.Join(resultsDir, domain, "subs", "live-subs.txt"),
			filepath.Join(resultsDir, domain, "subs", "live-hosts.txt"),
		}
		for _, c := range candidates {
			if diskLines, readErr := readNonEmptyLines(c); readErr == nil && len(diskLines) > 0 {
				lines = diskLines
				break
			}
		}
	}

	if len(lines) == 0 {
		return "", cleanup, fmt.Errorf("no live hosts found for domain %q (neither in DB nor on disk)", domain)
	}

	f, err := os.CreateTemp("", "autoar-hosts-*.txt")
	if err != nil {
		return "", cleanup, fmt.Errorf("failed to create temp host file: %w", err)
	}
	path = f.Name()
	cleanup = func() { os.Remove(path) }

	w := bufio.NewWriter(f)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(path)
		return "", func() {}, fmt.Errorf("failed to write temp host file: %w", err)
	}
	f.Close()
	return path, cleanup, nil
}

// WriteTempSubsFile creates an ephemeral file containing all subdomains for the
// given domain, sourced from the database.
//
// Falls back to the on-disk all-subs.txt if the database has no entries.
func WriteTempSubsFile(domain string) (path string, cleanup func(), err error) {
	cleanup = func() {}

	var lines []string

	// Primary: query DB
	if dbErr := db.Init(); dbErr == nil {
		_ = db.InitSchema()
		if subs, dbErr := db.ListSubdomains(domain); dbErr == nil && len(subs) > 0 {
			lines = subs
		}
	}

	// Fallback: on-disk file
	if len(lines) == 0 {
		resultsDir := GetResultsDir()
		candidates := []string{
			filepath.Join(resultsDir, domain, "subs", "all-subs.txt"),
			filepath.Join(resultsDir, domain, "subs", "subdomains.txt"),
		}
		for _, c := range candidates {
			if diskLines, readErr := readNonEmptyLines(c); readErr == nil && len(diskLines) > 0 {
				lines = diskLines
				break
			}
		}
	}

	if len(lines) == 0 {
		return "", cleanup, fmt.Errorf("no subdomains found for domain %q", domain)
	}

	f, err := os.CreateTemp("", "autoar-subs-*.txt")
	if err != nil {
		return "", cleanup, fmt.Errorf("failed to create temp subs file: %w", err)
	}
	path = f.Name()
	cleanup = func() { os.Remove(path) }

	w := bufio.NewWriter(f)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(path)
		return "", func() {}, fmt.Errorf("failed to write temp subs file: %w", err)
	}
	f.Close()
	return path, cleanup, nil
}

// WriteTempURLFile creates an ephemeral file containing crawled URLs for the
// given domain. URLs are read from the on-disk all-urls.txt for now;
// a future version will query a URLs table in the DB.
func WriteTempURLFile(domain string) (path string, cleanup func(), err error) {
	cleanup = func() {}

	resultsDir := GetResultsDir()
	candidates := []string{
		filepath.Join(resultsDir, domain, "urls", "all-urls.txt"),
	}

	var lines []string
	for _, c := range candidates {
		if diskLines, readErr := readNonEmptyLines(c); readErr == nil && len(diskLines) > 0 {
			lines = diskLines
			break
		}
	}

	if len(lines) == 0 {
		return "", cleanup, fmt.Errorf("no URLs found for domain %q", domain)
	}

	f, err := os.CreateTemp("", "autoar-urls-*.txt")
	if err != nil {
		return "", cleanup, fmt.Errorf("failed to create temp URL file: %w", err)
	}
	path = f.Name()
	cleanup = func() { os.Remove(path) }

	w := bufio.NewWriter(f)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(path)
		return "", func() {}, fmt.Errorf("failed to write temp URL file: %w", err)
	}
	f.Close()
	return path, cleanup, nil
}

// readNonEmptyLines reads a file and returns all non-empty, non-comment lines.
func readNonEmptyLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, sc.Err()
}
