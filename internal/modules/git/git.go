package git

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/deletescape/goop/pkg/goop"
	"github.com/h0tak88r/AutoAR/internal/modules/scanner"
)

// Options controls Git scan behavior
type Options struct {
	URL        string
	OutputDir  string
	ScannerDir string // Path to regexes directory
}

// Result holds the results of a git scan
type Result struct {
	DumpDir     string
	SecretsFile string
	SecretCount int
}

// Run performs the git dump and secret scan
func Run(opts Options) (*Result, error) {
	// 1. Create output directory
	log.Printf("[INFO] Git scan: Dumping .git from %s to %s", opts.URL, opts.OutputDir)
	if err := ensureDir(opts.OutputDir); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %w", err)
	}

	// 2. Run goop to dump the repository (using library)
	// goop.Clone(url, dir, force, keep)
	// force=false (don't delete if exists - we expect empty dir), keep=false (doesn't matter if empty)
	log.Printf("[INFO] Git scan: Starting goop clone (library)...")
	err := goop.Clone(opts.URL, opts.OutputDir, false, false)
	if err != nil {
		log.Printf("[WARN] goop clone failed: %v", err)
		// Continue to verify if anything was dumped
	}

	// 3. Verify dump
	if isEmpty(opts.OutputDir) {
		return nil, fmt.Errorf("git dump failed: no files recovered")
	}

	// 4. Scan for secrets
	secretsFile := filepath.Join(filepath.Dir(opts.OutputDir), "git-secrets.txt")
	log.Printf("[INFO] Git scan: Scanning dump for secrets...")

	count, err := scanCallback(opts.OutputDir, secretsFile, opts.ScannerDir)
	if err != nil {
		log.Printf("[WARN] Secrets scan failed: %v", err)
	}

	return &Result{
		DumpDir:     opts.OutputDir,
		SecretsFile: secretsFile,
		SecretCount: count,
	}, nil
}

func isEmpty(name string) bool {
	f, err := os.Open(name)
	if err != nil {
		return true
	}
	defer f.Close()

	_, err = f.Readdirnames(1)
	if err == nil {
		return false
	}
	return true
}

func ensureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

func scanCallback(dumpDir, secretsFile, regexesDir string) (int, error) {
	patterns, err := scanner.LoadSecretPatterns(regexesDir)
	if err != nil {
		return 0, err
	}

	f, err := os.Create(secretsFile)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	count := 0
	err = filepath.Walk(dumpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		// Skip large files (>10MB)
		if info.Size() > 10*1024*1024 {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		findings := scanner.ScanContentForSecrets(string(content), patterns)
		for _, finding := range findings {
			f.WriteString(fmt.Sprintf("[File: %s] %s\n", path, finding))
			count++
		}
		return nil
	})
	return count, err
}
