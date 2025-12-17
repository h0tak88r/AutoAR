package checktools

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type Tool struct {
	Name   string
	Binary string
}

// Run checks for required external tools and key directories.
// It is a Go rewrite of modules/check_tools.sh without auto-install logic.
func Run() error {
	tools := []Tool{
		// Core external scanners AutoAR still calls as CLIs
		{"nuclei", "nuclei"},
		{"misconfig-mapper", "misconfig-mapper"},
		{"trufflehog", "trufflehog"},
		{"jwt-hack", "jwt-hack"},

		// General utilities used by modules and docker-compose examples
		{"jq", "jq"},
		{"curl", "curl"},
		{"git", "git"},
		{"aws", "aws"},
		// Library-integrated tools:
		// - next88 (React2Shell) is now embedded as a Go package and
		//   does not require an external binary.
		// - apkX analysis is embedded via internal/tools/apkx and only
		//   requires the jadx decompiler binary on PATH.
		// - confused2 (dependency confusion) is now embedded via
		//   internal/tools/confused2 and does not require its CLI.
		{"jadx (APK decompiler for apkX)", "jadx"},
	}

	fmt.Println("[check-tools] Verifying required directories and tools...")

	// Directories
	root := getRootDir()
	dirs := []string{
		filepath.Join(root, "new-results"),
		filepath.Join(root, "Wordlists"),
		filepath.Join(root, "nuclei_templates"),
		filepath.Join(root, "regexes"),
	}

	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			fmt.Printf("[WARN] Failed to ensure directory %s: %v\n", d, err)
		} else {
			fmt.Printf("[OK] Directory: %s\n", d)
		}
	}

	// Tools
	total := len(tools)
	missing := 0

	for _, t := range tools {
		if _, err := exec.LookPath(t.Binary); err != nil {
			fmt.Printf("[MISSING] %s (%s) not found in PATH\n", t.Name, t.Binary)
			missing++
		} else {
			fmt.Printf("[OK] %s (%s)\n", t.Name, t.Binary)
		}
	}

	fmt.Printf("[SUMMARY] Tools present: %d/%d, missing: %d\n", total-missing, total, missing)

	if missing > 0 {
		return fmt.Errorf("%d required tools are missing; see log above", missing)
	}
	return nil
}

func getRootDir() string {
	if v := os.Getenv("AUTOAR_ROOT"); v != "" {
		return v
	}
	if cwd, err := os.Getwd(); err == nil {
		return cwd
	}
	return "/app"
}
