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
		{"subfinder", "subfinder"},
		{"httpx", "httpx"},
		{"naabu", "naabu"},
		{"nuclei", "nuclei"},
		{"ffuf", "ffuf"},
		{"kxss", "kxss"},
		{"qsreplace", "qsreplace"},
		{"gf", "gf"},
		{"dalfox", "dalfox"},
		{"urlfinder", "urlfinder"},
		{"jsleak", "jsleak"},
		{"jsfinder", "jsfinder"},
		{"dnsx", "dnsx"},
		{"dig", "dig"},
		{"jq", "jq"},
		{"yq", "yq"},
		{"anew", "anew"},
		{"curl", "curl"},
		{"git", "git"},
		{"aws", "aws"},
		{"trufflehog", "trufflehog"},
		{"fuzzuli", "fuzzuli"},
		{"confused2", "confused2"},
		{"misconfig-mapper", "misconfig-mapper"},
		{"jwt-hack", "jwt-hack"},
		{"next88 (React2Shell)", "next88"},
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
