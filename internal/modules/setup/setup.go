package setup

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Run installs all dependencies required for AutoAR
// It intelligently detects what's already installed and only installs missing dependencies
func Run() error {
	fmt.Println("🚀 AutoAR Setup - Installing dependencies...")
	fmt.Println()

	// Check if running as root (needed for some installations)
	if os.Geteuid() != 0 {
		fmt.Println("⚠️  Some installations require sudo privileges.")
		fmt.Println("   You may be prompted for your password.")
		fmt.Println()
	}

	// Detect OS
	osType := detectOS()
	fmt.Printf("📦 Detected OS: %s\n", osType)
	fmt.Println()

	// Check and install system packages
	if err := checkAndInstallSystemPackages(osType); err != nil {
		return fmt.Errorf("failed to install system packages: %w", err)
	}

	// Check and install Go tools
	if err := checkAndInstallGoTools(); err != nil {
		return fmt.Errorf("failed to install Go tools: %w", err)
	}


	// Create necessary directories
	fmt.Println("📁 Creating AutoAR directories...")
	root := getAutoarRoot()
	dirs := []string{
		filepath.Join(root, "new-results"),
		filepath.Join(root, "Wordlists"),
		filepath.Join(root, "nuclei_templates"),
		filepath.Join(root, "regexes"),
	}
	
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Printf("   ⚠️  Warning: Failed to create %s: %v\n", dir, err)
		} else {
			fmt.Printf("   [ + ]Created: %s\n", dir)
		}
	}

	// Clone Nuclei public templates
	if err := checkAndCloneNucleiTemplates(root); err != nil {
		fmt.Printf("   ⚠️  Warning: Failed to clone Nuclei public templates: %v\n", err)
		fmt.Println("   💡 You can manually clone them later:")
		fmt.Println("      git clone https://github.com/projectdiscovery/nuclei-templates.git")
	}

	fmt.Println()
	fmt.Println("[ + ]Setup completed successfully!")
	fmt.Println()
	fmt.Println("📋 Next steps:")
	fmt.Println("   1. Run 'autoar check-tools' to verify all dependencies")
	fmt.Println("   2. Configure your environment:")
	fmt.Println("      cp env.example .env")
	fmt.Println("      # Edit .env and set DISCORD_BOT_TOKEN")
	fmt.Println("   3. Start the bot:")
	fmt.Println("      export DISCORD_BOT_TOKEN='your_token'")
	fmt.Println("      ./autoar bot")
	fmt.Println("      # Or run in tmux: tmux new-session -d -s autoar './autoar bot'")
	fmt.Println()

	return nil
}

func getAutoarRoot() string {
	if root := os.Getenv("AUTOAR_ROOT"); root != "" {
		return root
	}
	if cwd, err := os.Getwd(); err == nil {
		return cwd
	}
	return "."
}

func detectOS() string {
	if runtime.GOOS == "linux" {
		// Try to detect Linux distribution
		if _, err := os.Stat("/etc/debian_version"); err == nil {
			return "debian"
		}
		if _, err := os.Stat("/etc/redhat-release"); err == nil {
			return "rhel"
		}
		return "linux"
	}
	return runtime.GOOS
}

func checkAndInstallSystemPackages(osType string) error {
	fmt.Println("📦 Checking system packages...")

	var packagesToInstall []string
	var packageChecker func(string) bool

	switch osType {
	case "debian", "linux":
		requiredPackages := map[string]string{
			"libpcap-dev":              "libpcap-dev",
			"unzip":                    "unzip",
			"git":                      "git",
			"curl":                     "curl",
			"jq":                       "jq",
			"dnsutils":                 "dnsutils",
			"docker.io":                "docker.io", // Docker for DNSReaper
		}
		
		packageChecker = func(pkg string) bool {
			// Check if package is installed using dpkg
			cmd := exec.Command("dpkg", "-l", pkg)
			cmd.Stdout = nil
			cmd.Stderr = nil
			return cmd.Run() == nil
		}

		for name, pkg := range requiredPackages {
			if !packageChecker(pkg) {
				packagesToInstall = append(packagesToInstall, pkg)
				fmt.Printf("   [MISSING] %s\n", name)
			} else {
				fmt.Printf("   [OK] %s\n", name)
			}
		}

		if len(packagesToInstall) == 0 {
			fmt.Println("   [ + ]All system packages are already installed")
			return nil
		}

		// Update package list
		fmt.Println("   Updating package list...")
		updateCmd := exec.Command("sudo", "apt-get", "update")
		updateCmd.Stdout = os.Stdout
		updateCmd.Stderr = os.Stderr
		if err := updateCmd.Run(); err != nil {
			return fmt.Errorf("failed to update package list: %w", err)
		}

		// Install missing packages
		fmt.Printf("   Installing missing packages: %s\n", strings.Join(packagesToInstall, ", "))
		installCmd := exec.Command("sudo", append([]string{"apt-get", "install", "-y", "--no-install-recommends"}, packagesToInstall...)...)
		installCmd.Stdout = os.Stdout
		installCmd.Stderr = os.Stderr
		if err := installCmd.Run(); err != nil {
			return fmt.Errorf("failed to install packages: %w", err)
		}

	case "rhel":
		requiredPackages := map[string]string{
			"libpcap-devel":           "libpcap-devel",
			"unzip":                   "unzip",
			"git":                     "git",
			"curl":                    "curl",
			"jq":                      "jq",
			"bind-utils":              "bind-utils",
			"docker":                  "docker", // Docker for DNSReaper
		}
		
		packageChecker = func(pkg string) bool {
			// Check if package is installed using rpm
			cmd := exec.Command("rpm", "-q", pkg)
			cmd.Stdout = nil
			cmd.Stderr = nil
			return cmd.Run() == nil
		}

		for name, pkg := range requiredPackages {
			if !packageChecker(pkg) {
				packagesToInstall = append(packagesToInstall, pkg)
				fmt.Printf("   [MISSING] %s\n", name)
			} else {
				fmt.Printf("   [OK] %s\n", name)
			}
		}

		if len(packagesToInstall) == 0 {
			fmt.Println("   [ + ]All system packages are already installed")
			return nil
		}

		fmt.Printf("   Installing missing packages: %s\n", strings.Join(packagesToInstall, ", "))
		installCmd := exec.Command("sudo", append([]string{"yum", "install", "-y"}, packagesToInstall...)...)
		installCmd.Stdout = os.Stdout
		installCmd.Stderr = os.Stderr
		if err := installCmd.Run(); err != nil {
			return fmt.Errorf("failed to install packages: %w", err)
		}

	default:
		return fmt.Errorf("unsupported OS: %s (only Linux/Debian/RHEL are supported)", osType)
	}

	fmt.Println("   [ + ]System packages installed")
	
	// Check if Docker is installed and provide setup instructions if not
	if _, err := exec.LookPath("docker"); err != nil {
		fmt.Println()
		fmt.Println("   ⚠️  Docker is not installed or not in PATH")
		fmt.Println("   📖 Docker is required for DNSReaper (DNS takeover detection)")
		fmt.Println("   💡 To install Docker:")
		fmt.Println("      - Debian/Ubuntu: sudo apt-get install docker.io")
		fmt.Println("      - RHEL/CentOS: sudo yum install docker")
		fmt.Println("      - Or follow: https://docs.docker.com/get-docker/")
		fmt.Println("      - After installation, add your user to docker group:")
		fmt.Println("        sudo usermod -aG docker $USER")
		fmt.Println("        (then log out and back in)")
	} else {
		// Check if Docker daemon is running
		cmd := exec.Command("docker", "info")
		cmd.Stdout = nil
		cmd.Stderr = nil
		if err := cmd.Run(); err != nil {
			fmt.Println()
			fmt.Println("   ⚠️  Docker is installed but daemon is not running")
			fmt.Println("   💡 Start Docker daemon: sudo systemctl start docker")
		} else {
			fmt.Println("   [ + ]Docker is installed and running")
		}
	}
	
	return nil
}

func checkAndInstallGoTools() error {
	fmt.Println("🔧 Checking Go-based tools...")

	// Check if Go is installed
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("Go is not installed. Please install Go 1.23+ from https://golang.org/dl/")
	}

	// Check if GOBIN is set, otherwise use default
	goPath := os.Getenv("GOBIN")
	if goPath == "" {
		goPath = filepath.Join(os.Getenv("HOME"), "go", "bin")
	}

	// Ensure GOBIN is in PATH
	path := os.Getenv("PATH")
	if !strings.Contains(path, goPath) {
		fmt.Printf("   ⚠️  Warning: %s is not in PATH. Add it to your ~/.bashrc or ~/.zshrc:\n", goPath)
		fmt.Printf("      export PATH=$PATH:%s\n", goPath)
	}

	// Check nuclei
	if _, err := exec.LookPath("nuclei"); err != nil {
		fmt.Println("   [MISSING] nuclei")
		fmt.Println("   Installing nuclei...")
		nucleiCmd := exec.Command("go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
		nucleiCmd.Env = append(os.Environ(), "GOBIN="+goPath)
		nucleiCmd.Stdout = os.Stdout
		nucleiCmd.Stderr = os.Stderr
		if err := nucleiCmd.Run(); err != nil {
			return fmt.Errorf("failed to install nuclei: %w", err)
		}
		fmt.Println("   [ + ]nuclei installed")
	} else {
		fmt.Println("   [OK] nuclei")
	}

	// Check trufflehog
	if _, err := exec.LookPath("trufflehog"); err != nil {
		fmt.Println("   [MISSING] trufflehog")
		fmt.Println("   Installing trufflehog...")
		tmpDir, err := os.MkdirTemp("", "autoar-setup-*")
		if err != nil {
			return fmt.Errorf("failed to create temp directory: %w", err)
		}
		defer os.RemoveAll(tmpDir)

		cloneCmd := exec.Command("git", "clone", "--depth", "1", "https://github.com/trufflesecurity/trufflehog.git", tmpDir)
		cloneCmd.Stdout = os.Stdout
		cloneCmd.Stderr = os.Stderr
		if err := cloneCmd.Run(); err != nil {
			return fmt.Errorf("failed to clone trufflehog: %w", err)
		}

		buildCmd := exec.Command("go", "build", "-o", filepath.Join(goPath, "trufflehog"), ".")
		buildCmd.Dir = tmpDir
		buildCmd.Env = append(os.Environ(), "GOBIN="+goPath)
		buildCmd.Stdout = os.Stdout
		buildCmd.Stderr = os.Stderr
		if err := buildCmd.Run(); err != nil {
			return fmt.Errorf("failed to build trufflehog: %w", err)
		}
		fmt.Println("   [ + ]trufflehog installed")
	} else {
		fmt.Println("   [OK] trufflehog")
	}

	fmt.Println("   [ + ]Go tools check completed")
	return nil
}


func downloadFile(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// checkAndCloneNucleiTemplates checks if Nuclei public templates exist and clones them if needed
func checkAndCloneNucleiTemplates(root string) error {
	nucleiTemplatesDir := filepath.Join(root, "nuclei-templates")
	
	// Check if already cloned
	if info, err := os.Stat(nucleiTemplatesDir); err == nil && info.IsDir() {
		// Check if it's a git repository
		gitDir := filepath.Join(nucleiTemplatesDir, ".git")
		if _, err := os.Stat(gitDir); err == nil {
			fmt.Println("   [OK] Nuclei public templates already cloned")
			// Try to update them
			fmt.Println("   Updating Nuclei public templates...")
			updateCmd := exec.Command("git", "pull")
			updateCmd.Dir = nucleiTemplatesDir
			updateCmd.Stdout = os.Stdout
			updateCmd.Stderr = os.Stderr
			if err := updateCmd.Run(); err != nil {
				fmt.Printf("   ⚠️  Warning: Failed to update templates: %v\n", err)
			} else {
				fmt.Println("   [ + ]Nuclei public templates updated")
			}
			return nil
		}
	}

	// Clone the repository
	fmt.Println("   [MISSING] Nuclei public templates")
	fmt.Println("   Cloning Nuclei public templates from GitHub...")
	cloneCmd := exec.Command("git", "clone", "--depth", "1", "https://github.com/projectdiscovery/nuclei-templates.git", nucleiTemplatesDir)
	cloneCmd.Stdout = os.Stdout
	cloneCmd.Stderr = os.Stderr
	if err := cloneCmd.Run(); err != nil {
		return fmt.Errorf("failed to clone nuclei-templates: %w", err)
	}
	
	fmt.Println("   [ + ]Nuclei public templates cloned successfully")
	return nil
}
