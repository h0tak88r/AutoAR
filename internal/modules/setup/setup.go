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

	// Check and install jadx
	if err := checkAndInstallJadx(); err != nil {
		return fmt.Errorf("failed to install jadx: %w", err)
	}

	// Check and install apktool
	if err := checkAndInstallApktool(); err != nil {
		return fmt.Errorf("failed to install apktool: %w", err)
	}

	// Check and install uber-apk-signer (optional but recommended)
	if err := checkAndInstallUberApkSigner(); err != nil {
		fmt.Printf("⚠️  Warning: Failed to install uber-apk-signer (optional): %v\n", err)
		fmt.Println("   MITM patching will still work, but APK signing may fail.")
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
			fmt.Printf("   ✅ Created: %s\n", dir)
		}
	}

	fmt.Println()
	fmt.Println("✅ Setup completed successfully!")
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
			"openjdk-17-jre-headless":  "openjdk-17-jre-headless",
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
			fmt.Println("   ✅ All system packages are already installed")
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
			"java-17-openjdk-headless": "java-17-openjdk-headless",
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
			fmt.Println("   ✅ All system packages are already installed")
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

	fmt.Println("   ✅ System packages installed")
	
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
			fmt.Println("   ✅ Docker is installed and running")
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
		fmt.Println("   ✅ nuclei installed")
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
		fmt.Println("   ✅ trufflehog installed")
	} else {
		fmt.Println("   [OK] trufflehog")
	}

	fmt.Println("   ✅ Go tools check completed")
	return nil
}

func checkAndInstallJadx() error {
	fmt.Println("📱 Checking jadx decompiler...")

	// Check if already installed
	if _, err := exec.LookPath("jadx"); err == nil {
		fmt.Println("   [OK] jadx is already installed")
		return nil
	}

	fmt.Println("   [MISSING] jadx")
	jadxVersion := "1.4.7"
	jadxURL := fmt.Sprintf("https://github.com/skylot/jadx/releases/download/v%s/jadx-%s.zip", jadxVersion, jadxVersion)
	
	tmpFile := filepath.Join(os.TempDir(), "jadx.zip")
	defer os.Remove(tmpFile)

	fmt.Printf("   Downloading jadx v%s...\n", jadxVersion)
	if err := downloadFile(jadxURL, tmpFile); err != nil {
		return fmt.Errorf("failed to download jadx: %w", err)
	}

	jadxDir := "/opt/jadx"
	fmt.Printf("   Extracting to %s...\n", jadxDir)
	
	// Create directory
	if err := exec.Command("sudo", "mkdir", "-p", jadxDir).Run(); err != nil {
		return fmt.Errorf("failed to create jadx directory: %w", err)
	}

	// Extract
	unzipCmd := exec.Command("sudo", "unzip", "-q", tmpFile, "-d", jadxDir)
	unzipCmd.Stdout = os.Stdout
	unzipCmd.Stderr = os.Stderr
	if err := unzipCmd.Run(); err != nil {
		return fmt.Errorf("failed to extract jadx: %w", err)
	}

	// Create symlinks
	jadxBin := filepath.Join(jadxDir, "bin", "jadx")
	if err := exec.Command("sudo", "ln", "-sf", jadxBin, "/usr/local/bin/jadx").Run(); err != nil {
		return fmt.Errorf("failed to create jadx symlink: %w", err)
	}

	fmt.Println("   ✅ jadx installed")
	return nil
}

func checkAndInstallApktool() error {
	fmt.Println("🔧 Checking apktool...")

	// Check if already installed
	if _, err := exec.LookPath("apktool"); err == nil {
		fmt.Println("   [OK] apktool is already installed")
		return nil
	}

	fmt.Println("   [MISSING] apktool")
	apktoolVersion := "2.9.3"
	apktoolURL := fmt.Sprintf("https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_%s.jar", apktoolVersion)
	
	jarPath := "/usr/local/bin/apktool.jar"
	tmpFile := filepath.Join(os.TempDir(), "apktool.jar")
	defer os.Remove(tmpFile)

	fmt.Printf("   Downloading apktool v%s...\n", apktoolVersion)
	if err := downloadFile(apktoolURL, tmpFile); err != nil {
		return fmt.Errorf("failed to download apktool: %w", err)
	}

	// Move to /usr/local/bin
	if err := exec.Command("sudo", "mv", tmpFile, jarPath).Run(); err != nil {
		return fmt.Errorf("failed to move apktool.jar: %w", err)
	}

	// Create wrapper script
	scriptPath := "/usr/local/bin/apktool"
	scriptContent := "#!/bin/sh\njava -jar /usr/local/bin/apktool.jar \"$@\"\n"
	if err := os.WriteFile(filepath.Join(os.TempDir(), "apktool"), []byte(scriptContent), 0755); err != nil {
		return fmt.Errorf("failed to create apktool script: %w", err)
	}

	if err := exec.Command("sudo", "mv", filepath.Join(os.TempDir(), "apktool"), scriptPath).Run(); err != nil {
		return fmt.Errorf("failed to move apktool script: %w", err)
	}

	fmt.Println("   ✅ apktool installed")
	return nil
}

func checkAndInstallUberApkSigner() error {
	fmt.Println("✍️  Checking uber-apk-signer (optional)...")

	// Check if already installed
	if _, err := exec.LookPath("uber-apk-signer"); err == nil {
		fmt.Println("   [OK] uber-apk-signer is already installed")
		return nil
	}

	fmt.Println("   [MISSING] uber-apk-signer")
	version := "1.3.0"
	url := fmt.Sprintf("https://github.com/patrickfav/uber-apk-signer/releases/download/v%s/uber-apk-signer-%s.jar", version, version)
	
	jarPath := "/usr/local/bin/uber-apk-signer.jar"
	tmpFile := filepath.Join(os.TempDir(), "uber-apk-signer.jar")
	defer os.Remove(tmpFile)

	fmt.Printf("   Downloading uber-apk-signer v%s...\n", version)
	if err := downloadFile(url, tmpFile); err != nil {
		return fmt.Errorf("failed to download uber-apk-signer: %w", err)
	}

	// Move to /usr/local/bin
	if err := exec.Command("sudo", "mv", tmpFile, jarPath).Run(); err != nil {
		return fmt.Errorf("failed to move uber-apk-signer.jar: %w", err)
	}

	// Create wrapper script
	scriptPath := "/usr/local/bin/uber-apk-signer"
	scriptContent := "#!/bin/sh\njava -jar /usr/local/bin/uber-apk-signer.jar \"$@\"\n"
	if err := os.WriteFile(filepath.Join(os.TempDir(), "uber-apk-signer"), []byte(scriptContent), 0755); err != nil {
		return fmt.Errorf("failed to create uber-apk-signer script: %w", err)
	}

	if err := exec.Command("sudo", "mv", filepath.Join(os.TempDir(), "uber-apk-signer"), scriptPath).Run(); err != nil {
		return fmt.Errorf("failed to move uber-apk-signer script: %w", err)
	}

	fmt.Println("   ✅ uber-apk-signer installed")
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
