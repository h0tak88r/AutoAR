package mitm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Patcher handles MITM patching of Android APK files
type Patcher struct {
	apktoolPath string
	javaPath    string
}

// GetApktoolPath returns the apktool path (for debugging)
func (p *Patcher) GetApktoolPath() string {
	return p.apktoolPath
}

// GetJavaPath returns the java path (for debugging)
func (p *Patcher) GetJavaPath() string {
	return p.javaPath
}

// NewPatcher creates a new MITM patcher
func NewPatcher() (*Patcher, error) {
	// Find apktool JAR (we'll need it for decode/encode)
	// Check common locations
	apktoolPaths := []string{
		"/usr/local/bin/apktool.jar",
		"/opt/apktool/apktool.jar",
		filepath.Join(os.Getenv("HOME"), ".local/share/apktool/apktool.jar"),
		"apktool.jar", // In PATH
	}
	
	var apktoolPath string
	
	// First, check if apktool script exists in PATH
	if found, err := exec.LookPath("apktool"); err == nil {
		// apktool script exists, try to find the JAR it uses
		// Read the script to find JAR path, or use common locations
		scriptData, err := os.ReadFile(found)
		if err == nil {
			// Look for JAR path in script (common pattern: java -jar /path/to/apktool.jar)
			jarRegex := regexp.MustCompile(`-jar\s+([^\s]+apktool[^\s]*\.jar)`)
			if matches := jarRegex.FindStringSubmatch(string(scriptData)); len(matches) > 1 {
				if _, err := os.Stat(matches[1]); err == nil {
					apktoolPath = matches[1]
				}
			}
		}
		// If not found in script, try default locations
		if apktoolPath == "" {
			for _, path := range apktoolPaths {
				if _, err := os.Stat(path); err == nil {
					apktoolPath = path
					break
				}
			}
		}
	} else {
		// No apktool script, check JAR locations directly
		for _, path := range apktoolPaths {
			if _, err := os.Stat(path); err == nil {
				apktoolPath = path
				break
			}
		}
	}
	
	if apktoolPath == "" {
		return nil, fmt.Errorf("apktool.jar not found. Install from: https://ibotpeaches.github.io/Apktool/")
	}

	// Find Java (required for apktool)
	javaPath, err := exec.LookPath("java")
	if err != nil {
		return nil, fmt.Errorf("java not found in PATH. Install Java 8+")
	}

	return &Patcher{
		apktoolPath: apktoolPath,
		javaPath:    javaPath,
	}, nil
}

// PatchAPK patches an APK file for MITM inspection
// Returns the path to the patched APK file
func (p *Patcher) PatchAPK(apkPath, outputDir string) (string, error) {
	if _, err := os.Stat(apkPath); err != nil {
		return "", fmt.Errorf("APK file not found: %w", err)
	}

	// Create temp directory for decoding
	tempDir, err := os.MkdirTemp("", "apk-mitm-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir) // Clean up on error

	// Step 1: Decode APK using apktool
	fmt.Printf("[MITM] Decoding APK...\n")
	if err := p.decodeAPK(apkPath, tempDir); err != nil {
		return "", fmt.Errorf("failed to decode APK: %w", err)
	}

	// Step 2: Modify AndroidManifest.xml to add network security config
	fmt.Printf("[MITM] Modifying AndroidManifest.xml...\n")
	if err := p.modifyManifest(tempDir); err != nil {
		return "", fmt.Errorf("failed to modify manifest: %w", err)
	}

	// Step 3: Create/update network_security_config.xml
	fmt.Printf("[MITM] Creating network security config...\n")
	if err := p.createNetworkSecurityConfig(tempDir); err != nil {
		return "", fmt.Errorf("failed to create network security config: %w", err)
	}

	// Step 4: Disable certificate pinning in Smali code
	fmt.Printf("[MITM] Disabling certificate pinning...\n")
	if err := p.disableCertificatePinning(tempDir); err != nil {
		return "", fmt.Errorf("failed to disable certificate pinning: %w", err)
	}

	// Step 5: Re-encode APK using apktool
	fmt.Printf("[MITM] Encoding patched APK...\n")
	// Use a more descriptive name for the patched APK
	apkBaseName := strings.TrimSuffix(filepath.Base(apkPath), filepath.Ext(apkPath))
	encodedAPK := filepath.Join(outputDir, apkBaseName+"-mitm-patched.apk")
	if err := p.encodeAPK(tempDir, encodedAPK); err != nil {
		return "", fmt.Errorf("failed to encode APK: %w", err)
	}
	fmt.Printf("[MITM] Encoded APK saved to: %s\n", encodedAPK)

	// Step 6: Sign APK (using uber-apk-signer or apksigner)
	fmt.Printf("[MITM] Signing patched APK...\n")
	if err := p.signAPK(encodedAPK); err != nil {
		// Signing failure is not critical, warn but continue
		fmt.Printf("[WARN] Failed to sign APK: %v (APK may need manual signing)\n", err)
	} else {
		fmt.Printf("[MITM] APK signed successfully\n")
	}

	// Verify the patched APK exists before returning
	if info, err := os.Stat(encodedAPK); err != nil {
		return "", fmt.Errorf("patched APK file not found after encoding: %w", err)
	} else {
		fmt.Printf("[MITM] Patched APK verified: %s (size: %d bytes, %.2f MB)\n", 
			encodedAPK, info.Size(), float64(info.Size())/1024/1024)
	}

	return encodedAPK, nil
}

// decodeAPK decodes an APK file using apktool
func (p *Patcher) decodeAPK(apkPath, outputDir string) error {
	// Check if apktool is a script or JAR
	var cmd *exec.Cmd
	if strings.HasSuffix(p.apktoolPath, ".jar") {
		// It's a JAR file, use java -jar
		cmd = exec.Command(p.javaPath, "-jar", p.apktoolPath, "d", apkPath, "-o", outputDir, "-f")
	} else {
		// It's a script, call it directly
		cmd = exec.Command(p.apktoolPath, "d", apkPath, "-o", outputDir, "-f")
	}
	fmt.Printf("[MITM] Running decode: %s\n", strings.Join(cmd.Args, " "))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apktool decode failed: %w, output: %s", err, string(output))
	}
	fmt.Printf("[MITM] Decode completed successfully\n")
	return nil
}

// encodeAPK encodes a decoded APK directory back to APK using apktool
func (p *Patcher) encodeAPK(decodedDir, outputAPK string) error {
	// Ensure output directory exists
	if err := os.MkdirAll(filepath.Dir(outputAPK), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Check if apktool is a script or JAR
	var cmd *exec.Cmd
	if strings.HasSuffix(p.apktoolPath, ".jar") {
		// It's a JAR file, use java -jar
		// apktool b command syntax: apktool b <decoded_dir> -o <output_apk> -f (force overwrite)
		cmd = exec.Command(p.javaPath, "-jar", p.apktoolPath, "b", decodedDir, "-o", outputAPK, "-f")
	} else {
		// It's a script, call it directly
		cmd = exec.Command(p.apktoolPath, "b", decodedDir, "-o", outputAPK, "-f")
	}
	
	fmt.Printf("[MITM] Running encode: %s\n", strings.Join(cmd.Args, " "))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apktool encode failed: %w, output: %s", err, string(output))
	}
	fmt.Printf("[MITM] Encode completed successfully\n")
	return nil
}

// modifyManifest modifies AndroidManifest.xml to add network security config reference
func (p *Patcher) modifyManifest(decodedDir string) error {
	manifestPath := filepath.Join(decodedDir, "AndroidManifest.xml")
	if _, err := os.Stat(manifestPath); err != nil {
		// Try alternative locations
		altPaths := []string{
			filepath.Join(decodedDir, "res", "AndroidManifest.xml"),
			filepath.Join(decodedDir, "resources", "AndroidManifest.xml"),
		}
		for _, altPath := range altPaths {
			if _, err := os.Stat(altPath); err == nil {
				manifestPath = altPath
				break
			}
		}
		if _, err := os.Stat(manifestPath); err != nil {
			return fmt.Errorf("AndroidManifest.xml not found")
		}
	}

	// Read manifest
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read manifest: %w", err)
	}

	manifestStr := string(data)

	// Check if network security config is already set
	if strings.Contains(manifestStr, "android:networkSecurityConfig") {
		fmt.Printf("[MITM] Network security config already present in manifest\n")
		return nil
	}

	// Find <application> tag and add networkSecurityConfig attribute
	// Pattern: <application ...> or <application>
	appTagRegex := regexp.MustCompile(`(<application[^>]*)(>)`)
	
	// Check if application tag has attributes
	if appTagRegex.MatchString(manifestStr) {
		// Add networkSecurityConfig to existing attributes
		manifestStr = appTagRegex.ReplaceAllString(manifestStr, `$1 android:networkSecurityConfig="@xml/network_security_config"$2`)
	} else {
		// If no application tag found, this is unusual but we'll try to add it
		return fmt.Errorf("could not find <application> tag in manifest")
	}

	// Write back
	if err := os.WriteFile(manifestPath, []byte(manifestStr), 0644); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// createNetworkSecurityConfig creates network_security_config.xml that allows user certificates
func (p *Patcher) createNetworkSecurityConfig(decodedDir string) error {
	// Determine res directory
	resDir := filepath.Join(decodedDir, "res")
	xmlDir := filepath.Join(resDir, "xml")
	
	// Create xml directory if it doesn't exist
	if err := os.MkdirAll(xmlDir, 0755); err != nil {
		return fmt.Errorf("failed to create xml directory: %w", err)
	}

	// Network security config XML that allows user certificates
	configXML := `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </domain-config>
</network-security-config>`

	configPath := filepath.Join(xmlDir, "network_security_config.xml")
	if err := os.WriteFile(configPath, []byte(configXML), 0644); err != nil {
		return fmt.Errorf("failed to write network security config: %w", err)
	}

	return nil
}

// disableCertificatePinning disables certificate pinning in Smali code
// This is a simplified implementation - for full coverage, we'd need a proper Smali parser
func (p *Patcher) disableCertificatePinning(decodedDir string) error {
	smaliDir := filepath.Join(decodedDir, "smali")
	if _, err := os.Stat(smaliDir); err != nil {
		// No smali directory, skip certificate pinning removal
		fmt.Printf("[MITM] No smali directory found, skipping certificate pinning removal\n")
		return nil
	}

	// Patterns to disable common certificate pinning libraries
	// Based on apk-mitm's approach: modify methods to return early or return null/void
	pinningMethods := []string{
		"Lokhttp3/CertificatePinner;->check",
		"Lokhttp3/internal/tls/CertificateChainCleaner;->clean",
		"Lcom/datatheorem/trustkit/TrustKit;->getInstance",
		"Lcom/datatheorem/trustkit/pinning/PinSet;->getPins",
		"Landroid/net/http/X509TrustManagerExtensions;->checkServerTrusted",
		"Ljavax/net/ssl/X509TrustManager;->checkServerTrusted",
		"Ljavax/net/ssl/TrustManager;->checkServerTrusted",
	}

	patchedCount := 0

	// Walk through smali files and apply patches
	err := filepath.Walk(smaliDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".smali") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil // Skip files we can't read
		}

		content := string(data)
		lines := strings.Split(content, "\n")
		modified := false

		// Look for methods that need patching
		for i, line := range lines {
			for _, method := range pinningMethods {
				if strings.Contains(line, method) {
					// Found a method that needs patching
					// Find the method body start (usually after .locals or .registers)
					// Add return-void at the start of the method body
					for j := i + 1; j < len(lines) && j < i+10; j++ {
						nextLine := strings.TrimSpace(lines[j])
						// Skip empty lines and annotations
						if nextLine == "" || strings.HasPrefix(nextLine, ".") {
							continue
						}
						// Found the method body start, insert return-void
						// Determine return type based on method signature
						returnType := "return-void"
						if strings.Contains(line, "Ljava/lang/String;") || strings.Contains(line, "Ljava/lang/Object;") {
							returnType = "return-object"
						} else if strings.Contains(line, "I") || strings.Contains(line, "Z") {
							returnType = "return"
						}

						// Insert return statement after method prologue
						indent := strings.Repeat(" ", 4) // Standard Smali indentation
						lines = append(lines[:j], append([]string{indent + returnType}, lines[j:]...)...)
						modified = true
						patchedCount++
						break
					}
					break
				}
			}
		}

		if modified {
			if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644); err != nil {
				return fmt.Errorf("failed to write patched smali file: %w", err)
			}
		}

		return nil
	})

	if err == nil && patchedCount > 0 {
		fmt.Printf("[MITM] Patched %d certificate pinning methods\n", patchedCount)
	}

	return err
}

// signAPK signs an APK file
func (p *Patcher) signAPK(apkPath string) error {
	// Try uber-apk-signer first
	if signerPath, err := exec.LookPath("uber-apk-signer"); err == nil {
		cmd := exec.Command(signerPath, "--apks", apkPath)
		fmt.Printf("[MITM] Using uber-apk-signer: %s\n", signerPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("uber-apk-signer failed: %w, output: %s", err, string(output))
		}
		return nil
	}

	// Try apksigner (Android SDK tool)
	if signerPath, err := exec.LookPath("apksigner"); err == nil {
		// Generate a debug keystore if needed
		keystorePath := filepath.Join(filepath.Dir(apkPath), "debug.keystore")
		if _, err := os.Stat(keystorePath); err != nil {
			// Create debug keystore using keytool
			if keytoolPath, err := exec.LookPath("keytool"); err == nil {
				cmd := exec.Command(keytoolPath,
					"-genkey", "-v",
					"-keystore", keystorePath,
					"-alias", "androiddebugkey",
					"-keyalg", "RSA",
					"-keysize", "2048",
					"-validity", "10000",
					"-storepass", "android",
					"-keypass", "android",
					"-dname", "CN=Android Debug,O=Android,C=US")
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("failed to create keystore: %w", err)
				}
			}
		}

		// Sign with apksigner
		fmt.Printf("[MITM] Using apksigner: %s\n", signerPath)
		cmd := exec.Command(signerPath, "sign",
			"--ks", keystorePath,
			"--ks-pass", "pass:android",
			"--key-pass", "pass:android",
			"--ks-key-alias", "androiddebugkey",
			apkPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("apksigner failed: %w, output: %s", err, string(output))
		}
		return nil
	}

	// If no signer found, return error (but not critical)
	return fmt.Errorf("no APK signer found (tried uber-apk-signer and apksigner)")
}
