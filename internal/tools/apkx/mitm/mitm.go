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
		// Add networkSecurityConfig to existing attributes (matching apk-mitm: @xml/nsc_mitm)
		manifestStr = appTagRegex.ReplaceAllString(manifestStr, `$1 android:networkSecurityConfig="@xml/nsc_mitm"$2`)
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

	// Network security config XML that allows user certificates (matching apk-mitm format)
	configXML := `<?xml version="1.0" encoding="utf-8"?>
  <!-- Intentionally lax Network Security Configuration (generated by apk-mitm) -->
  <network-security-config>
    <!-- Allow cleartext traffic -->
    <base-config cleartextTrafficPermitted="true">
      <trust-anchors>
        <!-- Allow user-added (proxy) certificates -->
        <certificates src="user" />
        <certificates src="system" />
      </trust-anchors>
    </base-config>
  </network-security-config>`

	configPath := filepath.Join(xmlDir, "nsc_mitm.xml")
	if err := os.WriteFile(configPath, []byte(configXML), 0644); err != nil {
		return fmt.Errorf("failed to write network security config: %w", err)
	}

	return nil
}

// methodPatch represents a patch to apply to a smali method
type methodPatch struct {
	className   string   // Full class name or interface name
	methodSig   string   // Full method signature
	returnType  string   // "void", "boolean", "array"
	replacement []string // Replacement smali code
}

// disableCertificatePinning disables certificate pinning in Smali code
// Based on apk-mitm's approach: match method signatures and replace method bodies
func (p *Patcher) disableCertificatePinning(decodedDir string) error {
	// Check for smali directories (can be smali, smali_classes2, etc.)
	smaliDirs := []string{}
	entries, err := os.ReadDir(decodedDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() && (strings.HasPrefix(entry.Name(), "smali") || entry.Name() == "smali") {
				smaliDirs = append(smaliDirs, filepath.Join(decodedDir, entry.Name()))
			}
		}
	}
	
	if len(smaliDirs) == 0 {
		fmt.Printf("[MITM] No smali directory found, skipping certificate pinning removal\n")
		return nil
	}

	// Method signatures to patch (matching apk-mitm patches.ts)
	
	patches := []methodPatch{
		// X509TrustManager interface methods
		{
			className:   "javax/net/ssl/X509TrustManager",
			methodSig:   "checkClientTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V",
			returnType: "void",
			replacement: []string{".locals 0", "return-void"},
		},
		{
			className:   "javax/net/ssl/X509TrustManager",
			methodSig:   "checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V",
			returnType: "void",
			replacement: []string{".locals 0", "return-void"},
		},
		{
			className:   "javax/net/ssl/X509TrustManager",
			methodSig:   "getAcceptedIssuers()[Ljava/security/cert/X509Certificate;",
			returnType: "array",
			replacement: []string{".locals 1", "const/4 v0, 0x0", "new-array v0, v0, [Ljava/security/cert/X509Certificate;", "return-object v0"},
		},
		// HostnameVerifier interface
		{
			className:   "javax/net/ssl/HostnameVerifier",
			methodSig:   "verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z",
			returnType: "boolean",
			replacement: []string{".locals 1", "const/4 v0, 0x1", "return v0"},
		},
		// OkHttp 2.5 CertificatePinner
		{
			className:   "com/squareup/okhttp/CertificatePinner",
			methodSig:   "check(Ljava/lang/String;Ljava/util/List;)V",
			returnType: "void",
			replacement: []string{".locals 0", "return-void"},
		},
		// OkHttp 3.x CertificatePinner
		{
			className:   "okhttp3/CertificatePinner",
			methodSig:   "check(Ljava/lang/String;Ljava/util/List;)V",
			returnType: "void",
			replacement: []string{".locals 0", "return-void"},
		},
		// OkHttp 4.2 CertificatePinner
		{
			className:   "okhttp3/CertificatePinner",
			methodSig:   "check$okhttp(Ljava/lang/String;Lkotlin/jvm/functions/Function0;)V",
			returnType: "void",
			replacement: []string{".locals 0", "return-void"},
		},
	}

	patchedCount := 0

	// Process each smali directory
	for _, smaliDir := range smaliDirs {
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
			originalContent := content
			
			// Check if this file implements any of the interfaces or is one of the classes we need to patch
			// Parse class name from file (first .class line)
			implements := []string{}
			for _, line := range strings.Split(content, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), ".class ") {
					// Extract class name
					if idx := strings.Index(line, "L"); idx != -1 {
						if endIdx := strings.Index(line[idx+1:], ";"); endIdx != -1 {
							className := line[idx+1 : idx+1+endIdx]
							// Check if this class matches any patch
							for _, patch := range patches {
								if className == patch.className {
									// This is the class we need to patch
									content = p.patchMethodInContent(content, patch)
									if content != originalContent {
										patchedCount++
									}
									break
								}
							}
						}
					}
				} else if strings.HasPrefix(strings.TrimSpace(line), ".implements ") {
					// Extract interface name
					if idx := strings.Index(line, "L"); idx != -1 {
						if endIdx := strings.Index(line[idx+1:], ";"); endIdx != -1 {
							interfaceName := line[idx+1 : idx+1+endIdx]
							implements = append(implements, interfaceName)
						}
					}
				}
			}
			
			// Check if this class implements any interfaces we need to patch
			for _, patch := range patches {
				if patch.className != "" {
					for _, impl := range implements {
						if impl == patch.className {
							// This class implements the interface we need to patch
							content = p.patchMethodInContent(content, patch)
							if content != originalContent {
								patchedCount++
							}
							break
						}
					}
				}
			}

			if content != originalContent {
				// Write back the patched content
				if err := os.WriteFile(path, []byte(content), 0644); err != nil {
					return fmt.Errorf("failed to write patched smali file: %w", err)
				}
			}

			return nil
		})
		
		if err != nil {
			return err
		}
	}

	if patchedCount > 0 {
		fmt.Printf("[MITM] Patched %d certificate pinning methods\n", patchedCount)
	}

	return nil
}

// patchMethodInContent patches a specific method in smali content
func (p *Patcher) patchMethodInContent(content string, patch methodPatch) string {
	// Escape special regex characters in method signature
	escapedSig := regexp.QuoteMeta(patch.methodSig)
	
	// Pattern to match: .method public (final?) <signature>
	// followed by method body until .end method
	// Use [\s\S] to match any character including newlines (works in Go regex)
	pattern := fmt.Sprintf(`(\.method public (?:final )?%s)\n([\s\S]+?)\n(\.end method)`, escapedSig)
	
	re := regexp.MustCompile(pattern)
	
	return re.ReplaceAllStringFunc(content, func(match string) string {
		submatches := re.FindStringSubmatch(match)
		if len(submatches) < 4 {
			return match
		}
		
		openingLine := submatches[1]
		body := submatches[2]
		closingLine := submatches[3]
		
		// Extract original body lines (remove indentation)
		bodyLines := strings.Split(body, "\n")
		commentedBody := []string{}
		for _, line := range bodyLines {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				commentedBody = append(commentedBody, "# "+trimmed)
			}
		}
		
		// Build patched method
		patchedLines := []string{
			openingLine,
			"    # inserted by apk-mitm to disable certificate pinning",
		}
		
		// Add replacement code with proper indentation
		for _, replLine := range patch.replacement {
			patchedLines = append(patchedLines, "    "+replLine)
		}
		
		patchedLines = append(patchedLines, "")
		patchedLines = append(patchedLines, "    # commented out by apk-mitm to disable old method body")
		patchedLines = append(patchedLines, "    # ")
		patchedLines = append(patchedLines, commentedBody...)
		patchedLines = append(patchedLines, closingLine)
		
		return strings.Join(patchedLines, "\n")
	})
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
