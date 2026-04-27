package apkx

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/internal/modules/apkx/downloader"
)

type Options struct {
	InputPath string
	Package   string
	Platform  string // "android" or "ios"
	MITM      bool
}

type Result struct {
	OriginalAPK    string
	MITMPatchedAPK string
	ReportDir      string
	LogFile        string
	Duration       time.Duration
	FromCache      bool
}

type PackageOptions struct {
	Package  string
	Platform string
	MITM     bool
}

// Run executes the lite APK analysis (download + optional MITM patch)
func Run(opts Options) (*Result, error) {
	if opts.InputPath == "" && opts.Package != "" {
		return RunFromPackage(PackageOptions{
			Package:  opts.Package,
			Platform: opts.Platform,
			MITM:     opts.MITM,
		})
	}

	if opts.InputPath == "" {
		return nil, fmt.Errorf("input path or package required")
	}

	start := time.Now()
	res := &Result{}

	// Create a report directory
	res.ReportDir = filepath.Join("new-results", "apkx-" + time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(res.ReportDir, 0755); err != nil {
		return nil, err
	}
	res.LogFile = filepath.Join(res.ReportDir, "apkx.log")
	
	logFile, _ := os.Create(res.LogFile)
	defer logFile.Close()

	res.OriginalAPK = opts.InputPath

	if opts.MITM {
		patched, err := MITMPatch(opts.InputPath, res.ReportDir, logFile)
		if err != nil {
			fmt.Fprintf(logFile, "[ERROR] MITM Patch failed: %v\n", err)
		} else {
			res.MITMPatchedAPK = patched
			fmt.Fprintf(logFile, "[OK] MITM Patch successful: %s\n", patched)
		}
	}

	res.Duration = time.Since(start)
	return res, nil
}

// RunFromPackage downloads the APK from a package name and runs analysis
func RunFromPackage(opts PackageOptions) (*Result, error) {
	start := time.Now()
	res := &Result{}

	// Create a report directory
	res.ReportDir = filepath.Join("new-results", "apkx-" + time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(res.ReportDir, 0755); err != nil {
		return nil, err
	}
	res.LogFile = filepath.Join(res.ReportDir, "apkx.log")
	logFile, _ := os.Create(res.LogFile)
	defer logFile.Close()

	fmt.Fprintf(logFile, "[INFO] Downloading package %s using apkeep downloader package\n", opts.Package)
	
	d, err := downloader.NewApkeepDownloader(res.ReportDir)
	if err != nil {
		return nil, err
	}

	config := downloader.GetDefaultConfig()
	config.PackageName = opts.Package

	apkPath, err := d.DownloadAPK(config)
	if err != nil {
		return nil, err
	}

	res.OriginalAPK = apkPath

	if opts.MITM {
		patched, err := MITMPatch(res.OriginalAPK, res.ReportDir, logFile)
		if err != nil {
			fmt.Fprintf(logFile, "[ERROR] MITM Patch failed: %v\n", err)
		} else {
			res.MITMPatchedAPK = patched
		}
	}

	res.Duration = time.Since(start)
	return res, nil
}

func MITMPatch(apkPath, outDir string, logWriter *os.File) (string, error) {
	fmt.Fprintf(logWriter, "[INFO] Starting MITM patch for %s\n", apkPath)
	
	// 1. Decompile
	decodeDir := filepath.Join(outDir, "decode")
	cmd := exec.Command("apktool", "d", apkPath, "-o", decodeDir, "-f")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("apktool decode: %v\n%s", err, string(out))
	}
	
	// 2. Modify Network Security Config
	// (Lite implementation: ensure res/xml/network_security_config.xml exists and allows user certs)
	nscDir := filepath.Join(decodeDir, "res", "xml")
	os.MkdirAll(nscDir, 0755)
	nscPath := filepath.Join(nscDir, "network_security_config.xml")
	
	nscContent := `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>`
	
	if err := os.WriteFile(nscPath, []byte(nscContent), 0644); err != nil {
		return "", err
	}
	
	// 3. Update AndroidManifest.xml
	manifestPath := filepath.Join(decodeDir, "AndroidManifest.xml")
	manifest, err := os.ReadFile(manifestPath)
	if err == nil {
		mStr := string(manifest)
		if !strings.Contains(mStr, "android:networkSecurityConfig") {
			mStr = strings.Replace(mStr, "<application ", `<application android:networkSecurityConfig="@xml/network_security_config" `, 1)
			os.WriteFile(manifestPath, []byte(mStr), 0644)
		}
	}

	// 4. Rebuild
	patchedUnsigned := filepath.Join(outDir, "patched-unsigned.apk")
	cmd = exec.Command("apktool", "b", decodeDir, "-o", patchedUnsigned)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("apktool build: %v\n%s", err, string(out))
	}
	
	// 5. Sign
	patchedSigned := filepath.Join(outDir, filepath.Base(apkPath[:len(apkPath)-len(filepath.Ext(apkPath))]) + "-mitm.apk")
	cmd = exec.Command("java", "-jar", "/usr/local/bin/uber-apk-signer.jar", "--apks", patchedUnsigned, "--out", outDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("uber-apk-signer: %v\n%s", err, string(out))
	}
	
	// uber-apk-signer names the output file with a suffix. 
	// We'll look for any .apk in the outDir that contains "aligned-debugSigned"
	files, _ := os.ReadDir(outDir)
	var finalPath string
	for _, f := range files {
		if !f.IsDir() && strings.Contains(f.Name(), "aligned-debugSigned.apk") {
			finalPath = filepath.Join(outDir, f.Name())
			break
		}
	}

	if finalPath != "" {
		os.Rename(finalPath, patchedSigned)
		return patchedSigned, nil
	}

	return "", fmt.Errorf("signed APK not found in %s", outDir)
}
