package apkx

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	apkxanalyzer "github.com/h0tak88r/AutoAR/internal/tools/apkx/analyzer"
	"github.com/h0tak88r/AutoAR/internal/tools/apkx/downloader"
	iosstore "github.com/h0tak88r/AutoAR/internal/tools/ipatool"
)

// Options controls how apkX is invoked from AutoAR.
type Options struct {
	// InputPath is the local path to an APK or IPA file.
	InputPath string
	// Optional explicit output directory. If empty, a directory under
	// $AUTOAR_RESULTS_DIR/apkx/<appname> will be created.
	OutputDir string
	// Whether to enable MITM patching (-mitm flag).
	MITM bool
}

// Result describes where apkX wrote its output.
type Result struct {
	ReportDir    string
	LogFile      string
	Duration     time.Duration
	MITMPatchedAPK string // Path to MITM patched APK if MITM was enabled
}

// PackageOptions controls apkX scans where AutoAR first downloads the
// application (APK/IPA) from a store or other source based on a package
// identifier, then runs the local analysis.
//
// The actual download is delegated to an external command configured via
// environment variables:
//
//   - APKX_ANDROID_DOWNLOAD_CMD: shell snippet used for Android packages
//   - APKX_IOS_DOWNLOAD_CMD:     shell snippet used for iOS apps
//
// For each invocation AutoAR sets:
//
//   - APKX_PACKAGE: package/bundle identifier (e.g. com.example.app)
//   - APKX_OUTPUT:  absolute path where the command MUST write the APK/IPA
//
// Example (Android with gplaycli):
//
//   export APKX_ANDROID_DOWNLOAD_CMD='gplaycli -d \"$APKX_PACKAGE\" -f \"$APKX_OUTPUT\"'
//
// Example (iOS with ipatool):
//
//   export APKX_IOS_DOWNLOAD_CMD='ipatool download -b \"$APKX_PACKAGE\" -o \"$APKX_OUTPUT\"'
//
type PackageOptions struct {
	// Package is the Android package name or iOS bundle identifier.
	Package string
	// Platform is either "android" or "ios" (defaults to "android").
	Platform string
	// Optional explicit output directory (same semantics as Options.OutputDir).
	OutputDir string
	// Whether to enable MITM patching where supported.
	MITM bool
}

// extractXAPK extracts a XAPK file (which is a ZIP archive) and returns
// the path to the main APK file. The main APK is typically the largest APK
// that is not a split APK (split APKs often have names like "split_config.xxx.apk").
func extractXAPK(xapkPath, extractDir string) (string, error) {
	// Open the XAPK file as a ZIP archive
	r, err := zip.OpenReader(xapkPath)
	if err != nil {
		return "", fmt.Errorf("failed to open XAPK as ZIP: %w", err)
	}
	defer r.Close()

	// Find all APK files in the archive
	type apkInfo struct {
		path     string
		size     int64
		isSplit  bool
	}
	var apkFiles []apkInfo

	for _, f := range r.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".apk") {
			isSplit := strings.Contains(f.Name, "split_") || strings.Contains(f.Name, "config.")
			apkFiles = append(apkFiles, apkInfo{
				path:    f.Name,
				size:    int64(f.UncompressedSize64),
				isSplit: isSplit,
			})
		}
	}

	if len(apkFiles) == 0 {
		return "", fmt.Errorf("no APK files found in XAPK archive")
	}

	// Find the main APK: prefer non-split APKs, then largest by size
	var mainAPK apkInfo
	for _, apk := range apkFiles {
		if mainAPK.path == "" {
			mainAPK = apk
			continue
		}
		// Prefer non-split APKs
		if !apk.isSplit && mainAPK.isSplit {
			mainAPK = apk
		} else if apk.isSplit == mainAPK.isSplit {
			// If both are split or both are not split, prefer larger
			if apk.size > mainAPK.size {
				mainAPK = apk
			}
		}
	}

	// Extract the main APK
	mainAPKPath := filepath.Join(extractDir, filepath.Base(mainAPK.path))
	
	for _, f := range r.File {
		if f.Name == mainAPK.path {
			rc, err := f.Open()
			if err != nil {
				return "", fmt.Errorf("failed to open %s in XAPK: %w", f.Name, err)
			}
			defer rc.Close()

			outFile, err := os.Create(mainAPKPath)
			if err != nil {
				return "", fmt.Errorf("failed to create output file %s: %w", mainAPKPath, err)
			}
			defer outFile.Close()

			if _, err := io.Copy(outFile, rc); err != nil {
				return "", fmt.Errorf("failed to extract %s: %w", f.Name, err)
			}
			
			if err := outFile.Close(); err != nil {
				return "", fmt.Errorf("failed to close output file: %w", err)
			}
			rc.Close()
			break
		}
	}

	return mainAPKPath, nil
}

// Run executes an apkX scan for the given options using the embedded
// apkX analysis engine instead of spawning the apkx binary.
func Run(opts Options) (*Result, error) {
	if strings.TrimSpace(opts.InputPath) == "" {
		return nil, fmt.Errorf("InputPath is required")
	}
	if _, err := os.Stat(opts.InputPath); err != nil {
		return nil, fmt.Errorf("input file not found: %s", opts.InputPath)
	}

	resultsRoot := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsRoot == "" {
		resultsRoot = "new-results"
	}

	outDir := opts.OutputDir
	if outDir == "" {
		base := filepath.Base(opts.InputPath)
		name := strings.TrimSuffix(base, filepath.Ext(base))
		outDir = filepath.Join(resultsRoot, "apkx", name)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create output dir %s: %w", outDir, err)
	}

	ext := strings.ToLower(filepath.Ext(opts.InputPath))
	start := time.Now()

	var mitmPatchedAPK string
	switch ext {
	case ".apk":
		// Use adaptive worker count: fewer workers for better memory management
		// Default to 4 workers (conservative) to prevent server overload
		workers := 4
		if runtime.NumCPU() <= 2 {
			workers = 2 // Very conservative for small VPS
		} else if runtime.NumCPU() <= 4 {
			workers = 3
		}
		
		// Allow override via environment variable
		if envWorkers := os.Getenv("APKX_WORKERS"); envWorkers != "" {
			if w, err := strconv.Atoi(envWorkers); err == nil && w > 0 {
				workers = w
			}
		}
		
		cfg := &apkxanalyzer.Config{
			APKPath:      opts.InputPath,
			OutputDir:    outDir,
			PatternsPath: "",
			Workers:      workers, // Conservative default to prevent OOM
			HTMLOutput:   true,
			JanusScan:    true,
		}
		scanner := apkxanalyzer.NewAPKScanner(cfg)
		if err := scanner.Run(); err != nil {
			return &Result{
				ReportDir: outDir,
				LogFile:   filepath.Join(outDir, "results.json"),
				Duration:  time.Since(start),
			}, fmt.Errorf("apk analysis failed: %w", err)
		}
		
		// If MITM patching was requested, look for patched APK in output directory
		if opts.MITM {
			mitmPatchedAPK = findMITMPatchedAPK(outDir, opts.InputPath)
		}
	case ".xapk":
		// Extract XAPK and find the main APK file
		extractDir, err := os.MkdirTemp("", "autoar-xapk-extract-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp directory for XAPK extraction: %w", err)
		}
		defer os.RemoveAll(extractDir) // Clean up extraction directory

		mainAPKPath, err := extractXAPK(opts.InputPath, extractDir)
		if err != nil {
			return nil, fmt.Errorf("failed to extract XAPK: %w", err)
		}

		// Process the extracted main APK
		cfg := &apkxanalyzer.Config{
			APKPath:      mainAPKPath,
			OutputDir:    outDir,
			PatternsPath: "",
			Workers:      runtime.NumCPU(),
			HTMLOutput:   true,
			JanusScan:    true,
		}
		scanner := apkxanalyzer.NewAPKScanner(cfg)
		if err := scanner.Run(); err != nil {
			return &Result{
				ReportDir: outDir,
				LogFile:   filepath.Join(outDir, "results.json"),
				Duration:  time.Since(start),
			}, fmt.Errorf("apk analysis failed: %w", err)
		}
	case ".ipa":
		cfg := &apkxanalyzer.Config{
			OutputDir:    outDir,
			PatternsPath: "",
			Workers:      runtime.NumCPU(),
			HTMLOutput:   true,
		}
		ios := apkxanalyzer.NewIOSAnalyzer(cfg)
		if err := ios.AnalyzeIPA(opts.InputPath); err != nil {
			return &Result{
				ReportDir: outDir,
				LogFile:   filepath.Join(outDir, "results.json"),
				Duration:  time.Since(start),
			}, fmt.Errorf("ipa analysis failed: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported file extension %q (only .apk, .xapk, and .ipa are supported)", ext)
	}

	return &Result{
		ReportDir:     outDir,
		LogFile:       filepath.Join(outDir, "results.json"),
		Duration:      time.Since(start),
		MITMPatchedAPK: mitmPatchedAPK,
	}, nil
}

// findMITMPatchedAPK searches for MITM patched APK files in the output directory.
// Common naming patterns: *-patched.apk, *-mitm.apk, *-mitm-patched.apk, or patched-*.apk
func findMITMPatchedAPK(outDir, originalAPK string) string {
	baseName := strings.TrimSuffix(filepath.Base(originalAPK), filepath.Ext(originalAPK))
	
	// Common patterns for MITM patched APKs
	patterns := []string{
		filepath.Join(outDir, baseName+"-patched.apk"),
		filepath.Join(outDir, baseName+"-mitm.apk"),
		filepath.Join(outDir, baseName+"-mitm-patched.apk"),
		filepath.Join(outDir, "patched-"+filepath.Base(originalAPK)),
		filepath.Join(outDir, "mitm-"+filepath.Base(originalAPK)),
		filepath.Join(outDir, "mitm-patched-"+filepath.Base(originalAPK)),
	}
	
	// Also search for any .apk files in the output directory that contain "patched" or "mitm"
	entries, err := os.ReadDir(outDir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".apk") {
				name := strings.ToLower(entry.Name())
				if strings.Contains(name, "patched") || strings.Contains(name, "mitm") {
					fullPath := filepath.Join(outDir, entry.Name())
					if info, err := os.Stat(fullPath); err == nil && info.Size() > 0 {
						return fullPath
					}
				}
			}
		}
	}
	
	// Check specific patterns
	for _, pattern := range patterns {
		if info, err := os.Stat(pattern); err == nil && info.Size() > 0 {
			return pattern
		}
	}
	
	return ""
}

// RunFromPackage downloads an APK/IPA for the given package identifier using
// an external helper command (configured via environment variables) and then
// runs the standard apkX analysis on the downloaded file.
func RunFromPackage(opts PackageOptions) (*Result, error) {
	pkg := strings.TrimSpace(opts.Package)
	if pkg == "" {
		return nil, fmt.Errorf("Package is required")
	}

	platform := strings.ToLower(strings.TrimSpace(opts.Platform))
	if platform == "" {
		platform = "android"
	}

	// Use a dedicated temporary directory for downloads.
	tmpDir, err := os.MkdirTemp("", "autoar-apkx-dl-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp download directory: %w", err)
	}
	// We keep the directory for inspection; caller may clean up separately.

	var inputPath string

	switch platform {
	case "android":
		// Use pure-Go ApkPure client (no Rust/binary dependency) to fetch the APK.
		client, err := downloader.NewApkPureClient()
		if err != nil {
			return nil, fmt.Errorf("failed to create ApkPure client: %w", err)
		}
		inputPath, err = client.DownloadAPKByPackage(context.Background(), pkg, tmpDir)
		if err != nil {
			return nil, err
		}
	case "ios":
		// Use ipatool Go library (via internal wrapper) to fetch the IPA.
		client, err := iosstore.NewFromEnv()
		if err != nil {
			return nil, err
		}
		inputPath, err = client.DownloadIPAByBundleID(context.Background(), pkg, tmpDir)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported platform %q (expected \"android\" or \"ios\")", platform)
	}

	// Reuse the existing Run logic for local file analysis.
	return Run(Options{
		InputPath: inputPath,
		OutputDir: opts.OutputDir,
		MITM:      opts.MITM,
	})
}
