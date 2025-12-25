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

	apkxanalyzer "github.com/h0tak88r/AutoAR/v3/internal/tools/apkx/analyzer"
	"github.com/h0tak88r/AutoAR/v3/internal/tools/apkx/downloader"
	"github.com/h0tak88r/AutoAR/v3/internal/tools/apkx/mitm"
	iosstore "github.com/h0tak88r/AutoAR/v3/internal/tools/ipatool"
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
	
	// Check if we're running in Docker by checking if /app exists and is writable
	isDocker := false
	if _, err := os.Stat("/app"); err == nil {
		// /app exists, check if we can write to it
		if err := os.MkdirAll("/app", 0755); err == nil {
			testPath := "/app/.test-write"
			if f, err := os.Create(testPath); err == nil {
				f.Close()
				os.Remove(testPath)
				isDocker = true
			}
		}
	}
	
	if resultsRoot == "" {
		// No env var set - use relative path for native, Docker path for Docker
		if isDocker {
			resultsRoot = "/app/new-results"
		} else {
			if cwd, err := os.Getwd(); err == nil {
				resultsRoot = filepath.Join(cwd, "new-results")
			} else {
				resultsRoot = "new-results"
			}
		}
	} else {
		// Env var is set - validate it
		// If we're not in Docker and the path is absolute but not /app/..., convert to relative
		if !isDocker && filepath.IsAbs(resultsRoot) && !strings.HasPrefix(resultsRoot, "/app") {
			// Absolute path like /new-results but not in Docker - convert to relative
			// This handles cases where AUTOAR_RESULTS_DIR=/new-results but we're running natively
			if cwd, err := os.Getwd(); err == nil {
				resultsRoot = filepath.Join(cwd, "new-results")
			} else {
				resultsRoot = "new-results"
			}
		} else if strings.HasPrefix(resultsRoot, "/app") && !isDocker {
			// Docker path but not in Docker - use relative
			if cwd, err := os.Getwd(); err == nil {
				resultsRoot = filepath.Join(cwd, "new-results")
			} else {
				resultsRoot = "new-results"
			}
		}
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
		
		// If MITM patching was requested, patch the APK using pure Go implementation
		if opts.MITM {
			fmt.Printf("[MITM] ========================================\n")
			fmt.Printf("[MITM] Starting APK patching for MITM inspection...\n")
			fmt.Printf("[MITM] Input APK: %s\n", opts.InputPath)
			fmt.Printf("[MITM] Output directory: %s\n", outDir)
			
			patcher, err := mitm.NewPatcher()
			if err != nil {
				fmt.Printf("[ERROR] MITM patcher initialization failed: %v\n", err)
				fmt.Printf("[ERROR] This usually means apktool or Java is not installed/available\n")
				fmt.Printf("[ERROR] Install apktool: https://ibotpeaches.github.io/Apktool/\n")
				fmt.Printf("[ERROR] Install Java: sudo apt install openjdk-17-jre-headless\n")
			} else {
				fmt.Printf("[MITM] Patcher initialized successfully\n")
				fmt.Printf("[MITM] apktool path: %s\n", patcher.GetApktoolPath())
				fmt.Printf("[MITM] java path: %s\n", patcher.GetJavaPath())
				
				patchedPath, err := patcher.PatchAPK(opts.InputPath, outDir)
				if err != nil {
					fmt.Printf("[ERROR] MITM patching failed: %v\n", err)
					fmt.Printf("[ERROR] Check logs above for apktool decode/encode errors\n")
				} else if patchedPath != "" {
					fmt.Printf("[MITM] Patcher returned path: %s\n", patchedPath)
					// Verify the file exists
					if info, statErr := os.Stat(patchedPath); statErr == nil {
						mitmPatchedAPK = patchedPath
						fmt.Printf("[OK] MITM patched APK created: %s (size: %d bytes, %.2f MB)\n", 
							patchedPath, info.Size(), float64(info.Size())/1024/1024)
						fmt.Printf("[MITM] ========================================\n")
					} else {
						fmt.Printf("[ERROR] MITM patched APK file not found at: %s (stat error: %v)\n", patchedPath, statErr)
						fmt.Printf("[MITM] ========================================\n")
					}
				} else {
					fmt.Printf("[WARN] MITM patching returned empty path (no error, but no file)\n")
					fmt.Printf("[MITM] ========================================\n")
				}
			}
		} else {
			fmt.Printf("[DEBUG] MITM patching not requested (opts.MITM = false)\n")
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
