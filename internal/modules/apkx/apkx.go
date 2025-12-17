package apkx

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	ReportDir string
	LogFile   string
	Duration  time.Duration
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

	switch ext {
	case ".apk":
		cfg := &apkxanalyzer.Config{
			APKPath:      opts.InputPath,
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
		return nil, fmt.Errorf("unsupported file extension %q (only .apk and .ipa are supported)", ext)
	}

	return &Result{
		ReportDir: outDir,
		LogFile:   filepath.Join(outDir, "results.json"),
		Duration:  time.Since(start),
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
