package apkx

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	apkxanalyzer "github.com/h0tak88r/AutoAR/internal/tools/apkx/analyzer"
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
