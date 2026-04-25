package decompiler

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/internal/tools/apkx/utils"
)

type Jadx struct {
	BinaryPath string
}

func NewJadx() (*Jadx, error) {
	path, err := exec.LookPath("jadx")
	if err != nil {
		return nil, fmt.Errorf("%sJadx is required but was not found in PATH. Please install jadx and ensure the 'jadx' binary is available on PATH.%s", utils.ColorWarning, utils.ColorEnd)
	}

	return &Jadx{BinaryPath: path}, nil
}

func (j *Jadx) Decompile(apkFile, outputDir string, args string) error {
	// ── Thread count ──────────────────────────────────────────────────────────
	// jadx default is 3 threads; each thread holds a large DEX parse tree in
	// memory. On a VPS with no swap, 3 threads can easily OOM. Cap at 2.
	jadxThreads := "2"
	if t := os.Getenv("JADX_THREADS"); t != "" {
		jadxThreads = t
	}

	// Default arguments to improve decompilation success rate
	cmdArgs := []string{
		apkFile,
		"-d", outputDir,
		"-j", jadxThreads,
		"--no-debug-info",
		"--no-inline-methods",
		"--no-replace-consts",
		"--escape-unicode",
		"--deobf",
		"--show-bad-code",
	}

	if args != "" {
		extraArgs := strings.Split(args, " ")
		cmdArgs = append(cmdArgs, extraArgs...)
	}

	// ── JVM heap cap ──────────────────────────────────────────────────────────
	// jadx's launcher script sets -XX:MaxRAMPercentage=70 by default.
	// On a 12 GB VPS that's ~8.4 GB JVM heap — way over available memory when
	// the rest of AutoAR is also running, and there's zero swap.
	// We override via JAVA_OPTS (the jadx launcher respects it).
	// Default: 1500 MB. Override with JADX_MAX_HEAP_MB env var.
	maxHeapMB := "1500"
	if m := os.Getenv("JADX_MAX_HEAP_MB"); m != "" {
		maxHeapMB = m
	}
	javaOpts := fmt.Sprintf("-Xmx%sm -Xms128m -XX:+UseG1GC -XX:+ExitOnOutOfMemoryError", maxHeapMB)

	// ── Timeout ───────────────────────────────────────────────────────────────
	// Very large APKs can loop forever. Default: 15 minutes. Override with
	// JADX_TIMEOUT_MINUTES env var.
	timeoutMins := 15
	if t := os.Getenv("JADX_TIMEOUT_MINUTES"); t != "" {
		if n, err := fmt.Sscanf(t, "%d", &timeoutMins); n == 0 || err != nil {
			timeoutMins = 15
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMins)*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, j.BinaryPath, cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "JAVA_OPTS="+javaOpts)

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("jadx timed out after %d minutes (set JADX_TIMEOUT_MINUTES to increase)", timeoutMins)
	}
	if err != nil {
		// Check if output directory was created and contains decompiled files
		if _, statErr := os.Stat(filepath.Join(outputDir, "sources")); statErr == nil {
			// Even if there were some errors, if we have decompiled files, continue
			return nil
		}
		return err
	}

	return nil
}

func DownloadJadx() error {
	jadxURL := "https://github.com/skylot/jadx/releases/download/v1.2.0/jadx-1.2.0.zip"

	// Create jadx directory in user's home
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	jadxDir := filepath.Join(home, ".apkleaks", "jadx")
	if err := os.MkdirAll(jadxDir, 0755); err != nil {
		return err
	}

	// Download and extract jadx
	resp, err := http.Get(jadxURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	zipBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	zipReader, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return err
	}

	for _, file := range zipReader.File {
		path := filepath.Join(jadxDir, file.Name)
		if file.FileInfo().IsDir() {
			os.MkdirAll(path, 0755)
			continue
		}
		if err := extractFile(file, path); err != nil {
			return err
		}
	}

	// Make jadx executable
	jadxBin := filepath.Join(jadxDir, "bin", "jadx")
	return os.Chmod(jadxBin, 0755)
}

func extractFile(file *zip.File, dest string) error {
	rc, err := file.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, rc)
	return err
}
