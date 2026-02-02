package decompiler

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
	// Default arguments to improve decompilation success rate
	cmdArgs := []string{
		apkFile,
		"-d", outputDir,
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

	cmd := exec.Command(j.BinaryPath, cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
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
