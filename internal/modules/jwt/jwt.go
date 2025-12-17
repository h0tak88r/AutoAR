package jwt

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// RunScan executes `jwt-hack scan` with the provided arguments
// and writes the output to a timestamped file under:
//
//	$AUTOAR_RESULTS_DIR/jwt-scan/vulnerabilities/jwt/jwt_hack_<ts>.txt
func RunScan(args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("no arguments provided to jwt-hack scan")
	}

	if _, err := exec.LookPath("jwt-hack"); err != nil {
		return "", fmt.Errorf("jwt-hack binary not found in PATH; ensure it is installed in the image")
	}

	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "new-results"
	}

	jwtDir := filepath.Join(resultsDir, "jwt-scan", "vulnerabilities", "jwt")
	if err := os.MkdirAll(jwtDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create JWT results directory: %w", err)
	}

	filename := fmt.Sprintf("jwt_hack_%d.txt", time.Now().Unix())
	outPath := filepath.Join(jwtDir, filename)

	outFile, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("failed to create JWT results file: %w", err)
	}
	defer outFile.Close()

	cmdArgs := append([]string{"scan"}, args...)
	cmd := exec.Command("jwt-hack", cmdArgs...)
	cmd.Stdout = outFile
	cmd.Stderr = outFile

	if err := cmd.Run(); err != nil {
		return outPath, fmt.Errorf("jwt-hack scan failed: %w", err)
	}

	return outPath, nil
}
