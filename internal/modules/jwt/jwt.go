package jwt

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	jwthack "github.com/h0tak88r/AutoAR/v3/internal/tools/jwthack"
)

// RunScan performs a JWT security scan using the embedded jwthack engine
// and writes a JSON report to:
//
//	$AUTOAR_RESULTS_DIR/jwt-scan/vulnerabilities/jwt/jwt_scan_<ts>.json
func RunScan(args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("no arguments provided to jwt scan")
	}

	token := args[0]
	var (
		wordlist         string
		maxCrackAttempts int
		skipCrack        bool
		skipPayloads     bool
		testAttacks      bool
	)

	// Parse remaining flags in a minimal, jwt-hack-compatible way.
	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--skip-crack":
			skipCrack = true
		case "--skip-payloads":
			skipPayloads = true
		case "--test-attacks", "-t":
			testAttacks = true
		case "-w", "--wordlist":
			if i+1 < len(args) {
				wordlist = args[i+1]
				i++
			}
		case "--max-crack-attempts":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 {
					maxCrackAttempts = n
				}
				i++
			}
		}
	}

	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "new-results"
	}

	jwtDir := filepath.Join(resultsDir, "jwt-scan", "vulnerabilities", "jwt")
	if err := os.MkdirAll(jwtDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create JWT results directory: %w", err)
	}

	filename := fmt.Sprintf("jwt_scan_%d.json", time.Now().Unix())
	outPath := filepath.Join(jwtDir, filename)

	opts := jwthack.ScanOptions{
		Token:            token,
		WordlistPath:     wordlist,
		MaxCrackAttempts: maxCrackAttempts,
		SkipCrack:        skipCrack,
		SkipPayloads:     skipPayloads,
		TestAttacks:      testAttacks,
	}

	res, err := jwthack.Scan(opts)
	if err != nil {
		return "", err
	}

	f, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("failed to create JWT results file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		return "", fmt.Errorf("failed to write JWT results: %w", err)
	}

	return outPath, nil
}
