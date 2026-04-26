package domain

import (
	"os"
	"strconv"
)

// nucleiTimeoutDomain returns the nuclei phase timeout in seconds for domain scans.
// Override with AUTOAR_TIMEOUT_NUCLEI env var.
// Set to 0 to disable the cap entirely (for large/slow targets).
// Default: 1200s (20 minutes).
func nucleiTimeoutDomain() int {
	v := os.Getenv("AUTOAR_TIMEOUT_NUCLEI")
	if v == "" {
		return 1200
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 1200
	}
	return n // 0 = unlimited
}

// backupTimeoutDomain returns the backup/fuzzuli phase timeout in seconds.
// Fuzzuli with method=all can stall for hours against firewalled hosts;
// this cap ensures Phase 4 (Nuclei, Reflection, etc.) is never blocked.
// Override with AUTOAR_TIMEOUT_BACKUP env var. Default: 600s (10 min).
func backupTimeoutDomain() int {
	v := os.Getenv("AUTOAR_TIMEOUT_BACKUP")
	if v == "" {
		return 600
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 600
	}
	return n // 0 = unlimited
}
