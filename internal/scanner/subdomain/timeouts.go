package subdomain

import "github.com/h0tak88r/AutoAR/internal/utils"

// zerodaysTimeout returns the zerodays phase timeout in seconds.
// Configured via the dashboard Settings page (timeout_zerodays),
// or AUTOAR_TIMEOUT_ZERODAYS env var. Default: 600s (10 min).
// Set to 0 for unlimited.
func zerodaysTimeout() int {
	return utils.GetTimeout("zerodays", 600)
}

// backupTimeout returns the backup/fuzzuli phase timeout in seconds.
// Fuzzuli with method=all generates a very large wordlist per host and
// can hang for hours on slow/firewalled targets.
// Configured via the dashboard Settings page (timeout_backup),
// or AUTOAR_TIMEOUT_BACKUP env var. Default: 600s (10 min).
func backupTimeout() int {
	return utils.GetTimeout("backup", 600)
}

// nucleiTimeout returns the nuclei phase timeout in seconds.
// Configured via the dashboard Settings page (timeout_nuclei),
// or AUTOAR_TIMEOUT_NUCLEI env var. Default: 1200s (20 min).
func nucleiTimeout() int {
	return utils.GetTimeout("nuclei", 1200)
}
