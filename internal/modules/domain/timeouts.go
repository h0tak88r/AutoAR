package domain

import "github.com/h0tak88r/AutoAR/internal/modules/utils"

// nucleiTimeoutDomain returns the nuclei phase timeout in seconds for domain scans.
// Configured via the dashboard Settings page (timeout_nuclei),
// or AUTOAR_TIMEOUT_NUCLEI env var. Default: 1200s (20 min).
func nucleiTimeoutDomain() int {
	return utils.GetTimeout("nuclei", 1200)
}

// backupTimeoutDomain returns the backup/fuzzuli phase timeout in seconds.
// Fuzzuli with method=all can stall for hours against firewalled hosts;
// this cap ensures Phase 4 (Nuclei, Reflection, etc.) is never blocked.
// Configured via the dashboard Settings page (timeout_backup),
// or AUTOAR_TIMEOUT_BACKUP env var. Default: 600s (10 min).
func backupTimeoutDomain() int {
	return utils.GetTimeout("backup", 600)
}
