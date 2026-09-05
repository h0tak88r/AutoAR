package api

import (
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

// Scan-initiator registry: records which dashboard user started a scan so the
// runner can stamp ScanRecord.CreatedBy. It is populated synchronously in the
// request goroutine (via generateScanID, before the scan goroutine is launched)
// and consumed exactly once by the runner when it creates the DB row — so there
// is no race with CreateScan. Automated scans (pipeline, monitors, nuclei-watch)
// record "system"; when nothing is recorded the initiator resolves to "".
var (
	scanInitiatorMu sync.Mutex
	scanInitiators  = map[string]string{}
)

const scanInitiatorCap = 1024

// currentUsername returns the authenticated dashboard username for a request, or
// "" when auth is disabled or no user is attached.
func currentUsername(c *gin.Context) string {
	if c == nil {
		return ""
	}
	return strings.TrimSpace(c.GetString("auth_sub"))
}

// recordScanInitiator associates a scanID with the user that started it. Bounded
// so orphaned entries (an id that never becomes a scan) can't grow without limit.
func recordScanInitiator(scanID, username string) {
	if scanID == "" {
		return
	}
	scanInitiatorMu.Lock()
	defer scanInitiatorMu.Unlock()
	if len(scanInitiators) >= scanInitiatorCap {
		n := 0
		for k := range scanInitiators { // map order is randomized; evict a batch
			delete(scanInitiators, k)
			if n++; n >= 64 {
				break
			}
		}
	}
	scanInitiators[scanID] = username
}

// takeScanInitiator returns and removes the recorded initiator for a scan ("" if
// none was recorded, e.g. an automated/system scan).
func takeScanInitiator(scanID string) string {
	scanInitiatorMu.Lock()
	defer scanInitiatorMu.Unlock()
	u := scanInitiators[scanID]
	delete(scanInitiators, scanID)
	return u
}
