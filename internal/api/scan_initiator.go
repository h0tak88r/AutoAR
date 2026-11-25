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

// Scan display metadata registry: same lifecycle as scanInitiators — recorded
// synchronously by the launch endpoint (or by an early PATCH from the
// dashboard), consumed exactly once by the runner at CreateScan.
type pendingScanMeta struct {
	name, desc       string
	hasName, hasDesc bool
}

var (
	scanNameMu sync.Mutex
	scanNames  = map[string]pendingScanMeta{}
)

// stashScanMeta merges name and/or description (nil = leave) for a scan
// whose DB row may not exist yet.
func stashScanMeta(scanID string, name, desc *string) {
	if scanID == "" || (name == nil && desc == nil) {
		return
	}
	scanNameMu.Lock()
	defer scanNameMu.Unlock()
	if len(scanNames) >= scanInitiatorCap {
		n := 0
		for k := range scanNames {
			delete(scanNames, k)
			if n++; n >= 64 {
				break
			}
		}
	}
	m := scanNames[scanID]
	if name != nil {
		m.name, m.hasName = *name, true
	}
	if desc != nil {
		m.desc, m.hasDesc = *desc, true
	}
	scanNames[scanID] = m
}

// recordScanName associates a scanID with the operator-supplied display name.
func recordScanName(scanID, name string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	stashScanMeta(scanID, &name, nil)
}

// takeScanMeta returns and removes the recorded metadata.
func takeScanMeta(scanID string) pendingScanMeta {
	scanNameMu.Lock()
	defer scanNameMu.Unlock()
	m := scanNames[scanID]
	delete(scanNames, scanID)
	return m
}

// dropScanMeta forgets stashed metadata once it has reached the DB row.
func dropScanMeta(scanID string) {
	scanNameMu.Lock()
	defer scanNameMu.Unlock()
	delete(scanNames, scanID)
}
