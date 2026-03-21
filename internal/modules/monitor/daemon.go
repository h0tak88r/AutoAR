package monitor

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/modules/db"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
)

// ─── URL Monitor Daemon ───────────────────────────────────────────────────────
// Real goroutine-based daemon that periodically checks all is_running URL
// targets and sends Discord alerts + writes DB change records on content change.

var (
	urlDaemonRunning bool
	urlDaemonMu      sync.Mutex
	stopURLDaemon    chan struct{}
	urlDaemonWg      sync.WaitGroup
)

// StartURLMonitorDaemon launches the URL monitoring daemon if not already running.
func StartURLMonitorDaemon() {
	urlDaemonMu.Lock()
	defer urlDaemonMu.Unlock()
	if urlDaemonRunning {
		return
	}
	stopURLDaemon = make(chan struct{})
	urlDaemonRunning = true
	urlDaemonWg.Add(1)
	go func() {
		defer urlDaemonWg.Done()
		defer func() {
			urlDaemonMu.Lock()
			urlDaemonRunning = false
			urlDaemonMu.Unlock()
		}()
		log.Printf("[URL-MONITOR] Daemon started")
		// Run once immediately on start
		checkAllURLTargets()
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				checkAllURLTargets()
			case <-stopURLDaemon:
				log.Printf("[URL-MONITOR] Daemon stopped")
				return
			}
		}
	}()
}

// StopURLMonitorDaemon signals the daemon to stop and waits for it.
func StopURLMonitorDaemon() {
	urlDaemonMu.Lock()
	if !urlDaemonRunning {
		urlDaemonMu.Unlock()
		return
	}
	close(stopURLDaemon)
	urlDaemonMu.Unlock()
	urlDaemonWg.Wait()
}

// IsURLDaemonRunning returns true if the monitor daemon goroutine is active.
func IsURLDaemonRunning() bool {
	urlDaemonMu.Lock()
	defer urlDaemonMu.Unlock()
	return urlDaemonRunning
}

// checkAllURLTargets iterates over all is_running=true targets and checks them.
func checkAllURLTargets() {
	targets, err := db.ListMonitorTargets()
	if err != nil {
		log.Printf("[URL-MONITOR] Failed to list targets: %v", err)
		return
	}

	client := &http.Client{Timeout: 20 * time.Second}
	var wg sync.WaitGroup
	for _, t := range targets {
		if !t.IsRunning {
			continue
		}
		t := t // capture range var
		wg.Add(1)
		go func() {
			defer wg.Done()
			checkTarget(client, t)
		}()
	}
	wg.Wait()
}

// checkTarget fetches a single URL, computes a SHA-256 hash, and records a
// change to the DB + fires a Discord alert if the content differs.
func checkTarget(client *http.Client, t db.MonitorTarget) {
	resp, err := client.Get(t.URL)
	if err != nil {
		log.Printf("[URL-MONITOR] Failed to fetch %s: %v", t.URL, err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[URL-MONITOR] Failed to read body for %s: %v", t.URL, err)
		return
	}

	rawHash := sha256.Sum256(body)
	currentHash := fmt.Sprintf("%x", rawHash)

	// First run — just store the baseline hash, no alert
	if t.LastHash == "" {
		log.Printf("[URL-MONITOR] First check for %s — storing baseline hash", t.URL)
		_ = db.UpdateMonitorTargetLastRun(t.ID, currentHash, false)
		return
	}

	if currentHash == t.LastHash {
		_ = db.UpdateMonitorTargetLastRun(t.ID, currentHash, false)
		return
	}

	// Content changed → record in DB + send Discord alert
	log.Printf("[URL-MONITOR] ⚠️  Change detected for %s", t.URL)

	detail, _ := json.Marshal(map[string]string{
		"old_hash": t.LastHash,
		"new_hash": currentHash,
	})
	_ = db.InsertMonitorChange(&db.MonitorChange{
		TargetType: "url",
		TargetID:   t.ID,
		Domain:     t.URL,
		ChangeType: "content_changed",
		Detail:     string(detail),
		Notified:   true,
	})
	_ = db.UpdateMonitorTargetLastRun(t.ID, currentHash, true)

	// Send Discord webhook alert
	msg := fmt.Sprintf(
		"🔔 **URL Monitor Alert**\n**URL**: %s\n**Change**: content hash changed\n**Old hash**: `%s`\n**New hash**: `%s`\n**Timestamp**: %s",
		t.URL, t.LastHash[:8], currentHash[:8], time.Now().Format(time.RFC3339),
	)
	utils.SendWebhookLogAsync(msg)
}
