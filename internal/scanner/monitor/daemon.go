package monitor

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/utils"
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

// checkTarget fetches a single URL. For strategy "hash" it compares SHA-256 of the body;
// for "regex" it compares the first regex match (or full match) to the stored baseline.
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

	strategy := strings.ToLower(strings.TrimSpace(t.Strategy))
	if strategy == "" {
		strategy = "hash"
	}
	if strategy == "regex" {
		checkTargetRegex(t, body)
		return
	}

	checkTargetHash(t, body)
}

func checkTargetHash(t db.MonitorTarget, body []byte) {
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
	log.Printf("[URL-MONITOR] ⚠️  Change detected for %s (hash)", t.URL)

	detail, _ := json.Marshal(map[string]string{
		"strategy": "hash",
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

	oldShort, newShort := t.LastHash, currentHash
	if len(oldShort) > 8 {
		oldShort = oldShort[:8]
	}
	if len(newShort) > 8 {
		newShort = newShort[:8]
	}
	msg := fmt.Sprintf(
		"🔔 **URL Monitor Alert**\n**URL**: %s\n**Change**: content hash changed\n**Old hash**: `%s`\n**New hash**: `%s`\n**Timestamp**: %s",
		t.URL, oldShort, newShort, time.Now().Format(time.RFC3339),
	)
	log.Printf("[URL-MONITOR] Alert: %s", msg)
	utils.SendMonitorWebhook(msg)
}

// looksLikeSHA256Hex reports whether s is a 64-char hex string (legacy hash baseline).
func looksLikeSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func defaultRegexPattern() string {
	return `([A-Z][a-z]{2,9} [0-9]{1,2}, [0-9]{4}|[0-9]{4}-[0-9]{2}-[0-9]{2})`
}

func checkTargetRegex(t db.MonitorTarget, body []byte) {
	pat := strings.TrimSpace(t.Pattern)
	if pat == "" {
		pat = defaultRegexPattern()
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		log.Printf("[URL-MONITOR] Invalid regex for %s: %v", t.URL, err)
		return
	}

	text := string(body)
	match := re.FindString(text)

	// Switched from hash strategy — old last_hash is hex; establish fresh regex baseline.
	baseline := t.LastHash
	if looksLikeSHA256Hex(baseline) {
		baseline = ""
	}

	if baseline == "" {
		log.Printf("[URL-MONITOR] First check for %s — storing baseline regex match", t.URL)
		_ = db.UpdateMonitorTargetLastRun(t.ID, match, false)
		return
	}

	if match == baseline {
		_ = db.UpdateMonitorTargetLastRun(t.ID, match, false)
		return
	}

	log.Printf("[URL-MONITOR] ⚠️  Change detected for %s (regex)", t.URL)

	detailObj := map[string]string{
		"strategy":  "regex",
		"old_match": baseline,
		"new_match": match,
	}
	if len(pat) <= 200 {
		detailObj["pattern"] = pat
	}
	detail, _ := json.Marshal(detailObj)

	_ = db.InsertMonitorChange(&db.MonitorChange{
		TargetType: "url",
		TargetID:   t.ID,
		Domain:     t.URL,
		ChangeType: "content_changed",
		Detail:     string(detail),
		Notified:   true,
	})
	_ = db.UpdateMonitorTargetLastRun(t.ID, match, true)

	oldDisp, newDisp := baseline, match
	if len(oldDisp) > 80 {
		oldDisp = oldDisp[:80] + "…"
	}
	if len(newDisp) > 80 {
		newDisp = newDisp[:80] + "…"
	}
	msg := fmt.Sprintf(
		"🔔 **URL Monitor Alert** (regex)\n**URL**: %s\n**Change**: matched text changed\n**Old**: `%s`\n**New**: `%s`\n**Timestamp**: %s",
		t.URL, oldDisp, newDisp, time.Now().Format(time.RFC3339),
	)
	log.Printf("[URL-MONITOR] Alert: %s", msg)
	utils.SendMonitorWebhook(msg)
}
