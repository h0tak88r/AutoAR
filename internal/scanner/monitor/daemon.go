package monitor

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"github.com/h0tak88r/AutoAR/internal/logger"
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
// targets and sends webhook alerts + writes DB change records on content change.

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
		logger.GetLogger().Infof("[URL-MONITOR] Daemon started")
		// Run once immediately on start
		checkAllURLTargets()
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				checkAllURLTargets()
			case <-stopURLDaemon:
				logger.GetLogger().Infof("[URL-MONITOR] Daemon stopped")
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
		logger.GetLogger().Infof("[URL-MONITOR] Failed to list targets: %v", err)
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
		logger.GetLogger().Infof("[URL-MONITOR] Failed to fetch %s: %v", t.URL, err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.GetLogger().Infof("[URL-MONITOR] Failed to read body for %s: %v", t.URL, err)
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
		logger.GetLogger().Infof("[URL-MONITOR] First check for %s — storing baseline hash", t.URL)
		_ = db.UpdateMonitorTargetLastRun(t.ID, currentHash, false)
		return
	}

	if currentHash == t.LastHash {
		_ = db.UpdateMonitorTargetLastRun(t.ID, currentHash, false)
		return
	}

	// Content changed → record in DB + send webhook alert
	logger.GetLogger().Infof("[URL-MONITOR]   Change detected for %s (hash)", t.URL)

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
		" **URL Monitor Alert**\n**URL**: %s\n**Change**: content hash changed\n**Old hash**: `%s`\n**New hash**: `%s`\n**Timestamp**: %s",
		t.URL, oldShort, newShort, time.Now().Format(time.RFC3339),
	)
	logger.GetLogger().Infof("[URL-MONITOR] Alert: %s", msg)
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
		logger.GetLogger().Infof("[URL-MONITOR] Invalid regex for %s: %v", t.URL, err)
		return
	}

	text := string(body)
	// Use ALL matches and pick the MAX (latest date / highest version / lexically
	// largest), not FindString's first match. A page that lists multiple matching
	// items (e.g. blog posts) often re-orders them between requests — picking the
	// first match flapped the baseline, e.g. blackline.com/blog/ alerting 23 → 24 →
	// 23 → 24 inside 4 minutes as the featured post shuffled. The max is stable
	// regardless of ordering.
	matches := re.FindAllString(text, -1)
	if len(matches) == 0 {
		return // nothing to compare; don't churn the baseline on a transient empty fetch
	}
	match := maxRegexMatch(matches)

	// Switched from hash strategy — old last_hash is hex; establish fresh regex baseline.
	baseline := t.LastHash
	if looksLikeSHA256Hex(baseline) {
		baseline = ""
	}

	if baseline == "" {
		logger.GetLogger().Infof("[URL-MONITOR] First check for %s — storing baseline regex match", t.URL)
		_ = db.UpdateMonitorTargetLastRun(t.ID, match, false)
		return
	}

	// Forward-only watermark: a regex monitor is for "latest X" — a backward jump
	// (older date / lower version) is almost always page-ordering noise, not a real
	// rollback. Skip the alert AND don't advance the baseline so the baseline stays
	// at the genuine high-water-mark; the next refresh comparing against it will be
	// stable. Use compareWatchValue which parses dates (ISO + "Jan 2, 2006") and
	// falls back to lexical compare for arbitrary patterns.
	cmp := compareWatchValue(match, baseline)
	if cmp == 0 {
		_ = db.UpdateMonitorTargetLastRun(t.ID, match, false)
		return
	}
	if cmp < 0 {
		// Match went backwards — keep the baseline, don't alert, don't advance.
		return
	}

	logger.GetLogger().Infof("[URL-MONITOR]   Change detected for %s (regex)", t.URL)

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
		" **URL Monitor Alert** (regex)\n**URL**: %s\n**Change**: matched text changed\n**Old**: `%s`\n**New**: `%s`\n**Timestamp**: %s",
		t.URL, oldDisp, newDisp, time.Now().Format(time.RFC3339),
	)
	logger.GetLogger().Infof("[URL-MONITOR] Alert: %s", msg)
	utils.SendMonitorWebhook(msg)
}

// maxRegexMatch returns the "largest" of a non-empty slice of regex matches,
// using compareWatchValue (date-aware where possible, lexical otherwise). This
// makes "latest update" monitoring stable on pages that list multiple matching
// items in a varying order.
func maxRegexMatch(matches []string) string {
	best := matches[0]
	for _, m := range matches[1:] {
		if compareWatchValue(m, best) > 0 {
			best = m
		}
	}
	return best
}

// compareWatchValue returns >0 if a>b, <0 if a<b, 0 if equal. Tries common date
// formats first so chronological ordering wins ("Jul 1, 2026" > "Jun 30, 2026"
// even though lexically Jul<Jun). Falls back to plain string compare for
// arbitrary patterns (version strings, hashes, etc.) where ASCII order is fine.
func compareWatchValue(a, b string) int {
	ta, aOK := tryParseWatchDate(a)
	tb, bOK := tryParseWatchDate(b)
	if aOK && bOK {
		return ta.Compare(tb)
	}
	return strings.Compare(a, b)
}

func tryParseWatchDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	formats := []string{
		"2006-01-02",
		"Jan 2, 2006",
		"January 2, 2006",
		"Jan 02, 2006",
		"02 Jan 2006",
		time.RFC3339,
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
