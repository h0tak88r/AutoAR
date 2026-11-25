package api

// Fingerprint backfill: probe every live host once (one GET, same-host
// redirects followed) for its tech stack, page title and server header, so
// PoC-day can target "hosts running product X" across the whole corpus. Before
// this only hosts that had a per-domain tech scan were fingerprinted — 19,394
// of 622,565 live hosts (3.1%) on 2026-10-18.
//
// Runs in the background in batches with a pause between them, oldest rows
// first; once the backlog is empty it only picks up newly live hosts.
// Kill switch: FINGERPRINT_BACKFILL=off (env or setting). Tuning:
// FINGERPRINT_THREADS (default 50), FINGERPRINT_RATE (req/s, default 150).

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/scanner/tech"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

const (
	fpBatchSize  = 1000
	fpBatchPause = 15 * time.Second
	fpIdlePause  = 30 * time.Minute
	fpOffPause   = 5 * time.Minute
)

// fpProbe is a seam for tests.
var fpProbe = tech.FingerprintHosts

// fpStats is the backfill's progress since boot.
type fpStats struct {
	Running  bool   `json:"running"`
	Batches  int64  `json:"batches"`
	Probed   int64  `json:"probed"`
	Answered int64  `json:"answered"`
	LastAt   int64  `json:"last_at"`
	LastErr  string `json:"last_error,omitempty"`
	Idle     bool   `json:"idle"` // backlog empty: only new live hosts are probed
}

var (
	fpMu    sync.Mutex
	fpState fpStats
	fpOnce  sync.Once
)

func fingerprintBackfillEnabled() bool {
	if v, _ := db.GetSetting("FINGERPRINT_BACKFILL"); strings.EqualFold(strings.TrimSpace(v), "off") {
		return false
	}
	return !strings.EqualFold(strings.TrimSpace(os.Getenv("FINGERPRINT_BACKFILL")), "off")
}

func fpIntSetting(key string, def, min, max int) int {
	for _, v := range []string{os.Getenv(key), func() string { s, _ := db.GetSetting(key); return s }()} {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= min && n <= max {
			return n
		}
	}
	return def
}

// fingerprintBackfillSnapshot returns a copy of the progress counters.
func fingerprintBackfillSnapshot() fpStats {
	fpMu.Lock()
	defer fpMu.Unlock()
	return fpState
}

// StartFingerprintBackfill launches the loop once per process.
func StartFingerprintBackfill() {
	fpOnce.Do(func() {
		utils.SafeGo("fingerprint-backfill", func() {
			time.Sleep(2 * time.Minute) // after boot-time scans/reconcilers settle
			for {
				if !fingerprintBackfillEnabled() {
					time.Sleep(fpOffPause)
					continue
				}
				n := 0
				utils.GuardedRun("fingerprint-backfill:batch", func() { n = fingerprintBackfillBatch() })
				if n == 0 {
					time.Sleep(fpIdlePause)
				} else {
					time.Sleep(fpBatchPause)
				}
			}
		})
	})
}

// fingerprintBackfillBatch probes one batch and stores the results; returns
// how many hosts it took from the backlog.
func fingerprintBackfillBatch() int {
	targets, err := db.FingerprintBacklog(fpBatchSize)
	fpMu.Lock()
	fpState.LastAt = time.Now().UTC().Unix()
	if err != nil {
		fpState.LastErr = err.Error()
		fpMu.Unlock()
		return 0
	}
	fpState.Idle = len(targets) == 0
	if len(targets) == 0 {
		fpMu.Unlock()
		return 0
	}
	fpState.Running = true
	fpMu.Unlock()
	defer func() {
		fpMu.Lock()
		fpState.Running = false
		fpMu.Unlock()
	}()

	byInput := make(map[string]int64, len(targets))
	inputs := make([]string, 0, len(targets))
	norm := func(s string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), "/") }
	for _, t := range targets {
		u := strings.TrimSpace(t.URL)
		if u == "" {
			u = "https://" + t.Subdomain
		}
		byInput[norm(u)] = t.ID
		inputs = append(inputs, u)
	}
	fps, perr := fpProbe(inputs, tech.FingerprintOptions{
		Threads:   fpIntSetting("FINGERPRINT_THREADS", 50, 1, 200),
		RateLimit: fpIntSetting("FINGERPRINT_RATE", 150, 1, 1000),
	})
	now := time.Now().UTC().Unix()
	results := make(map[int64]db.FingerprintResult, len(targets))
	for _, t := range targets {
		results[t.ID] = db.FingerprintResult{ID: t.ID, At: now} // stamped even when silent
	}
	answered := 0
	for _, fp := range fps {
		id, ok := byInput[norm(fp.Input)]
		if !ok {
			continue
		}
		answered++
		results[id] = db.FingerprintResult{ID: id, Techs: strings.Join(fp.Techs, ","), Title: fp.Title, Server: fp.Server, At: now}
	}
	if perr != nil && answered == 0 {
		// The probe itself failed (not "nobody answered"): leave the batch
		// un-stamped so it is retried, and back off.
		fpMu.Lock()
		fpState.LastErr = perr.Error()
		fpMu.Unlock()
		logger.GetLogger().Infof("[FINGERPRINT] probe failed (batch kept for retry): %v", perr)
		return 0
	}
	batch := make([]db.FingerprintResult, 0, len(results))
	for _, r := range results {
		batch = append(batch, r)
	}
	if err := db.SaveFingerprints(batch); err != nil {
		fpMu.Lock()
		fpState.LastErr = err.Error()
		fpMu.Unlock()
		return 0
	}
	fpMu.Lock()
	fpState.Batches++
	fpState.Probed += int64(len(targets))
	fpState.Answered += int64(answered)
	fpState.LastErr = ""
	batches := fpState.Batches
	fpMu.Unlock()
	if batches%20 == 1 {
		logger.GetLogger().Infof("[FINGERPRINT] batch %d: %d host(s) probed, %d answered", batches, len(targets), answered)
	}
	return len(targets)
}
