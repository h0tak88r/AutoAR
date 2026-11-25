package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/scanner/smarty"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// POST /api/smarty/run — native CVE-2026-82531 verifier over live hosts.
//
// Runs internal/scanner/smarty against every live host in the database (or a
// caller-supplied host list): homepage fingerprint gate, then the
// warm→poison→trigger chain with a computed-output payload (arithmetic echo
// only — no commands, no data access; see the package doc). Hits webhook the
// findings channel with the catalog scope tag like every other scan family.
//
// Body (all optional): {"hosts": ["https://x.example"], "params": ["name","q"]}

type smartyRunReq struct {
	Hosts  []string `json:"hosts"`
	Params []string `json:"params"`
	Paths  []string `json:"paths"`

	Name string `json:"name"`
}

func apiSmartyRun(c *gin.Context) {
	var req smartyRunReq
	_ = c.ShouldBindJSON(&req)

	scanID := fmt.Sprintf("smarty-%s-%s", time.Now().Format("20060102150405"), generateScanID(nil)[:8])
	recordScanInitiator(scanID, currentUsername(c))
	recordScanName(scanID, req.Name)

	// Run through the tracked-worker runner (NOT a bare goroutine): the
	// orphan reaper fails active rows with no in-memory worker after ~15min
	// idle, and slow corpus pages exceed that — the first two sweeps were
	// reaped mid-run exactly this way.
	command := "inprocess:smarty verifier=cve-2026-82531"
	utils.SafeGo("smarty-run:"+scanID, func() {
		RunScanInProcessWithCommand(scanID, "smarty", "global-subdomains", command, func() error {
			return runSmartyScan(scanID, req)
		})
	})

	c.JSON(http.StatusOK, gin.H{"message": "Smarty CVE-2026-82531 verifier started", "scan_id": scanID, "status": "started"})
}

func runSmartyScan(scanID string, req smartyRunReq) error {
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
	defer cancel()

	hits := []smarty.Result{}
	var mu = make(chan struct{}, 1)
	mu <- struct{}{}

	opts := smarty.Options{Params: req.Params, Paths: req.Paths}
	onHit := func(r smarty.Result) {
		<-mu
		hits = append(hits, r)
		mu <- struct{}{}

		tag := raceScopeTag(raceProgramsForHost(strings.TrimPrefix(strings.TrimPrefix(r.Host, "https://"), "http://")))
		msg := fmt.Sprintf("🚨 **CVE-2026-82531 Smarty RCE CONFIRMED — %s** (`%s` · app %s · param `%s`)\n• Evidence: computed marker `%s` executed via poisoned cache\n• Scope: %s",
			r.Host, r.Host, r.App, r.Param, r.Evidence, tag)
		if err := utils.SendPurposeWebhookErr("findings", msg); err != nil {
			logger.GetLogger().Errorf("[SMARTY] hit webhook failed for %s: %v", r.Host, err)
		}
	}

	hostBatch := func(hosts []string) {
		smarty.Run(ctx, hosts, opts, onHit)
	}

	if len(req.Hosts) > 0 {
		hostBatch(req.Hosts)
	} else {
		// Keyset pages over live hosts — same stream the global nuclei runs
		// use, processed page-by-page so 400k+ hosts never sit in memory.
		// Transient page errors retry (the first corpus run died at 17min on
		// an unretried page error with the failure point unobservable).
		var cursor int64
		pages, swept := 0, 0
		for {
			var (
				subs []db.GlobalSubdomain
				next int64
				err  error
			)
			for attempt := 0; attempt < 3; attempt++ {
				if subs, next, err = db.ListLiveSubdomainsAfter(cursor, 5000); err == nil {
					break
				}
				time.Sleep(time.Duration(attempt+1) * 3 * time.Second)
			}
			if err != nil {
				logger.GetLogger().Errorf("[SMARTY] live-host dump failed after cursor %d (page %d, %d hosts swept): %v", cursor, pages, swept, err)
				return fmt.Errorf("live-host dump failed after cursor %d: %w", cursor, err)
			}
			if len(subs) == 0 {
				break
			}
			var hosts []string
			for _, s := range subs {
				if u := s.BestURL(); u != "" {
					hosts = append(hosts, u)
				}
			}
			hostBatch(hosts)
			cursor = next
			pages++
			swept += len(hosts)
			<-mu
			hitsSoFar := len(hits)
			mu <- struct{}{}
			// Progress heartbeat: observability for multi-hour sweeps, and a
			// last_update/stats touch so the row never looks stale mid-run.
			logger.GetLogger().Infof("[SMARTY] %s: page %d — %d hosts swept, %d hit(s) so far", scanID, pages, swept, hitsSoFar)
			_ = db.UpdateScanStats(scanID, hitsSoFar, 0)
		}
	}

	<-mu
	n := len(hits)
	mu <- struct{}{}
	if err := utils.WriteJSONToScanDir(scanID, "smarty-cve-2026-82531.json", hits); err != nil {
		logger.GetLogger().Errorf("[SMARTY] results write failed: %v", err)
	}
	_ = db.UpdateScanStats(scanID, n, 0)
	logger.GetLogger().Infof("[SMARTY] scan %s completed: %d vulnerable host(s)", scanID, n)
	return nil
}
