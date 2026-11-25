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
	"github.com/h0tak88r/AutoAR/internal/scanner/zammad"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// POST /api/zammad/run — native CVE-2026-102489 verifier over live hosts.
//
// Runs internal/scanner/zammad: HTTP fingerprint gate ("zammad" on the
// homepage), then the benign WebSocket probe (single {"event":"base"} frame;
// vulnerable builds leak the Sessions::Event::Base inspect with @clients,
// patched 7.2.0+ answer a generic error). Hits webhook the findings channel
// with the catalog scope tag. Runs through the tracked-worker runner so the
// orphan reaper can't fail the row on slow pages (the smarty lesson).
//
// Body (all optional): {"hosts": ["https://x.example"]}

type zammadRunReq struct {
	Hosts []string `json:"hosts"`
	Name  string   `json:"name"`
}

func apiZammadRun(c *gin.Context) {
	var req zammadRunReq
	_ = c.ShouldBindJSON(&req)

	scanID := fmt.Sprintf("zammad-%s-%s", time.Now().Format("20060102150405"), generateScanID(nil)[:8])
	recordScanInitiator(scanID, currentUsername(c))
	recordScanName(scanID, req.Name)

	command := "inprocess:zammad verifier=cve-2026-102489"
	utils.SafeGo("zammad-run:"+scanID, func() {
		RunScanInProcessWithCommand(scanID, "zammad", "global-subdomains", command, func() error {
			return runZammadScan(scanID, req)
		})
	})

	c.JSON(http.StatusOK, gin.H{"message": "Zammad CVE-2026-102489 verifier started", "scan_id": scanID, "status": "started"})
}

func runZammadScan(scanID string, req zammadRunReq) error {
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
	defer cancel()

	hits := []zammad.Result{}
	var mu = make(chan struct{}, 1)
	mu <- struct{}{}

	onHit := func(r zammad.Result) {
		<-mu
		hits = append(hits, r)
		mu <- struct{}{}

		tag := raceScopeTag(raceProgramsForHost(strings.TrimPrefix(strings.TrimPrefix(r.Host, "https://"), "http://")))
		msg := fmt.Sprintf("🚨 **CVE-2026-102489 Zammad WS session disclosure CONFIRMED — %s**\n• Evidence: %s (chains to session hijack → RCE)\n• Scope: %s",
			r.Host, r.Evidence, tag)
		if err := utils.SendPurposeWebhookErr("findings", msg); err != nil {
			logger.GetLogger().Errorf("[ZAMMAD] hit webhook failed for %s: %v", r.Host, err)
		}
	}

	hostBatch := func(hosts []string) {
		zammad.Run(ctx, hosts, zammad.Options{}, onHit)
	}

	if len(req.Hosts) > 0 {
		hostBatch(req.Hosts)
	} else {
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
				logger.GetLogger().Errorf("[ZAMMAD] live-host dump failed after cursor %d (page %d, %d hosts swept): %v", cursor, pages, swept, err)
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
			logger.GetLogger().Infof("[ZAMMAD] %s: page %d — %d hosts swept, %d hit(s) so far", scanID, pages, swept, hitsSoFar)
			_ = db.UpdateScanStats(scanID, hitsSoFar, 0)
		}
	}

	<-mu
	n := len(hits)
	mu <- struct{}{}
	if err := utils.WriteJSONToScanDir(scanID, "zammad-cve-2026-102489.json", hits); err != nil {
		logger.GetLogger().Errorf("[ZAMMAD] results write failed: %v", err)
	}
	_ = db.UpdateScanStats(scanID, n, 0)
	logger.GetLogger().Infof("[ZAMMAD] scan %s completed: %d vulnerable host(s)", scanID, n)
	return nil
}
