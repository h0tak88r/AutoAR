package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/h0tak88r/AutoAR/internal/db"
	naabutool "github.com/h0tak88r/AutoAR/internal/tools/naabu"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// Port-surface corpus: naabu top-100 connect scan over live hosts, persisted
// to host_ports, so network/appliance CVEs (NetScaler, WinBox, management
// consoles) become sweepable instead of web-only.

const portsBatchSize = 4000 // hosts per naabu call (10-min window per batch)

type portsRunReq struct {
	Root string `json:"root"` // optional: limit to one root
	Name string `json:"name"`
}

func apiRunPortSurface(c *gin.Context) {
	_ = db.Init()
	var req portsRunReq
	_ = c.ShouldBindJSON(&req)
	scanID, _, err := launchPortSurface(req.Root, req.Name, currentUsername(c))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "started", "scan_id": scanID,
		"message": "Port-surface scan started"})
}

// launchPortSurface is the dashboard/MCP-shared port-surface scan (blank root
// = whole live-host corpus).
func launchPortSurface(rawRoot, name, actor string) (string, string, error) {
	target := "port-surface"
	if r := strings.TrimSpace(rawRoot); r != "" {
		target = r
	}
	scanID := "ports-" + time.Now().Format("20060102150405") + "-" + generateScanID(nil)[:8]
	recordScanInitiator(scanID, actor)
	recordScanName(scanID, name)
	command := fmt.Sprintf("inprocess:ports target=%s", target)
	utils.SendPurposeWebhookErr("scans", "📡 **Port-surface scan** — `"+nonEmptyStr(name, target)+"` launched (top-100 ports).")

	go RunScanInProcessWithCommand(scanID, "ports", target, command, func() error {
		stdLog(scanID, "[INFO] Streaming live hosts for %s…", target)
		var hosts []string
		if target == "port-surface" {
			// Keyset stream over every live host (same pager the smarty corpus
			// sweep uses), hosts only — naabu wants bare hostnames.
			var cursor int64
			for {
				subs, next, err := db.ListLiveSubdomainsAfter(cursor, 5000)
				if err != nil || len(subs) == 0 {
					break
				}
				for _, sub := range subs {
					hosts = append(hosts, hostOfURL(sub.BestURL()))
				}
				cursor = next
			}
		} else {
			if urls, err := db.ListLiveSubdomainURLs(target); err == nil {
				for _, u := range urls {
					hosts = append(hosts, hostOfURL(u))
				}
			}
		}
		if len(hosts) == 0 {
			stdLog(scanID, "[WARN] no live hosts found for %s", target)
			return fmt.Errorf("no live hosts")
		}
		stdLog(scanID, "[INFO] %d live host(s) — scanning top-100 ports in batches of %d…", len(hosts), portsBatchSize)

		openTotal := 0
		for off := 0; off < len(hosts); off += portsBatchSize {
			end := off + portsBatchSize
			if end > len(hosts) {
				end = len(hosts)
			}
			batch := hosts[off:end]
			tf, err := os.CreateTemp("", "ports-batch-*.txt")
			if err != nil {
				stdLog(scanID, "[WARN] temp file: %v", err)
				continue
			}
			for _, h := range batch {
				fmt.Fprintln(tf, h)
			}
			tf.Close()

			outFile := filepath.Join(os.TempDir(), fmt.Sprintf("ports-out-%s-%d.txt", scanID, off))
			_, records, err := naabutool.ScanFromFile(tf.Name(), 50, outFile)
			os.Remove(tf.Name())
			os.Remove(outFile)
			if err != nil {
				stdLog(scanID, "[WARN] batch %d-%d failed: %v", off, end, err)
			}
			now := time.Now().UTC().Unix()
			for _, r := range records {
				if err := db.UpsertHostPort(r.Host, r.Port, r.Protocol, now); err == nil {
					openTotal++
				}
			}
			stdLog(scanID, "[INFO] batch %d-%d / %d — %d open port(s) so far", off, end, len(hosts), openTotal)
			_ = db.UpdateScanStats(scanID, openTotal, 0)
		}
		stdLog(scanID, "[OK] port surface complete: %d open port(s) recorded", openTotal)
		utils.SendMonitorWebhook(fmt.Sprintf(
			"📡 **Port-surface scan complete** — `%s`\nHosts: %d · open ports recorded: %d",
			target, len(hosts), openTotal))
		return nil
	})
	return scanID, "port-surface scan launched for " + target, nil
}

func hostOfURL(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexAny(u, "/"); i > 0 {
		u = u[:i]
	}
	return u
}

// apiListHostPorts serves GET /api/ports?port=&host=&limit=
func apiListHostPorts(c *gin.Context) {
	_ = db.Init()
	port, _ := strconv.Atoi(c.Query("port"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	rows, total, err := db.ListHostPorts(c.Query("host"), port, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if rows == nil {
		rows = []*db.HostPort{}
	}
	c.JSON(http.StatusOK, gin.H{"ports": rows, "total": total})
}
