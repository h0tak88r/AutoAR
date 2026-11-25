package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/scanner/livehosts"
	"github.com/h0tak88r/AutoAR/internal/scanner/subdomains"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// Asset-discovery endpoints: a per-root subdomain+live discovery scan the
// operator can launch from the Scans page (with a custom name), and a feed of
// the newest discovered assets.

type discoverReq struct {
	Root    string `json:"root"`
	Name    string `json:"name"`
	Threads int    `json:"threads"`
}

// apiRunAssetDiscovery launches a tracked per-root discovery scan: passive
// subdomain enumeration, store, httpx liveness, and a "how many NEW" summary.
func apiRunAssetDiscovery(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()
	var req discoverReq
	_ = c.ShouldBindJSON(&req)
	scanID, _, err := launchAssetDiscovery(req.Root, req.Name, currentUsername(c))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "started", "scan_id": scanID,
		"message": "Asset discovery started"})
}

// launchAssetDiscovery is the dashboard/MCP-shared per-root discovery scan.
func launchAssetDiscovery(rawRoot, name, actor string) (string, string, error) {
	root := strings.ToLower(strings.TrimSpace(rawRoot))
	root = strings.TrimPrefix(strings.TrimPrefix(root, "https://"), "http://")
	root = strings.Trim(root, ". /")
	if root == "" || strings.ContainsAny(root, " \t\"'<>|;$`\\") || len(root) > 253 {
		return "", "", fmt.Errorf("a plain root domain is required (e.g. example.com)")
	}
	threads := 30
	scanID := "discover-" + time.Now().Format("20060102150405") + "-" + generateScanID(nil)[:8]
	recordScanInitiator(scanID, actor)
	recordScanName(scanID, name)
	command := fmt.Sprintf("inprocess:discover root=%s threads=%d", root, threads)
	utils.SendPurposeWebhookErr("scans", "🔍 **Asset discovery** — `"+root+"` ("+nonEmptyStr(name, scanID)+") launched.")

	go RunScanInProcessWithCommand(scanID, "subdomains", root, command, func() error {
		before, _ := db.CountSubdomains(root)
		stdLog(scanID, "[INFO] Enumerating subdomains for %s (threads %d)…", root, threads)
		subs, err := subdomains.EnumerateSubdomains(root, threads)
		if err != nil {
			stdLog(scanID, "[WARN] enumeration failed: %v", err)
			return err
		}
		if len(subs) > 0 {
			if ierr := db.BatchInsertSubdomains(root, subs, false); ierr != nil {
				stdLog(scanID, "[WARN] store subs failed: %v", ierr)
			}
		}
		stdLog(scanID, "[INFO] %d subdomain(s) found — probing liveness…", len(subs))
		liveRes, _ := livehosts.FilterLiveHosts(root, threads, true)
		liveN := 0
		if liveRes != nil {
			liveN = liveRes.LiveSubs
		}
		after, _ := db.CountSubdomains(root)
		newN := after - before
		if newN < 0 {
			newN = 0
		}
		stdLog(scanID, "[OK] discovery complete: %d subdomain(s), %d live, %d NEW asset(s)", len(subs), liveN, newN)
		utils.SendMonitorWebhook(fmt.Sprintf(
			"🔍 **Asset discovery complete** — `%s`\nSubdomains: %d · Live: %d · **New: %d**",
			root, len(subs), liveN, newN))
		return nil
	})
	return scanID, "asset discovery launched for " + root, nil
}

func nonEmptyStr(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

// apiDiscoveredAssets serves GET /api/subdomains/discovered — the newest
// assets in the DB (optionally scoped to the last N hours).
func apiDiscoveredAssets(c *gin.Context) {
	_ = db.Init()
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "168"))
	if hours <= 0 || hours > 24*30 {
		hours = 168
	}
	rows, err := db.ListRecentlyDiscoveredSubdomains(limit, hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if rows == nil {
		rows = []*db.DiscoveredSubdomain{}
	}
	c.JSON(http.StatusOK, gin.H{"assets": rows, "total": len(rows), "hours": hours})
}
