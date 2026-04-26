package gobot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/modules/db"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/h0tak88r/AutoAR/internal/modules/envloader"
	"github.com/h0tak88r/AutoAR/internal/modules/monitor"
	"github.com/h0tak88r/AutoAR/internal/modules/monitorsuggest"
	"github.com/h0tak88r/AutoAR/internal/modules/r2storage"
	"github.com/h0tak88r/AutoAR/internal/modules/subdomainmonitor"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
	"github.com/h0tak88r/AutoAR/internal/version"
)

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/config — returns public (non-secret) configuration to the UI
// ─────────────────────────────────────────────────────────────────────────────

func apiConfigHandler(c *gin.Context) {
	// Must match supabaseJWTAuth / dashboardAPIAuthEnforced (UI sends Bearer only when this is true).
	authOn := dashboardAPIAuthEnforced()
	getIntEnvOr := func(key string, def int) int {
		v := os.Getenv(key)
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return def
		}
		return n
	}
	c.JSON(http.StatusOK, gin.H{
		"version":                    version.Version,
		"r2_enabled":                 r2storage.IsEnabled(),
		"r2_public_url":              os.Getenv("R2_PUBLIC_URL"),
		"r2_bucket":                  os.Getenv("R2_BUCKET_NAME"),
		"auth_enabled":               authOn,
		"auth_provider":              "local",
		"db_type":                    getEnv("DB_TYPE", "postgresql"),
		"mode":                       getEnv("AUTOAR_MODE", "discord"),
		"monitor_webhook":            os.Getenv("MONITOR_WEBHOOK_URL"),
		"monitor_ai_available": strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY")) != "" ||
			strings.TrimSpace(os.Getenv("GEMINI_API_KEY")) != "",
		// Scan phase timeouts — read from DB first (survives redeployments), then env, then defaults.
		// DB key format: timeout_<name>. Env key format: AUTOAR_TIMEOUT_<NAME>.
		"timeout_zerodays": utils.GetTimeout("zerodays", 600),
		"timeout_nuclei":   utils.GetTimeout("nuclei", 1200),
		"timeout_backup":   utils.GetTimeout("backup", 600),
		"timeout_misconfig": utils.GetTimeout("misconfig", 1800),
		// Also include raw env fallbacks for legacy callers.
		"timeout_zerodays_env": getIntEnvOr("AUTOAR_TIMEOUT_ZERODAYS", 600),
		"timeout_nuclei_env":   getIntEnvOr("AUTOAR_TIMEOUT_NUCLEI", 1200),
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/settings — update dashboard configurations
// ─────────────────────────────────────────────────────────────────────────────

type UpdateSettingsBody struct {
	MonitorWebhook         string `json:"monitor_webhook"`
	OpenRouterKey          string `json:"openrouter_key"`
	GeminiKey              string `json:"gemini_key"`
	// Scan phase timeouts (seconds; 0 = unlimited, omit to keep current)
	TimeoutZerodays *int `json:"timeout_zerodays,omitempty"`
	TimeoutNuclei   *int `json:"timeout_nuclei,omitempty"`
	TimeoutBackup   *int `json:"timeout_backup,omitempty"`
	TimeoutMisconfig *int `json:"timeout_misconfig,omitempty"`
}

func apiUpdateSettingsHandler(c *gin.Context) {
	var body UpdateSettingsBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if body.MonitorWebhook != "" {
		_ = envloader.UpdateEnv("MONITOR_WEBHOOK_URL", strings.TrimSpace(body.MonitorWebhook))
	}
	if body.OpenRouterKey != "" {
		_ = envloader.UpdateEnv("OPENROUTER_API_KEY", strings.TrimSpace(body.OpenRouterKey))
	}
	if body.GeminiKey != "" {
		_ = envloader.UpdateEnv("GEMINI_API_KEY", strings.TrimSpace(body.GeminiKey))
	}

	// Scan phase timeouts — persist to DB (survives redeployments) AND apply
	// immediately in this process via os.Setenv (fallback for non-DB reads).
	saveTimeout := func(key, envKey string, val *int) {
		if val == nil {
			return
		}
		v := strconv.Itoa(*val)
		// 1. DB (primary, persists across redeployments)
		_ = db.SetSetting("timeout_"+key, v)
		// 2. env (immediate effect in this process)
		_ = os.Setenv(envKey, v)
	}
	saveTimeout("zerodays", "AUTOAR_TIMEOUT_ZERODAYS", body.TimeoutZerodays)
	saveTimeout("nuclei", "AUTOAR_TIMEOUT_NUCLEI", body.TimeoutNuclei)
	saveTimeout("backup", "AUTOAR_TIMEOUT_BACKUP", body.TimeoutBackup)
	saveTimeout("misconfig", "AUTOAR_TIMEOUT_MISCONFIG", body.TimeoutMisconfig)

	c.JSON(http.StatusOK, gin.H{"message": "Settings updated successfully", "ok": true})
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/dashboard/stats — aggregated real-time stats
// ─────────────────────────────────────────────────────────────────────────────

func apiDashboardStats(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()

	domains, _ := db.ListDomains()
	domainCount := len(domains)

	subdomainTotal := 0
	liveTotal := 0
	for _, d := range domains {
		subs, err := db.ListSubdomainsWithStatus(d)
		if err == nil {
			subdomainTotal += len(subs)
			for _, s := range subs {
				if s.IsLive {
					liveTotal++
				}
			}
		}
	}

	monitorTargets, _ := db.ListMonitorTargets()
	subMonitorTargets, _ := db.ListSubdomainMonitorTargets()

	runningMonitors := 0
	for _, t := range monitorTargets {
		if t.IsRunning {
			runningMonitors++
		}
	}
	for _, t := range subMonitorTargets {
		if t.IsRunning {
			runningMonitors++
		}
	}

	activeScansList, _ := db.ListActiveScans()
	activeScansList = mergeActiveScansFromMemory(activeScansList)
	activeScans := len(activeScansList)

	recentScans, _ := db.ListRecentScans(100)
	completedScans := 0
	for _, s := range recentScans {
		if s.Status == "done" || s.Status == "completed" {
			completedScans++
		}
	}

	recentChanges, _ := db.ListMonitorChanges("", 5)

	c.JSON(http.StatusOK, gin.H{
		"domains":          domainCount,
		"subdomains":       subdomainTotal,
		"live_subdomains":  liveTotal,
		"monitor_targets":  len(monitorTargets) + len(subMonitorTargets),
		"running_monitors": runningMonitors,
		"active_scans":     activeScans,
		"completed_scans":  completedScans,
		"recent_changes":   recentChanges,
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/domains — list tracked root domains
// ─────────────────────────────────────────────────────────────────────────────

func apiListDomains(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()

	domains, err := db.ListDomains()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	type DomainInfo struct {
		Domain         string `json:"domain"`
		SubdomainCount int    `json:"subdomain_count"`
		LiveCount      int    `json:"live_count"`
	}

	result := make([]DomainInfo, 0, len(domains))
	for _, d := range domains {
		subs, _ := db.ListSubdomainsWithStatus(d)
		liveCount := 0
		for _, s := range subs {
			if s.IsLive {
				liveCount++
			}
		}
		result = append(result, DomainInfo{
			Domain:         d,
			SubdomainCount: len(subs),
			LiveCount:      liveCount,
		})
	}

	c.JSON(http.StatusOK, gin.H{"domains": result, "total": len(result)})
}

// POST /api/domains — add a single domain to the database
func apiAddDomain(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()

	var body struct {
		Domain string `json:"domain"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	domain := strings.TrimSpace(body.Domain)
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}
	id, err := db.InsertOrGetDomain(domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"domain": domain, "id": id, "ok": true})
}

// POST /api/domains/bulk — add multiple domains in a single request
func apiAddDomainsBulk(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()

	var body struct {
		Domains []string `json:"domains"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if len(body.Domains) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domains list is required"})
		return
	}

	added := 0
	skipped := 0
	errors := []string{}
	for _, raw := range body.Domains {
		d := strings.TrimSpace(raw)
		if d == "" {
			skipped++
			continue
		}
		if _, err := db.InsertOrGetDomain(d); err != nil {
			errors = append(errors, d+": "+err.Error())
		} else {
			added++
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"added":   added,
		"skipped": skipped,
		"errors":  errors,
		"ok":      len(errors) == 0,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/domains/:domain/subdomains — list subdomains with status
// ─────────────────────────────────────────────────────────────────────────────

func apiListSubdomains(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}

	_ = db.Init()
	_ = db.EnsureSchema()

	subs, err := db.ListSubdomainsWithStatus(domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"domain":     domain,
		"subdomains": subs,
		"total":      len(subs),
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/subdomains — globally fetch subdomains matching search with pagination
// ─────────────────────────────────────────────────────────────────────────────

func apiAllSubdomainsPaginated(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit < 1 {
		limit = 50
	}
	// Guard against accidental huge requests that can starve the dashboard.
	if limit > 500 {
		limit = 500
	}
	search := strings.TrimSpace(c.Query("search"))
	techFilter := strings.TrimSpace(c.Query("tech"))
	cnameFilter := strings.TrimSpace(c.Query("cname"))
	statusFilter, _ := strconv.Atoi(c.Query("status"))

	offset := (page - 1) * limit

	_ = db.Init()
	_ = db.EnsureSchema()

	subs, total, err := db.ListAllSubdomainsPaginated(search, techFilter, cnameFilter, statusFilter, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if subs == nil {
		subs = make([]db.GlobalSubdomain, 0)
	}

	c.JSON(http.StatusOK, gin.H{
		"subdomains": subs,
		"total":      total,
		"page":       page,
		"limit":      limit,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/subdomains/cnames/retry — Retry CNAME resolution
// ─────────────────────────────────────────────────────────────────────────────

type RetryCnamesReq struct {
	MatchString string `json:"match_string"`
}

func apiRetryCnames(c *gin.Context) {
	var req RetryCnamesReq
	if err := c.ShouldBindJSON(&req); err != nil && err.Error() != "EOF" {
		// Ignore EOF to allow empty bodies
	}

	matchStr := strings.ToLower(strings.TrimSpace(req.MatchString))

	c.JSON(200, gin.H{"status": "started", "message": "CNAME resolution started in background"})

	go func() {
		log.Println("[INFO] Starting background CNAME retry for subdomains...")

		// Fetch all subdomains
		var allSubs []db.GlobalSubdomain
		limit := 10000
		for offset := 0; ; offset += limit {
			subs, _, err := db.ListAllSubdomainsPaginated("", "", "", -1, limit, offset)
			if err != nil {
				log.Printf("[ERROR] Failed to fetch subdomains: %v", err)
				break
			}
			if len(subs) == 0 {
				break
			}
			allSubs = append(allSubs, subs...)
		}

		if len(allSubs) == 0 {
			log.Println("[INFO] No subdomains found for CNAME retry.")
			return
		}

		log.Printf("[INFO] Initializing dnsx for %d subdomains...", len(allSubs))
		dnsClient, err := dnsx.New(dnsx.DefaultOptions)
		if err != nil {
			log.Printf("[ERROR] dnsx init failed: %v", err)
			return
		}

		var wg sync.WaitGroup
		jobs := make(chan db.GlobalSubdomain, len(allSubs))
		threads := 50 // Be gentle
		var foundMatches int32 = 0
		var mu sync.Mutex

		for i := 0; i < threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for sub := range jobs {
					// Only resolve if missing, or if a match string is provided, we can re-resolve to search for it.
					if matchStr == "" && sub.CNAMEs != "" && sub.CNAMEs != "—" {
						continue 
					}

					results, err := dnsClient.QueryOne(sub.Subdomain)
					if err != nil || results == nil || len(results.CNAME) == 0 {
						continue
					}
					
					cnamesStr := strings.Join(results.CNAME, ",")
					
					// Update DB if we actually found something
					_ = db.UpdateSubdomainCNAME(sub.Domain, sub.Subdomain, cnamesStr)
					
					// Check match string
					if matchStr != "" && strings.Contains(strings.ToLower(cnamesStr), matchStr) {
						mu.Lock()
						foundMatches++
						mu.Unlock()
						msg := fmt.Sprintf("🚨 **CNAME Match Found!**\nSubdomain: `%s`\nCNAME: `%s`\nMatch: `%s`", sub.Subdomain, cnamesStr, req.MatchString)
						utils.SendWebhookLogAsync(msg)
					}
				}
			}()
		}

		for _, s := range allSubs {
			jobs <- s
		}
		close(jobs)
		wg.Wait()
		
		log.Printf("[INFO] Background CNAME retry completed. Matches found: %d", foundMatches)
		if matchStr != "" {
			utils.SendWebhookLogAsync(fmt.Sprintf("✅ **CNAME Retry Completed**\nChecked %d subdomains for `%s`.\nFound %d matches.", len(allSubs), req.MatchString, foundMatches))
		}
	}()
}


// DELETE /api/domains/:domain — remove domain row, subdomains, related scans/artifacts, monitor rows, subdomain monitor target; R2 cleanup for those scans.
func apiDeleteDomain(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()

	domain := strings.TrimSpace(c.Param("domain"))
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}

	scanIDs, err := db.ListScanIDsForDomainRoot(domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	scansMutex.RLock()
	for _, id := range scanIDs {
		if s, ok := activeScans[id]; ok && s != nil {
			st := strings.ToLower(s.Status)
			if st == "running" || st == "starting" || st == "paused" || st == "cancelling" {
				scansMutex.RUnlock()
				c.JSON(http.StatusBadRequest, gin.H{"error": "a scan for this domain is still active; stop it first", "scan_id": id})
				return
			}
		}
	}
	scansMutex.RUnlock()

	keySet := make(map[string]struct{})
	for _, id := range scanIDs {
		mergeR2KeysForScanInto(id, keySet)
	}
	mergeWorkflowPrefixesIntoKeySet(domain, keySet)
	keys := r2KeySetToSlice(keySet)
	if err := r2storage.DeleteObjects(keys); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := db.DeleteDomain(domain); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	purgeScanMemoryByIDs(scanIDs)

	c.JSON(http.StatusOK, gin.H{
		"ok":              true,
		"domain":          domain,
		"deleted_scans":   len(scanIDs),
		"deleted_r2_keys": len(keys),
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/scans — list recent scans (active + historical)
// ─────────────────────────────────────────────────────────────────────────────

func apiListScans(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()

	active, err := db.ListActiveScans()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Safety net: if a scan is marked active in DB but there's no in-memory worker after restart,
	// mark it failed once it hasn't updated for a short grace window.
	if len(active) > 0 {
		cutoff := time.Now().Add(-2 * time.Minute)
		mem := map[string]struct{}{}
		scansMutex.RLock()
		for id := range activeScans {
			mem[id] = struct{}{}
		}
		scansMutex.RUnlock()

		updated := false
		for _, r := range active {
			if r == nil {
				continue
			}
			if _, ok := mem[r.ScanID]; ok {
				continue
			}
			if !r.LastUpdate.IsZero() && r.LastUpdate.Before(cutoff) {
				_ = db.UpdateScanStatus(r.ScanID, "failed")
				updated = true
			}
		}
		if updated {
			active, _ = db.ListActiveScans()
		}
	}

	recent, err := db.ListRecentScans(50)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	active = mergeActiveScansFromMemory(active)

	if active == nil {
		active = make([]*db.ScanRecord, 0)
	}
	if recent == nil {
		recent = make([]*db.ScanRecord, 0)
	}

	c.JSON(http.StatusOK, gin.H{
		"active_scans": active,
		"recent_scans": recent,
		"total":        len(active) + len(recent),
	})
}

// GET /api/scans/:id/artifacts — list indexed artifacts for a scan
func apiListScanArtifacts(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan id required"})
		return
	}
	artifacts, err := db.ListScanArtifacts(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if artifacts == nil {
		artifacts = make([]*db.ScanArtifact, 0)
	}
	c.JSON(http.StatusOK, gin.H{
		"scan_id":   id,
		"artifacts": artifacts,
		"total":     len(artifacts),
	})
}

func scanIsActiveInMemory(id string) bool {
	scansMutex.RLock()
	defer scansMutex.RUnlock()
	s, ok := activeScans[id]
	if !ok || s == nil {
		return false
	}
	st := strings.ToLower(s.Status)
	return st == "running" || st == "starting" || st == "paused" || st == "cancelling"
}

func mergeR2KeysForScanInto(scanID string, keySet map[string]struct{}) {
	scan, _ := db.GetScan(scanID)
	artifacts, _ := db.ListScanArtifacts(scanID)
	for _, a := range artifacts {
		if a == nil {
			continue
		}
		if a.R2Key != "" {
			keySet[a.R2Key] = struct{}{}
		} else if a.PublicURL != "" {
			if k := r2storage.ExtractObjectKeyFromPublicURL(a.PublicURL); k != "" {
				keySet[k] = struct{}{}
			}
		}
	}
	if scan != nil && scan.ResultURL != "" {
		if k := r2storage.ExtractObjectKeyFromPublicURL(scan.ResultURL); k != "" {
			keySet[k] = struct{}{}
		}
	}
}

func r2KeySetToSlice(keySet map[string]struct{}) []string {
	if len(keySet) == 0 {
		return nil
	}
	out := make([]string, 0, len(keySet))
	for k := range keySet {
		out = append(out, k)
	}
	return out
}

// mergeWorkflowTargetR2TreeIntoKeySet adds all R2 keys under workflow layout prefixes for target
// when no other scan row still references the same target (so shared domains are not wiped).
func mergeWorkflowTargetR2TreeIntoKeySet(scanID string, scan *db.ScanRecord, keySet map[string]struct{}) {
	if !r2storage.IsEnabled() || scan == nil || keySet == nil {
		return
	}
	target := strings.TrimSpace(scan.Target)
	if target == "" || strings.HasPrefix(target, "[") {
		return
	}
	others, err := db.CountScansWithTargetExcluding(scanID, target)
	if err != nil {
		log.Printf("[scan-delete] count scans for target %q: %v — skipping R2 prefix tree delete", target, err)
		return
	}
	if others > 0 {
		log.Printf("[scan-delete] target %q still referenced by %d other scan(s); R2 prefix tree kept (only this scan's indexed keys)", target, others)
		return
	}
	for _, prefix := range workflowScanR2Prefixes(target) {
		keys, err := r2storage.ListObjectKeysUnderPrefix(prefix)
		if err != nil {
			log.Printf("[scan-delete] list R2 prefix %q: %v", prefix, err)
			continue
		}
		for _, k := range keys {
			if k != "" {
				keySet[k] = struct{}{}
			}
		}
	}
	log.Printf("[scan-delete] queued full R2 workflow tree delete for target %q (last scan row for this target)", target)
}

// mergeWorkflowPrefixesIntoKeySet lists every key under workflow prefixes for a hostname (domain delete).
func mergeWorkflowPrefixesIntoKeySet(host string, keySet map[string]struct{}) {
	if !r2storage.IsEnabled() || keySet == nil {
		return
	}
	h := strings.TrimSpace(host)
	if h == "" {
		return
	}
	for _, prefix := range workflowScanR2Prefixes(h) {
		keys, err := r2storage.ListObjectKeysUnderPrefix(prefix)
		if err != nil {
			log.Printf("[domain-delete] list R2 prefix %q: %v", prefix, err)
			continue
		}
		for _, k := range keys {
			if k != "" {
				keySet[k] = struct{}{}
			}
		}
	}
}

func purgeScanMemoryByIDs(ids []string) {
	if len(ids) == 0 {
		return
	}
	scansMutex.Lock()
	for _, id := range ids {
		delete(activeScans, id)
	}
	scansMutex.Unlock()
	apiScansMutex.Lock()
	for _, id := range ids {
		delete(scanResults, id)
	}
	apiScansMutex.Unlock()
}

// performScanDelete removes R2 objects and the scan row; clears API result cache. Caller must ensure the scan is not active in memory.
func performScanDelete(scanID string) (int, error) {
	keySet := make(map[string]struct{})
	mergeR2KeysForScanInto(scanID, keySet)
	if scan, err := db.GetScan(scanID); err == nil && scan != nil {
		mergeWorkflowTargetR2TreeIntoKeySet(scanID, scan, keySet)
	}
	keys := r2KeySetToSlice(keySet)
	if err := r2storage.DeleteObjects(keys); err != nil {
		return 0, err
	}
	if err := db.DeleteScan(scanID); err != nil {
		return 0, err
	}

	// Delete the local scan directory (new-results/<scanID>/).
	// This only removes the scan-scoped result files — domains and subdomains
	// in the database are intentionally preserved.
	localDir := utils.GetScanResultsDir(scanID)
	if info, err := os.Stat(localDir); err == nil && info.IsDir() {
		if err := os.RemoveAll(localDir); err != nil {
			log.Printf("[WARN] Failed to delete local scan dir %s: %v", localDir, err)
		} else {
			log.Printf("[INFO] Deleted local scan dir: %s", localDir)
		}
	}

	purgeScanMemoryByIDs([]string{scanID})
	return len(keys), nil
}

// DELETE /api/scans/:id — delete scan record and indexed R2 artifacts
func apiDeleteScan(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan id required"})
		return
	}

	if scanIsActiveInMemory(id) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan is still active; stop it first"})
		return
	}

	nKeys, err := performScanDelete(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":              true,
		"scan_id":         id,
		"deleted_r2_keys": nKeys,
	})
}

// POST /api/scans/bulk-delete — body: { "scan_ids": ["..."] }
func apiBulkDeleteScans(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()

	var body struct {
		ScanIDs []string `json:"scan_ids"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	seen := make(map[string]struct{})
	var ids []string
	for _, id := range body.ScanIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no scan_ids provided"})
		return
	}

	deleted, skippedActive, failed := 0, 0, 0
	var firstErr string
	for _, id := range ids {
		if scanIsActiveInMemory(id) {
			skippedActive++
			continue
		}
		if _, err := performScanDelete(id); err != nil {
			failed++
			if firstErr == "" {
				firstErr = err.Error()
			}
			continue
		}
		deleted++
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":             failed == 0,
		"deleted":        deleted,
		"skipped_active": skippedActive,
		"failed":         failed,
		"error":          firstErr,
	})
}

// POST /api/scans/clear-all — delete every scan that is not active in memory (skipped_active in response).
func apiClearAllScans(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()

	allIDs, err := db.ListAllScanIDs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	deleted, skippedActive, failed := 0, 0, 0
	var firstErr string
	for _, id := range allIDs {
		if scanIsActiveInMemory(id) {
			skippedActive++
			continue
		}
		if _, err := performScanDelete(id); err != nil {
			failed++
			if firstErr == "" {
				firstErr = err.Error()
			}
			continue
		}
		deleted++
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":             failed == 0,
		"deleted":        deleted,
		"skipped_active": skippedActive,
		"failed":         failed,
		"error":          firstErr,
	})
}

// POST /api/scans/:id/cancel — stop a running scan (API child process or Discord cancel ctx)
func apiCancelScan(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan id required"})
		return
	}
	if err := CancelScanByID(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": "cancel requested"})
}

// POST /api/scans/:id/pause — SIGSTOP on API scan child (Unix only)
func apiPauseScan(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan id required"})
		return
	}
	if err := PauseScanByID(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": "paused"})
}

// POST /api/scans/:id/resume — SIGCONT after pause (Unix only)
func apiResumeScan(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan id required"})
		return
	}
	if err := ResumeScanByID(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": "resumed"})
}

// POST /api/scans/:id/rescan — re-run a completed/failed scan with the same command.
func apiRescan(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan id required"})
		return
	}

	_ = db.Init()
	record, err := db.GetScan(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not found: " + err.Error()})
		return
	}
	if record.Command == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan has no stored command — cannot rescan"})
		return
	}
	// Only rescan completed or failed scans (not running/paused ones).
	st := strings.ToLower(record.Status)
	if st == "running" || st == "starting" || st == "paused" {
		c.JSON(http.StatusConflict, gin.H{"error": "scan is still active — cancel it first before rescanning"})
		return
	}

	// ── In-process scans (domain_run, subdomain_run, …) ──────────────────────
	// These store "inprocess:<scanType> target=<target>" as their Command.
	// There is no external binary to re-exec; delegate to runInProcessRescan.
	if strings.HasPrefix(record.Command, "inprocess:") {
		newScanID, ok := runInProcessRescan(record.ScanType, record.Target)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "in-process scan type " + record.ScanType + " does not support rescan yet"})
			return
		}
		log.Printf("[rescan] Re-running in-process scan for %s (original: %s) → new scan ID: %s", record.Target, id, newScanID)
		c.JSON(http.StatusOK, gin.H{
			"ok":          true,
			"new_scan_id": newScanID,
			"target":      record.Target,
			"scan_type":   record.ScanType,
			"command":     fmt.Sprintf("inprocess:%s target=%s", record.ScanType, record.Target),
			"message":     "Rescan started",
		})
		return
	}

	// ── External-binary scans (legacy / apkx / …) ────────────────────────────
	// Parse the stored command string back into a slice.
	// The command is stored as a shell-joined string (space-separated tokens; the binary path
	// is always the first element).
	parts := strings.Fields(record.Command)
	if len(parts) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not parse stored command"})
		return
	}
	// Replace the binary path with the current binary to handle path changes.
	parts[0] = getAutoarScriptPath()

	// APK rescans from uploaded files can fail if the original temporary path moved/expired.
	// Try to recover a matching file from the persistent uploads directory.
	if strings.EqualFold(strings.TrimSpace(record.ScanType), "apkx") {
		if updated, recovered, recoverErr := recoverAPKRescanInput(parts, record.Target); recoverErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": recoverErr.Error()})
			return
		} else if recovered {
			parts = updated
		}
	}

	newScanID := generateScanID()
	go executeScan(newScanID, parts, record.ScanType)

	log.Printf("[rescan] Re-running scan for %s (original: %s) → new scan ID: %s", record.Target, id, newScanID)
	c.JSON(http.StatusOK, gin.H{
		"ok":          true,
		"new_scan_id": newScanID,
		"target":      record.Target,
		"scan_type":   record.ScanType,
		"command":     strings.Join(parts, " "),
		"message":     "Rescan started",
	})
}

func recoverAPKRescanInput(parts []string, target string) ([]string, bool, error) {
	if len(parts) < 2 {
		return parts, false, nil
	}
	inputIdx := -1
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "-i" || parts[i] == "--input" {
			inputIdx = i + 1
			break
		}
	}
	if inputIdx < 0 {
		// Package-based APK scans use -p; nothing to recover.
		return parts, false, nil
	}
	inputPath := strings.TrimSpace(parts[inputIdx])
	if inputPath != "" {
		if st, err := os.Stat(inputPath); err == nil && !st.IsDir() {
			return parts, false, nil
		}
	}

	baseName := filepath.Base(inputPath)
	if baseName == "." || baseName == string(filepath.Separator) || baseName == "" {
		baseName = strings.TrimSpace(target)
	}
	baseName = filepath.Base(baseName)
	if baseName == "." || baseName == string(filepath.Separator) || baseName == "" {
		return parts, false, fmt.Errorf("original APK input was not found; upload the APK again to rescan")
	}

	uploadsDir := filepath.Join(getResultsDir(), "uploads")
	entries, err := os.ReadDir(uploadsDir)
	if err != nil {
		return parts, false, fmt.Errorf("original APK input was not found; upload the APK again to rescan")
	}

	var bestPath string
	var bestTime time.Time
	suffixed := "-" + baseName
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name != baseName && !strings.HasSuffix(name, suffixed) {
			continue
		}
		full := filepath.Join(uploadsDir, name)
		info, statErr := e.Info()
		if statErr != nil {
			continue
		}
		if bestPath == "" || info.ModTime().After(bestTime) {
			bestPath = full
			bestTime = info.ModTime()
		}
	}
	if bestPath == "" {
		return parts, false, fmt.Errorf("original APK file is no longer available for rescan; upload it again")
	}

	parts[inputIdx] = bestPath
	log.Printf("[rescan] APK input path recovered: %s -> %s", inputPath, bestPath)
	return parts, true, nil
}

// mergeActiveScansFromMemory overlays in-memory API state (activeScans) on DB rows so live
// phase/status/command win. Previously we skipped memory when the scan already existed in
// the DB, which forced phase 0/1 (0%) for API-started runs.
func mergeActiveScansFromMemory(dbActive []*db.ScanRecord) []*db.ScanRecord {
	scansMutex.RLock()
	defer scansMutex.RUnlock()

	out := make([]*db.ScanRecord, 0, len(dbActive)+len(activeScans))
	for _, r := range dbActive {
		if r == nil {
			continue
		}
		if info, ok := activeScans[r.ScanID]; ok && info != nil {
			st := strings.ToLower(info.Status)
			if st == "running" || st == "starting" || st == "paused" || st == "cancelling" {
				out = append(out, mergeScanRecordWithMemory(r, info))
				continue
			}
		}
		out = append(out, r)
	}

	seen := make(map[string]struct{}, len(out)+len(activeScans))
	for _, r := range out {
		seen[r.ScanID] = struct{}{}
	}
	for id, info := range activeScans {
		if info == nil {
			continue
		}
		st := strings.ToLower(info.Status)
		if st != "running" && st != "starting" && st != "paused" && st != "cancelling" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, scanInfoToScanRecord(info))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].StartedAt.After(out[j].StartedAt)
	})
	return out
}

func mergeScanRecordWithMemory(r *db.ScanRecord, info *ScanInfo) *db.ScanRecord {
	m := scanInfoToScanRecord(info)
	merged := *r
	merged.Status = m.Status
	merged.CurrentPhase = m.CurrentPhase
	if m.TotalPhases > 0 {
		merged.TotalPhases = m.TotalPhases
	}
	merged.PhaseName = m.PhaseName
	merged.LastUpdate = m.LastUpdate
	merged.Command = m.Command
	merged.PhaseStartTime = m.PhaseStartTime
	if len(m.CompletedPhases) > 0 {
		merged.CompletedPhases = m.CompletedPhases
	}
	if len(m.FailedPhases) > 0 {
		merged.FailedPhases = m.FailedPhases
	}
	merged.FilesUploaded = m.FilesUploaded
	merged.ErrorCount = m.ErrorCount
	return &merged
}

func scanInfoToScanRecord(info *ScanInfo) *db.ScanRecord {
	st := info.ScanType
	if st == "" {
		st = info.Type
	}
	sa := info.StartedAt
	if sa.IsZero() {
		sa = info.StartTime
	}
	lu := info.LastUpdate
	if lu.IsZero() {
		lu = sa
	}
	tp := info.TotalPhases
	if tp <= 0 {
		tp = 1
	}
	rec := &db.ScanRecord{
		ScanID:        info.ScanID,
		ScanType:      st,
		Target:        info.Target,
		Status:        info.Status,
		CurrentPhase:  info.CurrentPhase,
		TotalPhases:   tp,
		PhaseName:     info.PhaseName,
		StartedAt:     sa,
		LastUpdate:    lu,
		Command:       info.Command,
		ChannelID:     info.ChannelID,
		ThreadID:      info.ThreadID,
		MessageID:     info.MessageID,
		FilesUploaded: info.FilesUploaded,
		ErrorCount:    info.ErrorCount,
	}
	if !info.PhaseStartTime.IsZero() {
		t := info.PhaseStartTime
		rec.PhaseStartTime = &t
	}
	if len(info.CompletedPhases) > 0 {
		rec.CompletedPhases = append([]string(nil), info.CompletedPhases...)
	}
	if len(info.FailedPhases) > 0 {
		rec.FailedPhases = append([]string(nil), info.FailedPhases...)
	}
	return rec
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/monitor/targets — URL monitor targets
// ─────────────────────────────────────────────────────────────────────────────

func apiMonitorTargets(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()

	targets, err := db.ListMonitorTargets()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"targets": targets, "total": len(targets)})
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/monitor/subdomain-targets — subdomain monitor targets
// ─────────────────────────────────────────────────────────────────────────────

func apiSubdomainMonitorTargets(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()

	targets, err := db.ListSubdomainMonitorTargets()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"targets": targets, "total": len(targets)})
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/monitor/changes — recent monitor change history
// ─────────────────────────────────────────────────────────────────────────────

func apiMonitorChanges(c *gin.Context) {
	domain := c.Query("domain")
	_ = db.Init()
	_ = db.EnsureSchema()

	changes, err := db.ListMonitorChanges(domain, 50)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"changes": changes, "total": len(changes)})
}

// DELETE /api/monitor/changes — wipe change history and reset URL monitor change counters.
func apiClearMonitorChanges(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()
	if err := db.ClearMonitorChanges(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func normalizeMonitorPageURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("url is required")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid URL")
	}
	u.Fragment = ""
	return u.String(), nil
}

func monitorTargetIDForURL(canonical string) (int, error) {
	targets, err := db.ListMonitorTargets()
	if err != nil {
		return 0, err
	}
	for _, t := range targets {
		if t.URL == canonical {
			return t.ID, nil
		}
	}
	return 0, fmt.Errorf("target not found after save")
}

// POST /api/monitor/url-targets — add (or update) a URL monitor; optionally mark running and start URL daemon.
func apiPostMonitorURLTarget(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()

	var body struct {
		URL      string `json:"url"`
		Strategy string `json:"strategy"`
		Pattern  string `json:"pattern"`
		Start    *bool  `json:"start"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}

	canonical, err := normalizeMonitorPageURL(body.URL)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	strategy := strings.TrimSpace(strings.ToLower(body.Strategy))
	if strategy == "" {
		strategy = "hash"
	}
	if strategy != "hash" && strategy != "regex" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "strategy must be hash or regex"})
		return
	}
	pattern := strings.TrimSpace(body.Pattern)
	if strategy == "regex" && pattern == "" {
		pattern = `([A-Z][a-z]{2,9} [0-9]{1,2}, [0-9]{4}|[0-9]{4}-[0-9]{2}-[0-9]{2})`
	}

	if err := db.AddMonitorTarget(canonical, strategy, pattern); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	id, err := monitorTargetIDForURL(canonical)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	start := true
	if body.Start != nil {
		start = *body.Start
	}
	if start {
		if err := db.SetMonitorRunningStatus(id, true); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		monitor.StartURLMonitorDaemon()
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"id":       id,
		"url":      canonical,
		"strategy": strategy,
		"started":  start,
	})
}

// POST /api/monitor/suggest-from-domain — probe common release/changelog paths, then rank with AI (or heuristics).
func apiPostMonitorSuggestFromDomain(c *gin.Context) {
	var body struct {
		Domain string `json:"domain"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	d := strings.TrimSpace(body.Domain)
	if d == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Minute)
	defer cancel()

	suggestions, candidates, err := monitorsuggest.SuggestFromDomain(ctx, d)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ai := strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY")) != "" || strings.TrimSpace(os.Getenv("GEMINI_API_KEY")) != ""
	c.JSON(http.StatusOK, gin.H{
		"suggestions":       suggestions,
		"candidates_probed": len(candidates),
		"ai":                ai,
	})
}

func parseMonitorTargetID(c *gin.Context) (int, bool) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid monitor id"})
		return 0, false
	}
	return id, true
}

// DELETE /api/monitor/url-targets/:id — remove URL monitor target.
func apiDeleteMonitorURLTarget(c *gin.Context) {
	id, ok := parseMonitorTargetID(c)
	if !ok {
		return
	}
	_ = db.Init()
	_ = db.EnsureSchema()
	t, err := db.GetMonitorTargetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if err := db.RemoveMonitorTarget(t.URL); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// POST /api/monitor/url-targets/:id/pause — stop checking this URL (keeps row).
func apiPauseMonitorURLTarget(c *gin.Context) {
	id, ok := parseMonitorTargetID(c)
	if !ok {
		return
	}
	_ = db.Init()
	_ = db.EnsureSchema()
	if _, err := db.GetMonitorTargetByID(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if err := db.SetMonitorRunningStatus(id, false); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "running": false})
}

// POST /api/monitor/url-targets/:id/resume — mark running and wake URL monitor worker.
func apiResumeMonitorURLTarget(c *gin.Context) {
	id, ok := parseMonitorTargetID(c)
	if !ok {
		return
	}
	_ = db.Init()
	_ = db.EnsureSchema()
	if _, err := db.GetMonitorTargetByID(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if err := db.SetMonitorRunningStatus(id, true); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	monitor.StartURLMonitorDaemon()
	c.JSON(http.StatusOK, gin.H{"ok": true, "running": true})
}

// POST /api/monitor/subdomain-targets — add subdomain monitor target; optionally mark running and start subdomain daemon.
func apiPostMonitorSubdomainTarget(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()

	var body struct {
		Domain          string `json:"domain"`
		IntervalSeconds int    `json:"interval_seconds"`
		Threads         int    `json:"threads"`
		CheckNew        *bool  `json:"check_new"`
		Start           *bool  `json:"start"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}

	domain := strings.TrimSpace(body.Domain)
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}

	interval := body.IntervalSeconds
	if interval <= 0 {
		interval = 3600
	}
	threads := body.Threads
	if threads <= 0 {
		threads = 100
	}
	checkNew := true
	if body.CheckNew != nil {
		checkNew = *body.CheckNew
	}

	if err := db.AddSubdomainMonitorTarget(domain, interval, threads, checkNew); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	targets, err := db.ListSubdomainMonitorTargets()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var id int
	found := false
	for _, t := range targets {
		if t.Domain == domain {
			id = t.ID
			found = true
			break
		}
	}
	if !found {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "target not found after save"})
		return
	}

	start := true
	if body.Start != nil {
		start = *body.Start
	}
	if start {
		if err := db.SetSubdomainMonitorRunningStatus(id, true); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if !subdomainmonitor.IsDaemonRunning() {
			if err := subdomainmonitor.StartDaemon(); err != nil {
				log.Printf("[WARN] subdomain monitor daemon: %v", err)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":               true,
		"id":               id,
		"domain":           domain,
		"interval_seconds": interval,
		"threads":          threads,
		"check_new":        checkNew,
		"started":          start,
	})
}

// DELETE /api/monitor/subdomain-targets/:id — remove subdomain monitor target.
func apiDeleteMonitorSubdomainTarget(c *gin.Context) {
	id, ok := parseMonitorTargetID(c)
	if !ok {
		return
	}
	_ = db.Init()
	_ = db.EnsureSchema()
	t, err := db.GetSubdomainMonitorTargetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if err := db.RemoveSubdomainMonitorTarget(t.Domain); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// POST /api/monitor/subdomain-targets/:id/pause
func apiPauseMonitorSubdomainTarget(c *gin.Context) {
	id, ok := parseMonitorTargetID(c)
	if !ok {
		return
	}
	_ = db.Init()
	_ = db.EnsureSchema()
	if _, err := db.GetSubdomainMonitorTargetByID(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if err := db.SetSubdomainMonitorRunningStatus(id, false); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "running": false})
}

// POST /api/monitor/subdomain-targets/:id/resume
func apiResumeMonitorSubdomainTarget(c *gin.Context) {
	id, ok := parseMonitorTargetID(c)
	if !ok {
		return
	}
	_ = db.Init()
	_ = db.EnsureSchema()
	if _, err := db.GetSubdomainMonitorTargetByID(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if err := db.SetSubdomainMonitorRunningStatus(id, true); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !subdomainmonitor.IsDaemonRunning() {
		if err := subdomainmonitor.StartDaemon(); err != nil {
			log.Printf("[WARN] subdomain monitor daemon: %v", err)
		}
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "running": true})
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/r2/files — proxy R2 bucket object listing
// ─────────────────────────────────────────────────────────────────────────────

// R2FileInfo represents a single object in the R2 bucket
type R2FileInfo struct {
	Key          string    `json:"key"`
	Size         int64     `json:"size"`
	LastModified time.Time `json:"last_modified"`
	PublicURL    string    `json:"public_url"`
}

func apiR2Files(c *gin.Context) {
	if !r2storage.IsEnabled() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "R2 storage is not enabled"})
		return
	}

	prefix := strings.TrimPrefix(c.Query("prefix"), "/")
	publicBaseURL := strings.TrimSuffix(os.Getenv("R2_PUBLIC_URL"), "/")
	bucketName := os.Getenv("R2_BUCKET_NAME")
	accountID := os.Getenv("R2_ACCOUNT_ID")
	accessKey := os.Getenv("R2_ACCESS_KEY_ID")
	secretKey := os.Getenv("R2_SECRET_KEY")

	client, err := buildR2Client(accountID, accessKey, secretKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to init R2 client: %v", err)})
		return
	}

	// Build list request — delimiter "/" for folder UI; omit delimiter when recursive=1
	// so nested keys (e.g. new-results/domain/urls/file.txt) are included.
	listPrefix := prefix
	if listPrefix != "" && !strings.HasSuffix(listPrefix, "/") {
		listPrefix += "/"
	}

	recursive := c.Query("recursive") == "1" || strings.EqualFold(c.Query("recursive"), "true")

	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	}
	if listPrefix != "" {
		input.Prefix = aws.String(listPrefix)
	}
	if !recursive {
		input.Delimiter = aws.String("/")
	}

	var files []R2FileInfo
	var dirs []string

	paginator := s3.NewListObjectsV2Paginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to list R2: %v", err)})
			return
		}

		for _, cp := range page.CommonPrefixes {
			if cp.Prefix != nil {
				dirs = append(dirs, *cp.Prefix)
			}
		}

		for _, obj := range page.Contents {
			key := aws.ToString(obj.Key)
			if listPrefix != "" && key == listPrefix {
				continue // skip the virtual "dir" itself
			}
			size := int64(0)
			if obj.Size != nil {
				size = *obj.Size
			}
			lastMod := time.Time{}
			if obj.LastModified != nil {
				lastMod = *obj.LastModified
			}
			files = append(files, R2FileInfo{
				Key:          key,
				Size:         size,
				LastModified: lastMod,
				PublicURL:    publicBaseURL + "/" + key,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"prefix": prefix,
		"dirs":   dirs,
		"files":  files,
		"total":  len(files),
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/r2/delete — delete one object by key or all objects under a prefix
// ─────────────────────────────────────────────────────────────────────────────

// r2ListAllKeysUnderPrefix lists every object key under prefix (recursive, no delimiter).
// Matches the browser listing bucket/client (same env vars as GET /api/r2/files).
func r2ListAllKeysUnderPrefix(ctx context.Context, client *s3.Client, bucket, prefix string) ([]string, error) {
	listPrefix := strings.TrimPrefix(strings.TrimSpace(prefix), "/")
	if listPrefix != "" && !strings.HasSuffix(listPrefix, "/") {
		listPrefix += "/"
	}
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
	}
	if listPrefix != "" {
		input.Prefix = aws.String(listPrefix)
	}
	var keys []string
	paginator := s3.NewListObjectsV2Paginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Contents {
			k := aws.ToString(obj.Key)
			if listPrefix != "" && k == listPrefix {
				continue
			}
			if k != "" {
				keys = append(keys, k)
			}
		}
	}
	return keys, nil
}

// r2DeleteKeys removes objects via S3 DeleteObjects in batches of 1000.
func r2DeleteKeys(ctx context.Context, client *s3.Client, bucket string, keys []string) error {
	uniq := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		k = strings.TrimSpace(strings.TrimPrefix(k, "/"))
		if k == "" {
			continue
		}
		uniq[k] = struct{}{}
	}
	if len(uniq) == 0 {
		return nil
	}
	const batchSize = 1000
	batch := make([]string, 0, batchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		objs := make([]types.ObjectIdentifier, len(batch))
		for i, k := range batch {
			objs[i] = types.ObjectIdentifier{Key: aws.String(k)}
		}
		out, err := client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(bucket),
			Delete: &types.Delete{
				Objects: objs,
				Quiet:   aws.Bool(true),
			},
		})
		if err != nil {
			return err
		}
		if len(out.Errors) > 0 {
			e := out.Errors[0]
			return fmt.Errorf("delete %s: %s (%s)", aws.ToString(e.Key), aws.ToString(e.Code), aws.ToString(e.Message))
		}
		batch = batch[:0]
		return nil
	}
	for k := range uniq {
		batch = append(batch, k)
		if len(batch) >= batchSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}

func validateR2ObjectKey(key string) error {
	key = strings.TrimPrefix(strings.TrimSpace(key), "/")
	if key == "" {
		return fmt.Errorf("empty key")
	}
	if strings.Contains(key, "..") {
		return fmt.Errorf("invalid key")
	}
	return nil
}

func validateR2DeletePrefix(prefix string) error {
	prefix = strings.TrimPrefix(strings.TrimSpace(prefix), "/")
	if prefix == "" {
		return fmt.Errorf("empty prefix")
	}
	if strings.Contains(prefix, "..") {
		return fmt.Errorf("invalid prefix")
	}
	return nil
}

func apiR2Delete(c *gin.Context) {
	if !r2storage.IsEnabled() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "R2 storage is not enabled"})
		return
	}

	bucketName := strings.TrimSpace(os.Getenv("R2_BUCKET_NAME"))
	accountID := os.Getenv("R2_ACCOUNT_ID")
	accessKey := os.Getenv("R2_ACCESS_KEY_ID")
	secretKey := os.Getenv("R2_SECRET_KEY")
	if bucketName == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "R2 bucket is not configured"})
		return
	}
	client, err := buildR2Client(accountID, accessKey, secretKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to init R2 client: %v", err)})
		return
	}
	ctx := c.Request.Context()

	var body struct {
		Prefix string `json:"prefix"`
		Key    string `json:"key"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	key := strings.TrimSpace(body.Key)
	prefix := strings.TrimPrefix(strings.TrimSpace(body.Prefix), "/")

	if key != "" && prefix != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provide either key or prefix, not both"})
		return
	}
	if key == "" && prefix == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "prefix or key required"})
		return
	}

	if key != "" {
		if err := validateR2ObjectKey(key); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		objKey := strings.TrimPrefix(strings.TrimSpace(key), "/")
		_, delErr := client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objKey),
		})
		if delErr != nil {
			low := strings.ToLower(delErr.Error())
			if !strings.Contains(low, "nosuchkey") && !strings.Contains(low, "notfound") && !strings.Contains(low, "404") {
				c.JSON(http.StatusInternalServerError, gin.H{"error": delErr.Error()})
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "deleted": 1})
		return
	}

	if err := validateR2DeletePrefix(prefix); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	keys, err := r2ListAllKeysUnderPrefix(ctx, client, bucketName, prefix)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(keys) == 0 {
		log.Printf("[API] R2 delete prefix %q: listed 0 objects (bucket=%s)", prefix, bucketName)
		c.JSON(http.StatusOK, gin.H{"ok": true, "deleted": 0, "prefix": prefix})
		return
	}
	if err := r2DeleteKeys(ctx, client, bucketName, keys); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	log.Printf("[API] R2 deleted %d object(s) under prefix %q (bucket=%s)", len(keys), prefix, bucketName)
	c.JSON(http.StatusOK, gin.H{"ok": true, "deleted": len(keys), "prefix": prefix})
}

// buildR2Client constructs an S3-compatible client pointing at Cloudflare R2
func buildR2Client(accountID, accessKey, secretKey string) (*s3.Client, error) {
	endpoint := fmt.Sprintf("https://%s.r2.cloudflarestorage.com", accountID)

	resolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, opts ...interface{}) (aws.Endpoint, error) {
		if service == s3.ServiceID {
			return aws.Endpoint{URL: endpoint, SigningRegion: "auto"}, nil
		}
		return aws.Endpoint{}, fmt.Errorf("unknown endpoint: %s", service)
	})

	cfg, err := awsconfig.LoadDefaultConfig(context.TODO(),
		awsconfig.WithEndpointResolverWithOptions(resolver),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
		awsconfig.WithRegion("auto"),
	)
	if err != nil {
		return nil, err
	}

	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	}), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// openRouterChat — calls OpenRouter chat/completions directly.
// Key priority: X-OpenRouter-Key header → OPENROUTER_API_KEY env var.
// ─────────────────────────────────────────────────────────────────────────────

func openRouterChat(c *gin.Context, systemPrompt, userPrompt string) (string, error) {
	key := strings.TrimSpace(c.GetHeader("X-OpenRouter-Key"))
	source := "UI Header"
	if key == "" {
		key = strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY"))
		source = "Environment Variable"
	}
	if key == "" {
		return "", fmt.Errorf("No OpenRouter API key configured. Add it in Settings → AI Configuration.")
	}
	log.Printf("[API] Using OpenRouter key from %s (starts with: %s, length: %d)", source, key[:min(4, len(key))], len(key))

	type orMsg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type orReq struct {
		Model    string  `json:"model"`
		Messages []orMsg `json:"messages"`
	}
	type orChoice struct {
		Message orMsg `json:"message"`
	}
	type orResp struct {
		Choices []orChoice `json:"choices"`
		Error   *struct {
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}

	payload := orReq{
		Model: "openai/gpt-4o-mini",
		Messages: []orMsg{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
	}
	payloadBytes, _ := json.Marshal(payload)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", "https://openrouter.ai/api/v1/chat/completions", bytes.NewReader(payloadBytes))
	if err != nil {
		return "", fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("HTTP-Referer", "https://autoar.tool")
	req.Header.Set("X-Title", "AutoAR")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("OpenRouter request failed: %w", err)
	}
	defer resp.Body.Close()

	var result orResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse OpenRouter response: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("OpenRouter error: %s", result.Error.Message)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("OpenRouter returned no choices")
	}
	return result.Choices[0].Message.Content, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/findings/validate — AI validates a single finding
// ─────────────────────────────────────────────────────────────────────────────

func apiValidateFinding(c *gin.Context) {
	var body struct {
		Target      string `json:"target"`
		FindingType string `json:"finding_type"`
		Severity    string `json:"severity"`
		Module      string `json:"module"`
		RawFinding  string `json:"raw_finding"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if strings.TrimSpace(body.Target) == "" && strings.TrimSpace(body.FindingType) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target and finding_type are required"})
		return
	}

	systemPrompt := "You are a senior bug bounty hunter and penetration tester. Be concise, technical, and direct. Use markdown headers."

	userPrompt := fmt.Sprintf(`Analyze this security finding and tell me:

**Finding:**
- Target: %s
- Type: %s
- Severity: %s
- Scanner: %s

**Respond with:**
## Validity
Is this real or a false positive? Confidence %%. Why?

## How to Reproduce
Exact steps / curl commands / tool commands to confirm this vulnerability.

## Impact
What can an attacker do? Be specific.

## Quick Fix
One-line remediation.`, body.Target, body.FindingType, body.Severity, body.Module)

	analysis, err := openRouterChat(c, systemPrompt, userPrompt)
	if err != nil {
		log.Printf("[API] validate finding error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"analysis": analysis,
		"target":   body.Target,
		"finding":  body.FindingType,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/findings/report — AI generates a structured vuln report
// ─────────────────────────────────────────────────────────────────────────────

func apiReportFinding(c *gin.Context) {
	var body struct {
		Target      string `json:"target"`
		FindingType string `json:"finding_type"`
		Severity    string `json:"severity"`
		Module      string `json:"module"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if strings.TrimSpace(body.FindingType) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "finding_type is required"})
		return
	}

	systemPrompt := `You are an experienced bug bounty hunter writing a vulnerability report. 
Rules:
- Write like a human, not an AI. Short sentences. Direct.
- No filler phrases like "I found", "It is worth noting", "In conclusion".
- Technical but readable.
- Title must be ≤80 chars and specific.
- Keep the whole report under 400 words.`

	userPrompt := fmt.Sprintf(`Write a bug bounty report for this finding:

Target: %s
Vulnerability: %s  
Severity: %s
Scanner: %s

Use EXACTLY this structure (markdown):
## Title
[specific vulnerability title]

## Summary
[2-3 sentences: what it is, why it matters]

## Steps to Reproduce
1. ...
2. ...
3. ...

## Impact
[1-2 sentences: what an attacker can do]`, body.Target, body.FindingType, body.Severity, body.Module)

	report, err := openRouterChat(c, systemPrompt, userPrompt)
	if err != nil {
		log.Printf("[API] report finding error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"report":  report,
		"target":  body.Target,
		"finding": body.FindingType,
	})
}
