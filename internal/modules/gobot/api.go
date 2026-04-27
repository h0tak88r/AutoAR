package gobot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/h0tak88r/AutoAR/internal/modules/db"
	"github.com/h0tak88r/AutoAR/internal/modules/r2storage"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
	"github.com/h0tak88r/AutoAR/internal/version"
)

const (
	// defaultMaxScanResults caps in-memory result entries.
	defaultMaxScanResults = 1000
	// defaultMaxScanResultsBytes caps aggregate cached output bytes across scanResults.
	defaultMaxScanResultsBytes int64 = 128 * 1024 * 1024
	// defaultMaxConcurrentScans limits simultaneous child-process scans.
	defaultMaxConcurrentScans = 15
	// defaultScanOutputCaptureBytes limits per-scan in-memory log capture.
	defaultScanOutputCaptureBytes = 2 * 1024 * 1024
)

var (
	maxScanResults               = defaultMaxScanResults
	maxScanResultsBytes    int64 = defaultMaxScanResultsBytes
	maxConcurrentScans           = defaultMaxConcurrentScans
	scanOutputCaptureBytes       = defaultScanOutputCaptureBytes
	minRuntimeFreeMemBytes int64 = 0

	scanResults           = make(map[string]*ScanResult)
	scanResultsTotalBytes int64
	apiScansMutex         sync.RWMutex

	// scanSemaphore limits concurrent child-process scans (#2 rate limiting).
	scanSemaphore = make(chan struct{}, maxConcurrentScans)
	resourceLimitsOnce   sync.Once
)

func scanResultSizeBytes(r *ScanResult) int64 {
	if r == nil {
		return 0
	}
	return int64(len(r.Output) + len(r.Error) + len(r.ScanID) + len(r.ScanType) + len(r.Status))
}

func storeScanResultLocked(scanID string, result *ScanResult) {
	if old, ok := scanResults[scanID]; ok {
		scanResultsTotalBytes -= scanResultSizeBytes(old)
	}
	scanResults[scanID] = result
	scanResultsTotalBytes += scanResultSizeBytes(result)
	for len(scanResults) > maxScanResults || scanResultsTotalBytes > maxScanResultsBytes {
		var oldest string
		var oldestTime time.Time
		for id, r := range scanResults {
			if oldest == "" || r.StartedAt.Before(oldestTime) {
				oldest = id
				oldestTime = r.StartedAt
			}
		}
		if oldest == "" {
			break
		}
		scanResultsTotalBytes -= scanResultSizeBytes(scanResults[oldest])
		delete(scanResults, oldest)
	}
}

func envIntWithBounds(name string, fallback, minV, maxV int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func envInt64WithBounds(name string, fallback, minV, maxV int64) int64 {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fallback
	}
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func isTruthyEnv(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func initRuntimeResourceLimits() {
	resourceLimitsOnce.Do(func() {
		// Small VPS profile: conservative defaults, still overridable by env vars below.
		if isTruthyEnv("AUTOAR_SMALL_VPS") {
			maxConcurrentScans = 3
			maxScanResults = 250
			maxScanResultsBytes = 32 * 1024 * 1024
			scanOutputCaptureBytes = 512 * 1024
			minRuntimeFreeMemBytes = 256 * 1024 * 1024
		}

		maxConcurrentScans = envIntWithBounds("AUTOAR_MAX_CONCURRENT_SCANS", maxConcurrentScans, 1, 50)
		maxScanResults = envIntWithBounds("AUTOAR_MAX_SCAN_RESULTS", maxScanResults, 50, 5000)
		maxScanResultsBytes = envInt64WithBounds("AUTOAR_MAX_SCAN_RESULTS_BYTES", maxScanResultsBytes, 8*1024*1024, 512*1024*1024)
		scanOutputCaptureBytes = envIntWithBounds("AUTOAR_SCAN_OUTPUT_CAPTURE_BYTES", scanOutputCaptureBytes, 128*1024, 8*1024*1024)
		minRuntimeFreeMemBytes = envInt64WithBounds("AUTOAR_MIN_FREE_MEM_BYTES", minRuntimeFreeMemBytes, 0, 8*1024*1024*1024)

		// Reinitialize semaphore with final configured capacity.
		scanSemaphore = make(chan struct{}, maxConcurrentScans)
		log.Printf("[resource-limits] concurrent=%d, max_results=%d, cache_bytes=%d, output_capture_bytes=%d, min_free_mem_bytes=%d",
			maxConcurrentScans, maxScanResults, maxScanResultsBytes, scanOutputCaptureBytes, minRuntimeFreeMemBytes)
	})
}

func runtimeMemoryPreflightCheck() (bool, string) {
	if minRuntimeFreeMemBytes <= 0 {
		return true, ""
	}
	avail := availableMemoryBytes()
	if avail <= 0 {
		return true, ""
	}
	if avail < minRuntimeFreeMemBytes {
		return false, fmt.Sprintf("insufficient free memory to start scan: available=%dMB required>=%dMB", avail/(1024*1024), minRuntimeFreeMemBytes/(1024*1024))
	}
	return true, ""
}

// ScanInfo is defined in commands.go

type ScanResult struct {
	ScanID      string     `json:"scan_id"`
	Status      string     `json:"status"`
	ScanType    string     `json:"scan_type"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Output      string     `json:"output,omitempty"`
	Error       string     `json:"error,omitempty"`
}

type scanOutputCapture struct {
	mu        sync.Mutex
	maxBytes  int
	buf       bytes.Buffer
	lineBuf   string
	resultURL string
	truncated bool
}

func newScanOutputCapture(maxBytes int) *scanOutputCapture {
	if maxBytes < 1 {
		maxBytes = 256 * 1024
	}
	return &scanOutputCapture{maxBytes: maxBytes}
}

func (s *scanOutputCapture) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Capture only up to maxBytes to avoid unbounded memory growth.
	if s.buf.Len() < s.maxBytes {
		remain := s.maxBytes - s.buf.Len()
		if len(p) <= remain {
			_, _ = s.buf.Write(p)
		} else {
			_, _ = s.buf.Write(p[:remain])
			s.truncated = true
		}
	} else {
		s.truncated = true
	}

	// Parse line-by-line for R2 URLs without storing full output.
	s.lineBuf += string(p)
	for {
		idx := strings.IndexByte(s.lineBuf, '\n')
		if idx < 0 {
			break
		}
		line := strings.TrimSpace(s.lineBuf[:idx])
		s.lineBuf = s.lineBuf[idx+1:]
		if s.resultURL == "" && (strings.Contains(line, "Results zip uploaded:") || strings.Contains(line, "Zip file uploaded:")) {
			if u := extractFirstHTTPURL(line); u != "" {
				s.resultURL = u
			}
		}
	}
	return len(p), nil
}

func (s *scanOutputCapture) OutputString() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.buf.String()
	if s.truncated {
		out += "\n[output truncated for memory safety]\n"
	}
	return out
}

func (s *scanOutputCapture) ResultURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.resultURL != "" {
		return s.resultURL
	}
	// Best-effort: inspect trailing buffered partial line.
	if s.lineBuf != "" {
		line := strings.TrimSpace(s.lineBuf)
		if strings.Contains(line, "Results zip uploaded:") || strings.Contains(line, "Zip file uploaded:") {
			if u := extractFirstHTTPURL(line); u != "" {
				s.resultURL = u
			}
		}
	}
	return s.resultURL
}

type moduleExecutionEntry struct {
	Module         string    `json:"module"`
	Status         string    `json:"status"` // started|completed|failed|cancelled
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    time.Time `json:"completed_at,omitempty"`
	DurationMS     int64     `json:"duration_ms,omitempty"`
	OutputFiles    []string  `json:"output_files,omitempty"`
	ScannerVersion string    `json:"scanner_version,omitempty"`
	Command        string    `json:"command,omitempty"`
}

type scanExecutionManifest struct {
	ScanID      string                 `json:"scan_id"`
	ScanType    string                 `json:"scan_type"`
	Target      string                 `json:"target"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt time.Time              `json:"completed_at,omitempty"`
	Modules     []moduleExecutionEntry `json:"modules"`
}

func writeScanManifest(scanID, scanType, target string, startedAt, completedAt time.Time, module moduleExecutionEntry) {
	if strings.TrimSpace(scanID) == "" {
		return
	}
	outDir := utils.GetScanResultsDir(scanID)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		log.Printf("[manifest] mkdir failed for %s: %v", scanID, err)
		return
	}
	manifest := scanExecutionManifest{
		ScanID:      scanID,
		ScanType:    scanType,
		Target:      target,
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		Modules:     []moduleExecutionEntry{module},
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		log.Printf("[manifest] marshal failed for %s: %v", scanID, err)
		return
	}
	path := filepath.Join(outDir, "scan-manifest.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		log.Printf("[manifest] write failed for %s: %v", scanID, err)
	}
}

func collectScanOutputFiles(scanID string) []string {
	arts, err := db.ListScanArtifacts(scanID)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(arts))
	seen := make(map[string]struct{}, len(arts))
	for _, a := range arts {
		name := strings.TrimSpace(a.FileName)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

type ScanRequest struct {
	Domain            *string `json:"domain"`
	Subdomain         *string `json:"subdomain"`
	URL               *string `json:"url"`
	Bucket            *string `json:"bucket"`
	Region            *string `json:"region"`
	Repo              *string `json:"repo"`
	FilePath          *string `json:"file_path"`
	Strategy          *string `json:"strategy"`
	Pattern           *string `json:"pattern"`
	Interval          *int    `json:"interval"`
	All               *bool   `json:"all"`
	Daemon            *bool   `json:"daemon"`
	Mode              *string `json:"mode"`
	SkipJS            *bool   `json:"skip_js"`
	SkipFFuf          *bool   `json:"skip_ffuf"`
	PhaseTimeout      *int    `json:"phase_timeout"`
	TimeoutLivehosts  *int    `json:"timeout_livehosts"`
	TimeoutReflection *int    `json:"timeout_reflection"`
	TimeoutJS         *int    `json:"timeout_js"`
	TimeoutNuclei     *int    `json:"timeout_nuclei"`
	Query             *string `json:"query"`
	Provider          *string `json:"provider"`
	APIKey            *string `json:"api_key"`
	// FFuf options
	Target         *string            `json:"target"`          // FFuf target URL
	Wordlist       *string            `json:"wordlist"`        // FFuf wordlist path
	Threads        *int               `json:"threads"`         // FFuf threads
	Recursion      *bool              `json:"recursion"`       // FFuf recursion
	RecursionDepth *int               `json:"recursion_depth"` // FFuf recursion depth
	Bypass403      *bool              `json:"bypass_403"`      // FFuf 403 bypass
	Extensions     *[]string          `json:"extensions"`      // FFuf extensions
	CustomHeaders  *map[string]string `json:"custom_headers"`  // FFuf custom headers
	// Zerodays options
	DomainsFile          *string   `json:"domains_file"`           // Zerodays domains file
	DOSTest              *bool     `json:"dos_test"`               // Zerodays DoS test
	EnableSourceExposure *bool     `json:"enable_source_exposure"` // Zerodays source exposure
	Silent               *bool     `json:"silent"`                 // Zerodays silent mode
	CVEs                 *[]string `json:"cves"`                   // CVEs to check (CVE-2025-55182, CVE-2025-14847)
	MongoDBHost          *string   `json:"mongodb_host"`           // MongoDB host for CVE-2025-14847
	MongoDBPort          *int      `json:"mongodb_port"`           // MongoDB port for CVE-2025-14847
	// ApkX options
	PackageID *string `json:"package_id"`
	MITM      *bool   `json:"mitm"`
	// JWT options
	Token            *string `json:"token"`              // JWT token
	SkipCrack        *bool   `json:"skip_crack"`         // JWT skip crack
	SkipPayloads     *bool   `json:"skip_payloads"`      // JWT skip payloads
	WordlistPath     *string `json:"wordlist_path"`      // JWT wordlist
	MaxCrackAttempts *int    `json:"max_crack_attempts"` // JWT max crack attempts
	// Misconfig options
	ServiceID    *string `json:"service_id"`   // Misconfig service ID
	Delay        *int    `json:"delay"`        // Misconfig delay (ms)
	Permutations *bool   `json:"permutations"` // Enable permutations (slower but more thorough)
	// DNS options
	DNSType *string `json:"dns_type"` // DNS scan type: takeover, dangling-ip
	// URLs options
	SkipSubdomainEnum *bool `json:"skip_subdomain_enum"` // URLs: skip subdomain enumeration (treat as single subdomain)
}

type ScanResponse struct {
	ScanID  string `json:"scan_id"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Command string `json:"command,omitempty"`
}

type ScanStatusResponse struct {
	ScanID      string     `json:"scan_id"`
	Status      string     `json:"status"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Output      *string    `json:"output,omitempty"`
	Error       *string    `json:"error,omitempty"`
}

// reconcileStaleScansOnStartup marks DB scans that were still "running" as failed. In-memory
// workers are gone after restart; leaving them active confuses the dashboard.
func reconcileStaleScansOnStartup() {
	if err := db.Init(); err != nil {
		return
	}
	if err := db.EnsureSchema(); err != nil {
		log.Printf("[WARN] EnsureSchema during stale scan reconcile: %v", err)
	}
	n, err := db.FailStaleActiveScans()
	if err != nil {
		log.Printf("[WARN] Stale scan reconcile: %v", err)
		return
	}
	if n > 0 {
		log.Printf("[INFO] Marked %d interrupted scan(s) as failed (API restart — no running worker).", n)
	}
}

// Setup API routes
func setupAPI() *gin.Engine {
	initRuntimeResourceLimits()

	// Initialize DB once at startup — all scan goroutines share this connection.
	// db.Init and db.EnsureSchema are idempotent (sync.Once internally).
	if err := db.Init(); err != nil {
		log.Printf("[WARN] DB init at startup: %v", err)
	} else if err := db.EnsureSchema(); err != nil {
		log.Printf("[WARN] DB schema at startup: %v", err)
	}

	gin.SetMode(gin.ReleaseMode)
	gin.DefaultWriter = utils.GetLogger().Out
	r := gin.Default()

	reconcileStaleScansOnStartup()

	// CORS middleware
	r.Use(corsMiddleware())

	auth := supabaseJWTAuth()

	// Root
	r.GET("/", rootHandler)
	r.GET("/health", healthHandler)
	r.GET("/metrics", auth, metricsHandler)
	r.GET("/docs", auth, docsHandler)

	// ── Dashboard UI (embedded SPA) ──────────────────────────────────────────
	// Both /ui and /ui/* use the same handler — no redirect loops.
	r.GET("/ui", serveDashboardUI)
	r.GET("/ui/*filepath", serveDashboardUI)
	// Deep link: /scans/:scanId (same SPA; client router reads pathname)
	r.GET("/scans", serveDashboardUI)
	r.GET("/scans/*filepath", serveDashboardUI)

	// Public: SPA reads these before login (no JWT).
	r.GET("/api/config", apiConfigHandler)
	r.POST("/api/settings", auth, apiUpdateSettingsHandler)
	r.POST("/api/auth/login", apiLocalAuthLogin)

	// ── Dashboard data API (protected when DASHBOARD_USER/PASSWORD is set) ───
	apiGroup := r.Group("/api")
	apiGroup.Use(auth)
	{
		apiGroup.GET("/dashboard/stats", apiDashboardStats)
		apiGroup.GET("/domains", apiListDomains)
		apiGroup.POST("/domains", apiAddDomain)           // single add
		apiGroup.POST("/domains/bulk", apiAddDomainsBulk) // batch add
		apiGroup.DELETE("/domains/:domain", apiDeleteDomain)
		apiGroup.GET("/domains/:domain/subdomains", apiListSubdomains)
		apiGroup.GET("/subdomains", apiAllSubdomainsPaginated)
		apiGroup.POST("/subdomains/cnames/retry", apiRetryCnames)
		apiGroup.GET("/subdomains/cnames/progress", apiRetryCnamesProgress)
		apiGroup.POST("/subdomains/nuclei/run", apiRunGlobalNuclei)
		apiGroup.GET("/scans", apiListScans)
		apiGroup.GET("/scans/:id/results/summary", apiScanResultsSummary)
		apiGroup.GET("/scans/:id/results/files", apiScanResultFiles)
		apiGroup.GET("/scans/:id/results/file", apiScanResultFileContent)
		apiGroup.GET("/scans/:id/results/download", apiScanResultFileDownload)
		apiGroup.GET("/scans/:id/results/parsed", apiScanParsedResults)
		apiGroup.GET("/scans/:id/results/assets", apiScanAssets)
		apiGroup.GET("/scans/:id/results/urls", apiScanURLs)
		apiGroup.GET("/scans/:id/artifacts", apiListScanArtifacts)
		apiGroup.GET("/scans/:id/manifest", apiGetScanManifest)
		apiGroup.GET("/scans/:id", apiGetScan)
		apiGroup.GET("/scans/:id/report", apiGetScanReport)
		apiGroup.GET("/scans/:id/logs/stream", apiStreamScanLogs)
		apiGroup.POST("/scans/bulk-delete", apiBulkDeleteScans)
		apiGroup.POST("/scans/clear-all", apiClearAllScans)
		apiGroup.DELETE("/scans/:id", apiDeleteScan)
		apiGroup.POST("/scans/:id/cancel", apiCancelScan)
		apiGroup.POST("/scans/:id/pause", apiPauseScan)
		apiGroup.POST("/scans/:id/resume", apiResumeScan)
		apiGroup.POST("/scans/:id/rescan", apiRescan)
		apiGroup.GET("/monitor/targets", apiMonitorTargets)
		apiGroup.GET("/monitor/subdomain-targets", apiSubdomainMonitorTargets)
		apiGroup.GET("/monitor/changes", apiMonitorChanges)
		apiGroup.DELETE("/monitor/changes", apiClearMonitorChanges)
		apiGroup.POST("/monitor/url-targets", apiPostMonitorURLTarget)
		apiGroup.POST("/monitor/suggest-from-domain", apiPostMonitorSuggestFromDomain)
		apiGroup.DELETE("/monitor/url-targets/:id", apiDeleteMonitorURLTarget)
		apiGroup.POST("/monitor/url-targets/:id/pause", apiPostMonitorURLTarget)
		apiGroup.POST("/monitor/url-targets/:id/resume", apiPostMonitorURLTarget)
		apiGroup.POST("/monitor/subdomain-targets", apiPostMonitorSubdomainTarget)
		apiGroup.DELETE("/monitor/subdomain-targets/:id", apiDeleteMonitorSubdomainTarget)
		apiGroup.POST("/monitor/subdomain-targets/:id/pause", apiPostMonitorSubdomainTarget)
		apiGroup.POST("/monitor/subdomain-targets/:id/resume", apiPostMonitorSubdomainTarget)
		apiGroup.GET("/r2/files", apiR2Files)
		apiGroup.POST("/r2/delete", apiR2Delete)
		// Bug bounty scope / target fetch endpoints
		apiGroup.POST("/scope/fetch", apiFetchScope)
		apiGroup.GET("/scope/platforms", apiScopePlatforms)
		// AI finding validation & reporting
		apiGroup.POST("/findings/validate", apiValidateFinding)
		apiGroup.POST("/findings/report", apiReportFinding)
		// KeyHack templates
		apiGroup.GET("/keyhacks", apiListKeyhacks)
		apiGroup.GET("/keyhacks/search", apiSearchKeyhacks)
		// System & Templates
		apiGroup.GET("/system/metrics", apiGetSystemMetrics)
		apiGroup.GET("/system/limits", apiGetRuntimeLimits)
		apiGroup.GET("/nuclei/templates", apiListNucleiTemplates)
		// Upload handler
		apiGroup.POST("/upload", apiUploadHandler)
		// Report Templates
		apiGroup.GET("/report-templates", apiListReportTemplates)
		apiGroup.GET("/report-templates/export", apiExportReportTemplates)
		apiGroup.POST("/report-templates/import", apiImportReportTemplates)
		apiGroup.GET("/report-templates/:name", apiGetReportTemplate)
		apiGroup.POST("/report-templates", apiSaveReportTemplate)
		apiGroup.DELETE("/report-templates/:name", apiDeleteReportTemplate)
	}

	// Scan endpoints
	api := r.Group("/scan")
	api.Use(auth)
	{
		api.POST("/domain_run", scanDomainRun)
		api.POST("/subdomain_run", scanSubdomainRun)
		api.POST("/subdomains", scanSubdomains)
		api.POST("/livehosts", scanLivehosts)
		api.POST("/cnames", scanCnames)
		api.POST("/urls", scanURLs)
		api.POST("/js", scanJS)
		api.POST("/reflection", scanReflection)
		api.POST("/nuclei", scanNuclei)
		api.POST("/tech", scanTech)
		api.POST("/ports", scanPorts)
		api.POST("/gf", scanGF)
		api.POST("/dns-takeover", scanDNSTakeover)
		api.POST("/dns", scanDNS)              // New unified DNS endpoint (supports takeover and dangling-ip)
		api.POST("/dns-cf1016", scanDNSCF1016) // Cloudflare 1016 dangling DNS scan
		api.POST("/s3", scanS3)
		api.POST("/github", scanGitHub)
		api.POST("/github_org", scanGitHubOrg)
		api.POST("/recon", scanRecon) // Unified asset discovery: subdomains, livehosts, tech, cnames
		api.POST("/lite", scanLite)
		api.POST("/ffuf", scanFFuf)           // FFuf fuzzing
		api.POST("/backup", scanBackup)       // Backup file discovery
		api.POST("/misconfig", scanMisconfig) // Cloud misconfiguration scan
		api.POST("/zerodays", scanZerodays)   // Zerodays scan (CVE-2025-55182 React2Shell, CVE-2025-14847 MongoDB)
		api.POST("/jwt", scanJWT)             // JWT vulnerability scan
		api.POST("/apkx", scanApkX)           // APK analysis and MITM patching
		api.GET("/:scan_id/status", getScanStatus)
		api.GET("/:scan_id/results", getScanResults)
		api.GET("/:scan_id/download", downloadScanResults)
	}

	// KeyHack endpoints
	keyhack := r.Group("/keyhack")
	keyhack.Use(auth)
	{
		keyhack.POST("/search", keyhackSearch)
		keyhack.POST("/validate", keyhackValidate)
	}

	// Internal endpoints for module file notifications
	internal := r.Group("/internal")
	internal.Use(auth)
	{
		internal.POST("/send-file", sendFileToDiscord)
		internal.POST("/send-message", sendMessageToDiscord)
	}

	// Utility endpoints
	r.POST("/cleanup", auth, cleanupHandler)

	return r
}


func readInt64FromFile(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(b))
	if s == "" || s == "max" {
		return math.MaxInt64, nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return v, nil
}

func availableMemoryBytes() int64 {
	// cgroup v2
	if lim, err := readInt64FromFile("/sys/fs/cgroup/memory.max"); err == nil {
		if cur, err2 := readInt64FromFile("/sys/fs/cgroup/memory.current"); err2 == nil {
			if lim != math.MaxInt64 && lim > cur {
				return lim - cur
			}
		}
	}
	// cgroup v1
	if lim, err := readInt64FromFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		if cur, err2 := readInt64FromFile("/sys/fs/cgroup/memory/memory.usage_in_bytes"); err2 == nil {
			if lim > 0 && lim < (1<<62) && lim > cur {
				return lim - cur
			}
		}
	}
	// Host fallback (/proc/meminfo)
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "MemAvailable:") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}
			if kb, err := strconv.ParseInt(parts[1], 10, 64); err == nil && kb > 0 {
				return kb * 1024
			}
		}
	}
	return -1
}


// apiUploadHandler handles file uploads for analysis
func apiUploadHandler(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
		return
	}

	// Create temp directory for uploads
	uploadDir := filepath.Join(getResultsDir(), "uploads")
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create upload directory"})
		return
	}

	// Clean filename to prevent traversal
	filename := filepath.Base(file.Filename)
	destPath := filepath.Join(uploadDir, fmt.Sprintf("%d-%s", time.Now().Unix(), filename))

	if err := c.SaveUploadedFile(file, destPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save file: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "File uploaded successfully",
		"file_path": destPath,
		"filename":  filename,
	})
}

// validateFilePath ensures the given path is inside an allowed directory (#5 path traversal protection).
func validateFilePath(filePath string) error {
	if strings.TrimSpace(filePath) == "" {
		return fmt.Errorf("file_path is required")
	}
	allowedRoots := []string{
		getResultsDir(),
		os.TempDir(),
		"/app",
		"/tmp",
	}
	if extra := os.Getenv("AUTOAR_ALLOWED_FILE_ROOT"); extra != "" {
		allowedRoots = append(allowedRoots, extra)
	}

	resolvedPath, err := filepath.EvalSymlinks(filePath)
	if err != nil {
		return fmt.Errorf("invalid file_path %q: %w", filePath, err)
	}
	resolvedPath, err = filepath.Abs(resolvedPath)
	if err != nil {
		return fmt.Errorf("invalid file_path %q: %w", filePath, err)
	}

	for _, root := range allowedRoots {
		if root == "" {
			continue
		}
		resolvedRoot, rErr := filepath.EvalSymlinks(root)
		if rErr != nil {
			resolvedRoot = root // root may not exist in some deployments; keep conservative fallback
		}
		resolvedRoot, rErr = filepath.Abs(filepath.Clean(resolvedRoot))
		if rErr != nil {
			continue
		}
		rel, relErr := filepath.Rel(resolvedRoot, resolvedPath)
		if relErr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil
		}
	}
	return fmt.Errorf("file_path %q is outside the allowed directories — only paths under AUTOAR_RESULTS_DIR or /tmp are permitted", filePath)
}

func corsMiddleware() gin.HandlerFunc {
	// #3: Warn once at startup if the API accepts cross-origin requests from any origin.
	allowedOrigins := strings.TrimSpace(os.Getenv("CORS_ALLOWED_ORIGINS"))
	if allowedOrigins == "" {
		log.Printf("[WARN] CORS_ALLOWED_ORIGINS is not set — API accepts cross-origin requests from ANY origin. Set CORS_ALLOWED_ORIGINS in production.")
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if allowedOrigins != "" {
			for _, o := range strings.Split(allowedOrigins, ",") {
				if strings.TrimSpace(o) == origin && origin != "" {
					c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
					c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
					break
				}
			}
		} else {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		}
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func rootHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "AutoAR API Server",
		"version": version.Version,
		"docs":    "/docs",
		"status":  "operational",
	})
}

func healthHandler(c *gin.Context) {
	snapshot := getMetricsSnapshot()

	c.JSON(http.StatusOK, gin.H{
		"status":       "healthy",
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"uptime":       snapshot["uptime"],
		"active_scans": snapshot["active_scans"],
	})
}

func metricsHandler(c *gin.Context) {
	snapshot := getMetricsSnapshot()
	c.JSON(http.StatusOK, snapshot)
}

func cleanupHandler(c *gin.Context) {
	// Execute cleanup via CLI command to avoid import cycle
	scanID := generateScanID()
	command := []string{
		getAutoarScriptPath(),
		"cleanup",
	}

	go executeScan(scanID, command, "cleanup")

	c.JSON(http.StatusOK, gin.H{
		"scan_id": scanID,
		"status":  "started",
		"message": "Cleanup started",
		"command": strings.Join(command, " "),
	})
}

func docsHandler(c *gin.Context) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AutoAR API Documentation</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        header {
            border-bottom: 1px solid #30363d;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        h1 {
            color: #58a6ff;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .version {
            color: #8b949e;
            font-size: 1.1em;
        }
        .endpoint {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .method {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 0.85em;
            margin-right: 10px;
        }
        .method.post { background: #238636; color: white; }
        .method.get { background: #1f6feb; color: white; }
        .endpoint-path {
            font-family: 'Courier New', monospace;
            font-size: 1.1em;
            color: #58a6ff;
            margin-bottom: 10px;
        }
        .description {
            color: #8b949e;
            margin-bottom: 15px;
        }
        .example {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 4px;
            padding: 15px;
            margin-top: 10px;
            overflow-x: auto;
        }
        .example code {
            color: #c9d1d9;
            font-family: 'Courier New', monospace;
        }
        .section {
            margin-top: 40px;
        }
        .section-title {
            color: #58a6ff;
            font-size: 1.8em;
            margin-bottom: 20px;
            border-bottom: 1px solid #30363d;
            padding-bottom: 10px;
        }
        a {
            color: #58a6ff;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>AutoAR API Documentation</h1>
            <div class="version">Version ` + version.Version + `</div>
        </header>

        <div class="section">
            <h2 class="section-title">Base Information</h2>
            <div class="endpoint">
                <div class="endpoint-path"><span class="method get">GET</span> /</div>
                <div class="description">API root endpoint - returns API information</div>
            </div>
            <div class="endpoint">
                <div class="endpoint-path"><span class="method get">GET</span> /health</div>
                <div class="description">Health check endpoint</div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">Scan Endpoints</h2>
            
            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /scan/subdomains</div>
                <div class="description">Enumerate subdomains for a domain</div>
                <div class="example">
                    <code>curl -X POST http://localhost:8000/scan/subdomains \<br>
&nbsp;&nbsp;-H "Content-Type: application/json" \<br>
&nbsp;&nbsp;-d '{"domain": "example.com"}'</code>
                </div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /scan/livehosts</div>
                <div class="description">Filter live hosts from subdomains</div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /scan/cnames</div>
                <div class="description">Collect CNAME records for domain subdomains</div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /scan/urls</div>
                <div class="description">Collect URLs and JS URLs</div>
                <div class="example">
                    <code>curl -X POST http://localhost:8000/scan/urls \<br>
&nbsp;&nbsp;-H "Content-Type: application/json" \<br>
&nbsp;&nbsp;-d '{"domain": "example.com", "skip_subdomain_enum": false}'</code>
                </div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /scan/js</div>
                <div class="description">JavaScript scan (JS URLs)</div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /scan/reflection</div>
                <div class="description">Reflection scan (kxss)</div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /scan/nuclei</div>
                <div class="description">Run Nuclei templates</div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /scan/tech</div>
                <div class="description">Technology detection</div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /scan/ports</div>
                <div class="description">Port scanning with Naabu</div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /scan/gf</div>
                <div class="description">GF patterns scan</div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /scan/dns</div>
                <div class="description">DNS scan (takeover or dangling-ip detection)</div>
                <div class="example">
                    <code>curl -X POST http://localhost:8000/scan/dns \<br>
&nbsp;&nbsp;-H "Content-Type: application/json" \<br>
&nbsp;&nbsp;-d '{"domain": "example.com", "dns_type": "takeover"}'</code>
                </div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /scan/s3</div>
                <div class="description">S3 bucket scanning</div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /scan/github</div>
                <div class="description">GitHub repository scanning</div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /scan/github_org</div>
                <div class="description">GitHub organization scanning</div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /scan/lite</div>
                <div class="description">Lite scan: Comprehensive automated scan workflow. Runs livehosts → reflection → JS → CNAME → backup → DNS → misconfig → nuclei phases sequentially with real-time progress updates.</div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /scan/ffuf</div>
                <div class="description">FFuf web fuzzing</div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /scan/backup</div>
                <div class="description">Backup file discovery</div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /scan/misconfig</div>
                <div class="description">Cloud misconfiguration scanning</div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /scan/zerodays</div>
                <div class="description">Zerodays scan (CVE-2025-55182 React2Shell, CVE-2025-14847 MongoDB)</div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /scan/jwt</div>
                <div class="description">JWT vulnerability scan</div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method get">GET</span> /scan/:scan_id/status</div>
                <div class="description">Get scan status by scan ID</div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method get">GET</span> /scan/:scan_id/results</div>
                <div class="description">Get scan results by scan ID</div>
            </div>

            <div class="endpoint">
                <div class="endpoint-path"><span class="method get">GET</span> /scan/:scan_id/download</div>
                <div class="description">Download scan results as archive</div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">KeyHack Endpoints</h2>
            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /keyhack/search</div>
                <div class="description">Search for API keys</div>
            </div>
            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /keyhack/validate</div>
                <div class="description">Validate API keys</div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">Utility Endpoints</h2>
            <div class="endpoint">
                <div class="endpoint-path"><span class="method get">GET</span> /scans</div>
                <div class="description">List all scans (active and completed)</div>
            </div>
            <div class="endpoint">
                <div class="endpoint-path"><span class="method post">POST</span> /cleanup</div>
                <div class="description">Clean up the entire results directory</div>
                <div class="example">
                    <code>curl -X POST http://localhost:8000/cleanup</code>
                </div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">Request Format</h2>
            <div class="endpoint">
                <div class="description">
                    All POST endpoints accept JSON in the following format:
                </div>
                <div class="example">
                    <code>{<br>
&nbsp;&nbsp;"domain": "example.com",<br>
&nbsp;&nbsp;"threads": 100,<br>
&nbsp;&nbsp;"skip_subdomain_enum": false<br>
}</code>
                </div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">Response Format</h2>
            <div class="endpoint">
                <div class="description">
                    Successful scan initiation returns:
                </div>
                <div class="example">
                    <code>{<br>
&nbsp;&nbsp;"scan_id": "abc123...",<br>
&nbsp;&nbsp;"status": "started",<br>
&nbsp;&nbsp;"message": "Scan started for example.com",<br>
&nbsp;&nbsp;"command": "autoar scan ..."<br>
}</code>
                </div>
            </div>
        </div>
    </div>
</body>
</html>`
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}
func getScanStatus(c *gin.Context) {
	scanID := c.Param("scan_id")

	// Check active in-memory scans first (fastest path).
	scansMutex.RLock()
	activeScan, inActive := activeScans[scanID]
	scansMutex.RUnlock()

	if inActive {
		c.JSON(http.StatusOK, ScanStatusResponse{
			ScanID:      scanID,
			Status:      activeScan.Status,
			StartedAt:   activeScan.StartedAt,
			CompletedAt: activeScan.CompletedAt,
			Output:      nil,
			Error:       nil,
		})
		return
	}

	// Check in-memory completed results cache.
	apiScansMutex.RLock()
	scan, inResults := scanResults[scanID]
	apiScansMutex.RUnlock()

	if inResults {
		var output *string
		var scanErr *string
		if scan.Output != "" {
			output = &scan.Output
		}
		if scan.Error != "" {
			scanErr = &scan.Error
		}
		c.JSON(http.StatusOK, ScanStatusResponse{
			ScanID:      scanID,
			Status:      scan.Status,
			StartedAt:   scan.StartedAt,
			CompletedAt: scan.CompletedAt,
			Output:      output,
			Error:       scanErr,
		})
		return
	}

	// #6: Fall through to DB — covers scans that survived a server restart.
	if dbScan, err := db.GetScan(scanID); err == nil && dbScan != nil {
		c.JSON(http.StatusOK, ScanStatusResponse{
			ScanID:      scanID,
			Status:      dbScan.Status,
			StartedAt:   dbScan.StartedAt,
			CompletedAt: dbScan.CompletedAt,
			Output:      nil,
			Error:       nil,
		})
		return
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
}

func getScanResults(c *gin.Context) {
	scanID := c.Param("scan_id")

	apiScansMutex.RLock()
	defer apiScansMutex.RUnlock()

	if scan, ok := scanResults[scanID]; ok {
		c.JSON(http.StatusOK, scan)
		return
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Scan results not found"})
}

func downloadScanResults(c *gin.Context) {
	scanID := c.Param("scan_id")

	apiScansMutex.RLock()
	scan, ok := scanResults[scanID]
	apiScansMutex.RUnlock()

	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan results not found"})
		return
	}

	// Create temporary file
	tmpFile, err := os.CreateTemp("", fmt.Sprintf("scan-%s-*.txt", scanID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create temp file"})
		return
	}
	defer os.Remove(tmpFile.Name())

	// Write results to file
	fmt.Fprintf(tmpFile, "Scan ID: %s\n", scanID)
	fmt.Fprintf(tmpFile, "Scan Type: %s\n", scan.ScanType)
	fmt.Fprintf(tmpFile, "Status: %s\n", scan.Status)
	fmt.Fprintf(tmpFile, "Started: %s\n", scan.StartedAt.Format(time.RFC3339))
	if scan.CompletedAt != nil {
		fmt.Fprintf(tmpFile, "Completed: %s\n", scan.CompletedAt.Format(time.RFC3339))
	}
	fmt.Fprintf(tmpFile, "\n%s\n", strings.Repeat("=", 80))
	fmt.Fprintf(tmpFile, "OUTPUT:\n")
	fmt.Fprintf(tmpFile, "%s\n\n", strings.Repeat("=", 80))
	fmt.Fprintf(tmpFile, "%s\n", scan.Output)

	if scan.Error != "" {
		fmt.Fprintf(tmpFile, "\n\n%s\n", strings.Repeat("=", 80))
		fmt.Fprintf(tmpFile, "ERRORS:\n")
		fmt.Fprintf(tmpFile, "%s\n\n", strings.Repeat("=", 80))
		fmt.Fprintf(tmpFile, "%s\n", scan.Error)
	}

	tmpFile.Close()

	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=scan-%s-results.txt", scanID))
	c.File(tmpFile.Name())
}

// Helper functions

// generateScanID returns a cryptographically random UUID v4 (#1).
// Using time.Now().UnixNano() was collision-prone under concurrent load and guessable.
func generateScanID() string {
	return uuid.New().String()
}

// extractScanTargetFromCommand infers the human-readable target from command arguments (#11).
// Special cases:
//   - JWT scans: returns "jwt-token" rather than exposing the actual token value in the DB.
func extractScanTargetFromCommand(command []string, scanType string) string {
	if len(command) == 0 {
		return ""
	}
	st := strings.ToLower(scanType)
	for i := 0; i < len(command)-1; i++ {
		arg := command[i]
		next := command[i+1]
		if next == "" {
			continue
		}
		switch arg {
		case "-d", "--domain", "-s", "--subdomain":
			return next
		}
	}
	for i := 0; i < len(command)-1; i++ {
		arg := command[i]
		next := command[i+1]
		if next == "" {
			continue
		}
		switch {
		case arg == "-u" || arg == "--url":
			return next
		case (st == "s3") && (arg == "-b" || arg == "--bucket"):
			return next
		case (st == "github" || st == "github_scan") && arg == "-r":
			return next
		case st == "github_org" && arg == "-o":
			return next
		case st == "zerodays" && arg == "-f":
			return "file:" + filepath.Base(next)
		case st == "jwt" && (arg == "-t" || arg == "--token"):
			// Never expose the raw token string in the DB.
			return "jwt-token"
		}
	}
	return ""
}

func executeScan(scanID string, command []string, scanType string) {
	initRuntimeResourceLimits()
	startedAt := time.Now()

	target := extractScanTargetFromCommand(command, scanType)
	if target == "" {
		// #11: Use a descriptive label, never just the raw scanType as if it were a domain.
		target = "[" + scanType + "]"
	}

	if ok, msg := runtimeMemoryPreflightCheck(); !ok {
		log.Printf("[executeScan] refusing to start scan %s (%s): %s", scanID, scanType, msg)
		completedAt := time.Now()
		_ = db.Init()
		_ = db.EnsureSchema()
		_ = db.CreateScan(&db.ScanRecord{
			ScanID:     scanID,
			ScanType:   scanType,
			Target:     target,
			Status:     "failed",
			StartedAt:  startedAt,
			LastUpdate: completedAt,
			Command:    strings.Join(command, " "),
		})
		_ = db.UpdateScanResult(scanID, "failed", "")
		writeScanManifest(scanID, scanType, target, startedAt, completedAt, moduleExecutionEntry{
			Module:         scanType,
			Status:         "failed",
			StartedAt:      startedAt,
			CompletedAt:    completedAt,
			DurationMS:     completedAt.Sub(startedAt).Milliseconds(),
			ScannerVersion: version.Version,
			Command:        strings.Join(command, " "),
		})
		apiScansMutex.Lock()
		result := &ScanResult{
			ScanID:      scanID,
			Status:      "failed",
			ScanType:    scanType,
			StartedAt:   startedAt,
			CompletedAt: &completedAt,
			Error:       msg,
		}
		storeScanResultLocked(scanID, result)
		apiScansMutex.Unlock()
		return
	}

	// #2: Acquire semaphore slot — blocks if maxConcurrentScans are already running.
	scanSemaphore <- struct{}{}
	defer func() { <-scanSemaphore }()

	scansMutex.Lock()
	activeScans[scanID] = &ScanInfo{
		ScanID:    scanID,
		Status:    "running",
		ScanType:  scanType,
		Target:    target,
		StartedAt: startedAt,
		Command:   strings.Join(command, " "),
	}
	scansMutex.Unlock()

	// Set initial total phases based on scan type.
	// Workflow scans (domain_run / subdomain_run) track ~18 sub-phases via the
	// subprocess; atomic one-shot scans (cf1016, misconfig, s3, …) are a single
	// indivisible step and should show 0 phases so the UI never shows phantom
	// "skipped" stages.
	initialTotalPhases := 0 // default: no sub-phase tracking
	switch scanType {
	case "domain_run", "subdomain_run":
		initialTotalPhases = 18
	}
	dbRecord := &db.ScanRecord{
		ScanID:      scanID,
		ScanType:    scanType,
		Target:      target,
		Status:      "running",
		TotalPhases: initialTotalPhases,
		StartedAt:   startedAt,
		LastUpdate:  startedAt,
		Command:     strings.Join(command, " "),
	}
	if err := db.CreateScan(dbRecord); err != nil {
		log.Printf("[executeScan] Failed to create DB scan record for %s: %v", scanID, err)
	}
	writeScanManifest(scanID, scanType, target, startedAt, time.Time{}, moduleExecutionEntry{
		Module:         scanType,
		Status:         "started",
		StartedAt:      startedAt,
		ScannerVersion: version.Version,
		Command:        strings.Join(command, " "),
	})

	// Notify scan start via webhook
	utils.SendScanNotification("start", scanID, target, scanType, "running", 0)

	if target == "demo.autoar.com" || target == "keyword.com" || target == "0x88.autoar" {
		log.Printf("[executeScan] DEMO intercepted. Generating mock artifacts for %s", target)
		go generateMockResults(scanID, target, scanType, startedAt, command)
		return
	}

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("AUTOAR_CURRENT_SCAN_ID=%s", scanID),
	)
	capture := newScanOutputCapture(scanOutputCaptureBytes)
	// Stream output to console while capturing a bounded window.
	multi := io.MultiWriter(os.Stdout, capture)
	cmd.Stdout = multi
	cmd.Stderr = multi

	if err := cmd.Start(); err != nil {
		log.Printf("[executeScan] Failed to start scan %s: %v", scanID, err)
		completedAt := time.Now()
		_ = db.UpdateScanResult(scanID, "failed", "")
		scansMutex.Lock()
		delete(activeScans, scanID)
		scansMutex.Unlock()
		apiScansMutex.Lock()
		newResult := &ScanResult{
			ScanID: scanID, Status: "failed", ScanType: scanType,
			StartedAt: startedAt, CompletedAt: &completedAt, Error: err.Error(),
		}
		storeScanResultLocked(scanID, newResult)
		apiScansMutex.Unlock()
		return
	}

	scansMutex.Lock()
	if s, ok := activeScans[scanID]; ok {
		s.ExecCmd = cmd
	}
	scansMutex.Unlock()

	err := cmd.Wait()
	output := []byte(capture.OutputString())
	completedAt := time.Now()

	scansMutex.Lock()
	si, stillThere := activeScans[scanID]
	cancelled := stillThere && si != nil && si.CancelRequested
	scansMutex.Unlock()

	// Determine final status
	finalStatus := "completed"
	if cancelled {
		finalStatus = "cancelled"
	} else if err != nil {
		finalStatus = "failed"
		log.Printf("[executeScan] Scan %s (%s) failed: %v", scanID, scanType, err)
	}

	// Extract R2 result URL from output if any
	resultURL := capture.ResultURL()
	if resultURL == "" {
		resultURL = ExtractR2ZipURLFromOutput(string(output))
	}
	if resultURL != "" {
		log.Printf("[executeScan] Extracted result URL for scan %s: %s", scanID, resultURL)
	}

	// Update DB status and result URL
	if dbErr := db.UpdateScanResult(scanID, finalStatus, resultURL); dbErr != nil {
		log.Printf("[executeScan] Failed to update DB status for %s: %v", scanID, dbErr)
	}

	// Count findings for final notification
	findingsCount := 0
	if artifacts, err := db.ListScanArtifacts(scanID); err == nil {
		for _, a := range artifacts {
			if a.Category == "vulnerability" {
				findingsCount += a.LineCount
			}
		}
	}
	utils.SendScanNotification("finish", scanID, target, scanType, finalStatus, findingsCount)

	// For atomic one-shot scans: mark the scan's single task as completed/failed
	// so the dashboard shows a clean result instead of "0 done · N skipped".
	if initialTotalPhases == 0 {
		scanLabel := map[string]string{
			"dns_cf1016": "CF1016 Dangling DNS", "dns-cf1016": "CF1016 Dangling DNS",
			"misconfig": "Misconfiguration", "s3": "S3 Bucket",
			"github": "GitHub Recon", "github_org": "GitHub Org Recon",
			"jwt": "JWT Scan",
			"dns-takeover": "DNS Takeover", "dns-dangling-ip": "Dangling IP",
			"nuclei": "Nuclei Scan", "tech": "Tech Detection",
			"ports": "Port Scan", "gf": "GF Patterns",
		}[scanType]
		if scanLabel == "" {
			scanLabel = scanType
		}
		phaseEntry := scanLabel + " scan"
		phaseFailed := finalStatus == "failed"
		_ = db.AppendScanPhase(scanID, phaseEntry, phaseFailed)
		// Also update total_phases to 1 so the UI can compute 100%.
		progress := &db.ScanProgress{
			CurrentPhase:    1,
			TotalPhases:     1,
			PhaseName:       phaseEntry,
			CompletedPhases: []string{phaseEntry},
		}
		if phaseFailed {
			progress.CompletedPhases = nil
		}
		_ = db.UpdateScanProgress(scanID, progress)
	}

	// For subdomain_run: index the scanned subdomain into the domain DB so it
	// appears in the Subdomains tab under the correct root domain.
	if scanType == "subdomain_run" && finalStatus == "completed" && target != "" {
		go func(sub string) {
			rootDomain := extractRootDomain(sub)
			if rootDomain == "" {
				rootDomain = sub
			}
			if _, err := db.InsertOrGetDomain(rootDomain); err != nil {
				log.Printf("[executeScan] failed to upsert domain %s for subdomain_run: %v", rootDomain, err)
				return
			}
			if err := db.InsertSubdomain(rootDomain, sub, true, "https://"+sub, "", 200, 0); err != nil {
				log.Printf("[executeScan] failed to insert subdomain %s under %s: %v", sub, rootDomain, err)
			} else {
				log.Printf("[executeScan] indexed subdomain %s under root domain %s", sub, rootDomain)
			}
		}(target)
	}
	// Always save full console log for the dashboard
	logPath := filepath.Join(utils.GetScanResultsDir(scanID), "scan.log")
	_ = os.WriteFile(logPath, output, 0644)
	if _, statErr := os.Stat(logPath); statErr == nil {
		if _, err := utils.IndexExistingResultFile(scanID, logPath); err != nil {
			log.Printf("[executeScan] Failed to index scan.log: %v", err)
		}
	} else if !os.IsNotExist(statErr) {
		log.Printf("[executeScan] scan.log stat failed: %v", statErr)
	}

	// Index any final tool-generated artifacts (nuclei/ffuf/gf/tech/etc) that bypass wrappers.
	indexScanArtifacts(scanID, scanType, target)
	// domain_run / subdomain_run delete local results after upload — backfill from R2 for the UI table.
	indexWorkflowArtifactsFromR2(scanID, scanType, target)
	outputFiles := collectScanOutputFiles(scanID)
	durationMS := completedAt.Sub(startedAt).Milliseconds()
	writeScanManifest(scanID, scanType, target, startedAt, completedAt, moduleExecutionEntry{
		Module:         scanType,
		Status:         finalStatus,
		StartedAt:      startedAt,
		CompletedAt:    completedAt,
		DurationMS:     durationMS,
		OutputFiles:    outputFiles,
		ScannerVersion: version.Version,
		Command:        strings.Join(command, " "),
	})

	scansMutex.Lock()
	delete(activeScans, scanID)
	scansMutex.Unlock()

	apiScansMutex.Lock()
	defer apiScansMutex.Unlock()

	// Add to in-memory results cache
	result := &ScanResult{
		ScanID:      scanID,
		Status:      finalStatus,
		ScanType:    scanType,
		StartedAt:   startedAt,
		CompletedAt: &completedAt,
		Output:      string(output),
	}

	if err != nil && finalStatus != "cancelled" {
		result.Error = err.Error()
	}
	if finalStatus == "cancelled" {
		result.Error = "cancelled by user"
	}

	storeScanResultLocked(scanID, result)
}

func indexScanArtifacts(scanID, scanType, target string) {
	resultsDir := getResultsDir()
	if scanID == "" || resultsDir == "" {
		return
	}
	roots := make([]string, 0, 8)

	// Scan types that write to new-results/<target>/ (the full domain dir).
	// These are workflow scans that own the entire target directory.
	domainRootTypes := map[string]bool{
		"domain_run": true, "subdomain_run": true, "lite": true,
		"subdomains": true, "livehosts": true, "cnames": true,
		"urls": true, "js": true, "jsscan": true, "reflection": true,
		"nuclei": true, "tech": true, "ports": true, "gf": true,
		"backup": true, "aem": true, "depconfusion": true, "wp_confusion": true,
		"zerodays": true,
	}

	if domainRootTypes[scanType] && target != "" {
		roots = append(roots, filepath.Join(resultsDir, target))
	}

	switch scanType {
	case "misconfig":
		if target != "" {
			roots = append(roots, filepath.Join(resultsDir, "misconfig", target))
			roots = append(roots, filepath.Join(resultsDir, target, "misconfig"))
		}
	case "s3":
		if target != "" {
			roots = append(roots, filepath.Join(resultsDir, "s3", target))
		}
	case "github":
		if target != "" {
			roots = append(roots, filepath.Join(resultsDir, "github", "repos", target))
		}
	case "github_org":
		if target != "" {
			roots = append(roots, filepath.Join(resultsDir, "github", "orgs", target))
		}
	case "jwt":
		roots = append(roots, filepath.Join(resultsDir, "jwt-scan"))
	case "apkx":
		if target != "" {
			roots = append(roots, filepath.Join(resultsDir, "apkx", target))
		}
	// DNS-specific scans: only index from their specific output dir, never the whole domain root.
	case "dns-takeover", "dns-dangling-ip":
		if target != "" {
			roots = append(roots, filepath.Join(resultsDir, target, "vulnerabilities", "dns-takeover"))
		}
	case "dns_cf1016", "dns-cf1016":
		if target != "" {
			roots = append(roots, filepath.Join(resultsDir, target, "vulnerabilities", "cf1016"))
			// Also pick up enumerated subdomains file (all-subs.txt / live-subs.txt written by the enumeration step)
			roots = append(roots, filepath.Join(resultsDir, target, "subs"))
		}
	case "dns-takeover-legacy", "dns_takeover_legacy":
		if target != "" {
			roots = append(roots, filepath.Join(resultsDir, target, "vulnerabilities", "dns-takeover"))
		}
	}

	// Ensure scan results directory exists for local-first file storage
	scanResultsDir := utils.GetScanResultsDir(scanID)
	_ = os.MkdirAll(scanResultsDir, 0755)

	seen := map[string]struct{}{}
	for _, root := range roots {
		if root == "" {
			continue
		}
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			if shouldSkipArtifact(path) {
				return nil
			}
			if scanType == "apkx" && !strings.HasSuffix(strings.ToLower(path), ".apk") {
				return nil
			}
			if _, ok := seen[path]; ok {
				return nil
			}
			seen[path] = struct{}{}

			// Copy file to scan results directory for local-first access
			fileName := filepath.Base(path)
			destPath := filepath.Join(scanResultsDir, fileName)
			if _, statErr := os.Stat(destPath); statErr != nil {
				if data, readErr := os.ReadFile(path); readErr == nil {
					if writeErr := os.WriteFile(destPath, data, 0644); writeErr != nil {
						log.Printf("[executeScan] failed to copy %s to scan dir: %v", fileName, writeErr)
					}
				}
			}

			// Legacy: still index for backward compat
			if _, idxErr := utils.IndexExistingResultFile(scanID, path); idxErr != nil {
				log.Printf("[executeScan] index artifact failed (%s): %v", path, idxErr)
			}
			return nil
		})
	}
}

// targetHostForR2Prefixes mirrors the UI r2PrefixesForScan hostname normalization (app.js).
func targetHostForR2Prefixes(target string) string {
	t := strings.TrimSpace(target)
	t = strings.TrimPrefix(strings.TrimPrefix(t, "http://"), "https://")
	if i := strings.Index(t, "/"); i >= 0 {
		t = t[:i]
	}
	t = strings.TrimPrefix(strings.ToLower(t), "www.")
	return t
}

// workflowScanR2Prefixes returns R2 key prefixes used for domain_run / subdomain_run (matches app.js default branch).
func workflowScanR2Prefixes(target string) []string {
	h := targetHostForR2Prefixes(target)
	if h == "" {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(p string) {
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	add("new-results/" + h + "/")
	add("results/" + h + "/")
	add("lite/" + h + "/")
	add("new-results/misconfig/" + h + "/")
	add("misconfig/" + h + "/")
	return out
}

// isR2KeyIndexableArtifact matches shouldSkipArtifact extension rules for workflow backfill.
func isR2KeyIndexableArtifact(key string) bool {
	name := strings.ToLower(filepath.Base(key))
	if name == "scan-manifest.json" || name == "cache_info.json" || name == "report-table.json" {
		return false
	}
	if strings.HasPrefix(name, ".lite-uploads-") {
		return false
	}
	if strings.HasPrefix(name, "temp-") || strings.Contains(name, "dangling-ip-temp") {
		return false
	}
	if strings.EqualFold(name, "temp-url.txt") {
		return false
	}
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".txt", ".json", ".log", ".csv", ".html", ".md", ".bin", ".xml":
		return true
	default:
		return false
	}
}

// indexWorkflowArtifactsFromR2 populates scan_artifacts from R2 listings for domain_run / subdomain_run.
// These scan types delete local result dirs on completion, so post-scan
// filesystem indexing finds nothing; uploads still land in R2. Backfilling here makes the scan modal
// use the same indexed-artifact table as other scans instead of the raw R2 fallback.
func indexWorkflowArtifactsFromR2(scanID, scanType, target string) {
	st := strings.ToLower(strings.TrimSpace(scanType))

	var r2Prefixes []string
	switch st {
	case "domain_run", "subdomain_run":
		r2Prefixes = workflowScanR2Prefixes(target)
	}

	if len(r2Prefixes) == 0 || strings.TrimSpace(scanID) == "" || !r2storage.IsEnabled() {
		return
	}
	seenKey := map[string]struct{}{}
	for _, prefix := range r2Prefixes {
		objs, err := r2storage.ListObjectsRecursive(prefix)
		if err != nil {
			log.Printf("[indexWorkflowArtifactsFromR2] list prefix %q: %v", prefix, err)
			continue
		}
		for _, o := range objs {
			if o.Size == 0 {
				continue
			}
			if !isR2KeyIndexableArtifact(o.Key) {
				continue
			}
			if _, dup := seenKey[o.Key]; dup {
				continue
			}
			seenKey[o.Key] = struct{}{}
			pub := r2storage.PublicURLForKey(o.Key)
			if pub == "" {
				continue
			}
			art := &db.ScanArtifact{
				ScanID:    scanID,
				FileName:  filepath.Base(o.Key),
				R2Key:     o.Key,
				PublicURL: pub,
				SizeBytes: o.Size,
				CreatedAt: o.LastModified,
			}
			if err := db.AppendScanArtifact(art); err != nil {
				log.Printf("[indexWorkflowArtifactsFromR2] append %s: %v", o.Key, err)
			}
		}
	}
}

func shouldSkipArtifact(path string) bool {
	name := strings.ToLower(filepath.Ext(path))
	if name == ".log" || name == ".txt" || name == ".json" || name == ".csv" || name == ".html" || name == ".md" {
		// keep these
	} else {
		// skip others by default
		// return true 
	}

	base := strings.ToLower(filepath.Base(path))
	if base == "scan-manifest.json" || base == "cache_info.json" || base == "report-table.json" {
		return true
	}
	
	skipByName := []string{
		"misconfig-scan-results.txt",
		"ffuf-results.txt",
		"ffuf-webhook-messages.txt",
		"kxss-results.txt",
		"exposure-findings.txt",
		"wp-confusion-results.txt",
		"nuclei-summary.txt",
		"all-subs.txt",
		"live-subs.txt",
		"live-hosts.txt",
		"all-urls.txt",
		"subdomains.txt",
		"enumerated-subs.txt",
		"urls.json",
		"js-urls.json",
		"subdomains.json",
		"ports.json",
		"livehosts.json",
		"cname-records.json",
	}
	for _, skip := range skipByName {
		if strings.EqualFold(base, skip) {
			return true
		}
	}

	return false
}

// CancelScanByID stops a running scan: API process (SIGKILL) or Discord context cancel.
func CancelScanByID(scanID string) error {
	scansMutex.Lock()
	defer scansMutex.Unlock()
	scan, ok := activeScans[scanID]
	if !ok {
		return fmt.Errorf("scan not found or already finished")
	}
	if scan.Status != "running" && scan.Status != "starting" && scan.Status != "paused" {
		return fmt.Errorf("scan is not active (status: %s)", scan.Status)
	}
	scan.CancelRequested = true
	if scan.ExecCmd != nil && scan.ExecCmd.Process != nil {
		if err := scan.ExecCmd.Process.Kill(); err != nil {
			// Process already exited: reconcile stale in-memory state and avoid surfacing
			// a hard error to the UI for a scan that has effectively finished.
			if strings.Contains(err.Error(), "process already finished") {
				delete(activeScans, scanID)
				_ = db.Init()
				// If status is still marked active in DB, transition it to cancelled.
				if rec, gErr := db.GetScan(scanID); gErr == nil {
					st := strings.ToLower(strings.TrimSpace(rec.Status))
					if st == "running" || st == "starting" || st == "paused" || st == "cancelling" {
						_ = db.UpdateScanStatus(scanID, "cancelled")
					}
				}
				return nil
			}
			return fmt.Errorf("kill process: %w", err)
		}
		return nil
	}
	if scan.CancelFunc != nil {
		scan.CancelFunc()
		scan.Status = "cancelling"
		return nil
	}
	return fmt.Errorf("this scan cannot be cancelled (not started via API or Discord with cancel support)")
}

// PauseScanByID sends SIGSTOP to the API scan child process (Unix only).
func PauseScanByID(scanID string) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("pause is not supported on Windows")
	}
	scansMutex.Lock()
	defer scansMutex.Unlock()
	scan, ok := activeScans[scanID]
	if !ok {
		return fmt.Errorf("scan not found or already finished")
	}
	if scan.Status != "running" && scan.Status != "starting" {
		return fmt.Errorf("only running scans can be paused (status: %s)", scan.Status)
	}
	if scan.ExecCmd == nil || scan.ExecCmd.Process == nil {
		return fmt.Errorf("pause is only available for scans started via the REST API")
	}
	if err := scan.ExecCmd.Process.Signal(syscall.SIGSTOP); err != nil {
		return fmt.Errorf("pause: %w", err)
	}
	scan.Status = "paused"
	_ = db.Init()
	if err := db.UpdateScanStatus(scanID, "paused"); err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	return nil
}

// ResumeScanByID sends SIGCONT after PauseScanByID (Unix only).
func ResumeScanByID(scanID string) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("resume is not supported on Windows")
	}
	scansMutex.Lock()
	defer scansMutex.Unlock()
	scan, ok := activeScans[scanID]
	if !ok {
		return fmt.Errorf("scan not found or already finished")
	}
	if scan.Status != "paused" {
		return fmt.Errorf("scan is not paused (status: %s)", scan.Status)
	}
	if scan.ExecCmd == nil || scan.ExecCmd.Process == nil {
		return fmt.Errorf("resume is only available for scans started via the REST API")
	}
	if err := scan.ExecCmd.Process.Signal(syscall.SIGCONT); err != nil {
		return fmt.Errorf("resume: %w", err)
	}
	scan.Status = "running"
	_ = db.Init()
	if err := db.UpdateScanStatus(scanID, "running"); err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	return nil
}

// sendFileToDiscord handles file uploads from modules
func sendFileToDiscord(c *gin.Context) {
	log.Printf("[API] [sendFileToDiscord] Received file send request")

	var req struct {
		ScanID      string `json:"scan_id"`
		FilePath    string `json:"file_path" binding:"required"`
		Description string `json:"description"`
		ChannelID   string `json:"channel_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[API] [sendFileToDiscord] [ERROR] Failed to bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("[API] [sendFileToDiscord] Request details - FilePath: %s, ChannelID: %s, ScanID: %s, Description: %s",
		req.FilePath, req.ChannelID, req.ScanID, req.Description)

	// Get channel ID - priority: request > scan_id lookup > environment > default
	var channelID string
	if req.ChannelID != "" {
		channelID = req.ChannelID
		log.Printf("[API] [sendFileToDiscord] Using channel ID from request: %s", channelID)
	} else if req.ScanID != "" {
		channelID = getChannelID(req.ScanID)
		log.Printf("[API] [sendFileToDiscord] Looked up channel ID from scan ID %s: %s", req.ScanID, channelID)
	}

	if channelID == "" {
		// Try to get from environment (set by modules)
		channelID = os.Getenv("AUTOAR_CURRENT_CHANNEL_ID")
		log.Printf("[API] [sendFileToDiscord] Tried environment variable AUTOAR_CURRENT_CHANNEL_ID: %s", channelID)
	}

	if channelID == "" {
		// Try default channel from environment
		channelID = os.Getenv("DISCORD_DEFAULT_CHANNEL_ID")
		log.Printf("[API] [sendFileToDiscord] Tried environment variable DISCORD_DEFAULT_CHANNEL_ID: %s", channelID)
	}

	if channelID == "" {
		log.Printf("[API] [sendFileToDiscord] [ERROR] No channel ID found")
		c.JSON(http.StatusBadRequest, gin.H{"error": "no channel ID found. Provide channel_id, scan_id, or set AUTOAR_CURRENT_CHANNEL_ID"})
		return
	}

	log.Printf("[API] [sendFileToDiscord] Using channel ID: %s", channelID)

	// Check if we should send to a thread instead of the channel
	threadID := ""
	if req.ScanID != "" {
		scansMutex.RLock()
		if scan, ok := activeScans[req.ScanID]; ok && scan.ThreadID != "" {
			threadID = scan.ThreadID
			log.Printf("[API] [sendFileToDiscord] Found thread ID %s for scan %s", threadID, req.ScanID)
		}
		scansMutex.RUnlock()
	}

	// If no thread found by scanID, try to find by channel ID
	if threadID == "" && channelID != "" {
		scansMutex.RLock()
		for _, scan := range activeScans {
			if scan.ChannelID == channelID && scan.ThreadID != "" {
				threadID = scan.ThreadID
				log.Printf("[API] [sendFileToDiscord] Found thread ID %s for channel %s", threadID, channelID)
				break
			}
		}
		scansMutex.RUnlock()
	}

	// Use thread ID if available, otherwise use channel ID
	targetID := channelID
	if threadID != "" {
		targetID = threadID
		log.Printf("[API] [sendFileToDiscord] Sending to thread %s (instead of channel %s)", threadID, channelID)
	}

	// Check if file exists
	log.Printf("[API] [sendFileToDiscord] Checking if file exists: %s", req.FilePath)
	if info, err := os.Stat(req.FilePath); os.IsNotExist(err) {
		log.Printf("[API] [sendFileToDiscord] [ERROR] File not found: %s", req.FilePath)
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	} else if err != nil {
		log.Printf("[API] [sendFileToDiscord] [ERROR] Failed to stat file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to stat file: %v", err)})
		return
	} else {
		log.Printf("[API] [sendFileToDiscord] File found: %s (size: %d bytes)", req.FilePath, info.Size())
	}

	// Get file info
	fileName := filepath.Base(req.FilePath)
	description := req.Description
	if description == "" {
		description = fmt.Sprintf("📁 %s", fileName)
	}

	// Get file info for size check
	fileInfo, err := os.Stat(req.FilePath)
	if err != nil {
		log.Printf("[API] [sendFileToDiscord] [ERROR] Failed to stat file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to stat file: %v", err)})
		return
	}

	// Check if file should use R2
	useR2 := r2storage.ShouldUseR2(req.FilePath) || (r2storage.IsEnabled() && fileInfo.Size() > r2storage.GetFileSizeLimit())

	if useR2 {
		// Upload to R2 and send link
		log.Printf("[API] [sendFileToDiscord] File is large (%d bytes), uploading to R2...", fileInfo.Size())
		publicURL, err := r2storage.UploadFile(req.FilePath, fileName, false)
		if err != nil {
			log.Printf("[API] [sendFileToDiscord] [ERROR] Failed to upload to R2: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to upload to R2: %v", err)})
			return
		}

		// Get Discord session to send link
		discordSessionMutex.RLock()
		session := globalDiscordSession
		discordSessionMutex.RUnlock()

		if session == nil {
			log.Printf("[API] [sendFileToDiscord] [ERROR] Discord session is nil")
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Discord bot not available"})
			return
		}

		// Send R2 link to Discord
		message := fmt.Sprintf("%s\n\n📦 **File too large for Discord** (%.2f MB)\n🔗 **Download:** %s", description, float64(fileInfo.Size())/1024/1024, publicURL)
		_, err = session.ChannelMessageSend(channelID, message)
		if err != nil {
			log.Printf("[API] [sendFileToDiscord] [ERROR] Failed to send R2 link to Discord: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to send R2 link: %v", err)})
			return
		}

		log.Printf("[API] [sendFileToDiscord] [SUCCESS] R2 link sent successfully: %s", publicURL)
		c.JSON(http.StatusOK, gin.H{
			"message":   "file uploaded to R2 and link sent",
			"r2_url":    publicURL,
			"file_size": fileInfo.Size(),
		})
		return
	}

	// #4: Stream file via os.Open instead of loading everything into RAM with os.ReadFile.
	log.Printf("[API] [sendFileToDiscord] Opening file for streaming: %s", req.FilePath)
	fileStream, streamErr := os.Open(req.FilePath)
	if streamErr != nil {
		log.Printf("[API] [sendFileToDiscord] [ERROR] Failed to open file: %v", streamErr)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to open file: %v", streamErr)})
		return
	}
	defer fileStream.Close()
	log.Printf("[API] [sendFileToDiscord] Streaming %d bytes to Discord", fileInfo.Size())

	// Detect content type from the first 512 bytes without buffering the whole file.
	header := make([]byte, 512)
	n, _ := fileStream.Read(header)
	contentType := http.DetectContentType(header[:n])
	// Seek back to the beginning so the full file is sent.
	_, _ = fileStream.Seek(0, io.SeekStart)

	// Get Discord session
	log.Printf("[API] [sendFileToDiscord] Getting Discord session...")
	discordSessionMutex.RLock()
	session := globalDiscordSession
	discordSessionMutex.RUnlock()

	if session == nil {
		log.Printf("[API] [sendFileToDiscord] [ERROR] Discord session is nil")
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Discord bot not available"})
		return
	}
	log.Printf("[API] [sendFileToDiscord] Discord session obtained")

	// Stream file to Discord channel/thread (no memory buffer)
	log.Printf("[API] [sendFileToDiscord] Streaming file to Discord %s: %s (description: %s)", targetID, fileName, description)
	_, err = session.ChannelMessageSendComplex(targetID, &discordgo.MessageSend{
		Content: description,
		Files: []*discordgo.File{
			{
				Name:        fileName,
				ContentType: contentType,
				Reader:      fileStream,
			},
		},
	})

	if err != nil {
		// If direct upload fails due to size, try R2 as fallback
		if strings.Contains(err.Error(), "413") || strings.Contains(err.Error(), "too large") || strings.Contains(err.Error(), "Request entity too large") {
			log.Printf("[API] [sendFileToDiscord] ⚠️  Discord upload failed due to size, uploading to R2 as fallback...")
			if r2storage.IsEnabled() {
				publicURL, r2Err := r2storage.UploadFile(req.FilePath, fileName, false)
				if r2Err != nil {
					log.Printf("[API] [sendFileToDiscord] [ERROR] Failed to upload to R2: %v", r2Err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to send file and R2 upload failed: %v (R2 error: %v)", err, r2Err)})
					return
				}
				message := fmt.Sprintf("%s\n\n📦 **File too large for Discord** (%.2f MB)\n🔗 **Download:** %s", description, float64(fileInfo.Size())/1024/1024, publicURL)
				_, err = session.ChannelMessageSend(targetID, message)
				if err != nil {
					log.Printf("[API] [sendFileToDiscord] [ERROR] Failed to send R2 link: %v", err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to send R2 link: %v", err)})
					return
				}
				log.Printf("[API] [sendFileToDiscord] [SUCCESS] R2 link sent successfully (fallback): %s", publicURL)
				c.JSON(http.StatusOK, gin.H{
					"message":   "file uploaded to R2 and link sent (fallback)",
					"r2_url":    publicURL,
					"file_size": fileInfo.Size(),
				})
				return
			}
		}
		log.Printf("[API] [sendFileToDiscord] [ERROR] Failed to send file to Discord: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to send file: %v", err)})
		return
	}

	log.Printf("[API] [sendFileToDiscord] [SUCCESS] File sent successfully to Discord channel %s", channelID)
	c.JSON(http.StatusOK, gin.H{"message": "file sent successfully"})
}

// sendMessageToDiscord handles sending text messages from modules
func sendMessageToDiscord(c *gin.Context) {
	log.Printf("[API] [sendMessageToDiscord] Received message send request")

	var req struct {
		ScanID    string `json:"scan_id"`
		Message   string `json:"message" binding:"required"`
		ChannelID string `json:"channel_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var channelID string
	if req.ChannelID != "" {
		channelID = req.ChannelID
	} else if req.ScanID != "" {
		channelID = getChannelID(req.ScanID)
	}
	if channelID == "" {
		channelID = os.Getenv("AUTOAR_CURRENT_CHANNEL_ID")
	}
	if channelID == "" {
		channelID = os.Getenv("DISCORD_DEFAULT_CHANNEL_ID")
	}
	if channelID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no channel ID found"})
		return
	}

	threadID := ""
	if req.ScanID != "" {
		scansMutex.RLock()
		if scan, ok := activeScans[req.ScanID]; ok && scan.ThreadID != "" {
			threadID = scan.ThreadID
		}
		scansMutex.RUnlock()
	}
	if threadID == "" && channelID != "" {
		scansMutex.RLock()
		for _, scan := range activeScans {
			if scan.ChannelID == channelID && scan.ThreadID != "" {
				threadID = scan.ThreadID
				break
			}
		}
		scansMutex.RUnlock()
	}

	targetID := channelID
	if threadID != "" {
		targetID = threadID
	}

	discordSessionMutex.RLock()
	session := globalDiscordSession
	discordSessionMutex.RUnlock()

	if session == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Discord bot not available"})
		return
	}

	_, err := session.ChannelMessageSend(targetID, req.Message)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to send message: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "message sent successfully"})
}

func generateMockResults(scanID, target, scanType string, startedAt time.Time, command []string) {
	time.Sleep(2 * time.Second)
	resultsDir := filepath.Join(os.Getenv("AUTOAR_RESULTS_DIR"), target)
	_ = os.MkdirAll(resultsDir, 0755)

	_ = os.WriteFile(filepath.Join(resultsDir, "urls.txt"), []byte(fmt.Sprintf("https://%[1]s/api\nhttps://%[1]s/admin\nhttps://%[1]s/test", target)), 0644)
	_ = os.WriteFile(filepath.Join(resultsDir, "js-urls.json"), []byte(fmt.Sprintf("[\"https://%[1]s/main.js\",\"https://%[1]s/vendor.chunk.js\"]", target)), 0644)
	_ = os.WriteFile(filepath.Join(resultsDir, "nuclei-results.json"), []byte(fmt.Sprintf("[{\"template-id\": \"cve-2023-1000\", \"info\": {\"name\": \"Mock CVE\", \"severity\": \"high\"}, \"host\": \"%[1]s\", \"matched-at\": \"https://%[1]s/api\"}]", target)), 0644)
	_ = os.WriteFile(filepath.Join(resultsDir, "buckets-s3.json"), []byte(fmt.Sprintf("[{\"target\": \"%s-bucket\", \"status\": \"Open\", \"vulnerable\": true, \"severity\": \"critical\"}]", target)), 0644)
	_ = os.WriteFile(filepath.Join(resultsDir, "backup-files.json"), []byte(fmt.Sprintf("[{\"url\": \"https://%[1]s/backup.zip\", \"size\": 1048576, \"severity\": \"high\"}]", target)), 0644)
	_ = os.WriteFile(filepath.Join(resultsDir, "ports-nmap.json"), []byte(fmt.Sprintf("[{\"host\": \"%[1]s\", \"port\": 8080, \"service\": \"http-alt\", \"severity\": \"info\"}]", target)), 0644)
	_ = os.WriteFile(filepath.Join(resultsDir, "js-secrets.json"), []byte(fmt.Sprintf("[{\"file\": \"https://%[1]s/main.js\", \"secret\": \"AKIA1234567890\", \"type\": \"AWS API Key\", \"severity\": \"high\"}]", target)), 0644)
	_ = os.WriteFile(filepath.Join(resultsDir, "zeroday-results.json"), []byte(fmt.Sprintf("[{\"target\": \"https://%[1]s\", \"finding\": \"CVE-2024-XXXX Node.js Remote Code Execution\", \"severity\": \"critical\"}]", target)), 0644)
	_ = os.WriteFile(filepath.Join(resultsDir, "aem-scan.json"), []byte(fmt.Sprintf("[{\"target\": \"https://%[1]s/aem\", \"finding\": \"AEM Default Credentials\", \"severity\": \"critical\"}]", target)), 0644)
	_ = os.WriteFile(filepath.Join(resultsDir, "misconfig-mapper.json"), []byte(fmt.Sprintf("[{\"target\": \"https://%[1]s/.git\", \"finding\": \"Exposed Git Directory\", \"severity\": \"medium\"}]", target)), 0644)
	_ = os.WriteFile(filepath.Join(resultsDir, "wp-confusion-results.json"), []byte(fmt.Sprintf("[{\"target\": \"https://%[1]s/wp-content\", \"finding\": \"WordPress Missing Theme\", \"severity\": \"medium\"}]", target)), 0644)
	_ = os.WriteFile(filepath.Join(resultsDir, "depconf-scan.json"), []byte("[{\"target\": \"package.json\", \"finding\": \"Dependency Confusion in 'internal-core'\", \"severity\": \"high\"}]"), 0644)

	// Add remaining simulation payloads
	_ = os.WriteFile(filepath.Join(resultsDir, "ffuf-results.json"), []byte(fmt.Sprintf("[{\"url\": \"https://%[1]s/secret-dir\", \"status\": 200, \"length\": 1024, \"finding\": \"Hidden Directory\", \"severity\": \"medium\"}]", target)), 0644)
	_ = os.WriteFile(filepath.Join(resultsDir, "dalfox-results.json"), []byte(fmt.Sprintf("[{\"target\": \"https://%[1]s/?q=test\", \"finding\": \"Reflected XSS in 'q' parameter\", \"severity\": \"high\"}]", target)), 0644)
	_ = os.WriteFile(filepath.Join(resultsDir, "kxss-results.txt"), []byte(fmt.Sprintf("URL: https://%[1]s/?id=test Param: id Reflection: true", target)), 0644)
	_ = os.WriteFile(filepath.Join(resultsDir, "sqlmap-results.json"), []byte(fmt.Sprintf("[{\"target\": \"https://%[1]s/?id=1\", \"finding\": \"Time-based blind SQLi (MySQL)\", \"severity\": \"critical\"}]", target)), 0644)
	_ = os.WriteFile(filepath.Join(resultsDir, "gf-xss.json"), []byte(fmt.Sprintf("[{\"target\": \"https://%[1]s/?action=test\", \"finding\": \"Potential XSS Endpoint\", \"severity\": \"info\"}]", target)), 0644)
	_ = os.WriteFile(filepath.Join(resultsDir, "cname-takeover-vulnerable.txt"), []byte(fmt.Sprintf("https://test.%[1]s", target)), 0644)
	_ = os.WriteFile(filepath.Join(resultsDir, "cf1016-dangling.json"), []byte(fmt.Sprintf("[{\"target\": \"cloud.%[1]s\", \"finding\": \"Cloudflare Error 1016 (Dangling Record)\", \"cloudflare_ips\": [\"104.21.XX.XX\"], \"severity\": \"high\"}]", target)), 0644)
	_ = os.WriteFile(filepath.Join(resultsDir, "github-scan.json"), []byte("[{\"target\": \"https://github.com/org/repo\", \"finding\": \"Leaked Stripe API Key in commit\", \"severity\": \"critical\"}]"), 0644)

	completedAt := time.Now()
	_ = db.UpdateScanResult(scanID, "completed", "")

	scansMutex.Lock()
	delete(activeScans, scanID)
	scansMutex.Unlock()

	apiScansMutex.Lock()
	storeScanResultLocked(scanID, &ScanResult{
		ScanID: scanID, Status: "completed", ScanType: scanType,
		StartedAt: startedAt, CompletedAt: &completedAt, Error: "",
	})
	apiScansMutex.Unlock()

	// Index
	indexScanArtifacts(scanID, scanType, target)
}

// getEnv is defined in main.go
