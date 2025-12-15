package gobot

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/bwmarrin/discordgo"
)

var (
	scanResults   = make(map[string]*ScanResult)
	apiScansMutex sync.RWMutex
)

// ScanInfo is defined in commands.go

type ScanResult struct {
	ScanID     string    `json:"scan_id"`
	Status     string    `json:"status"`
	ScanType   string    `json:"scan_type"`
	StartedAt  time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Output     string    `json:"output,omitempty"`
	Error      string    `json:"error,omitempty"`
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
	PhaseTimeout      *int    `json:"phase_timeout"`
	TimeoutLivehosts  *int    `json:"timeout_livehosts"`
	TimeoutReflection *int    `json:"timeout_reflection"`
	TimeoutJS         *int    `json:"timeout_js"`
	TimeoutNuclei      *int    `json:"timeout_nuclei"`
	Query             *string `json:"query"`
	Provider          *string `json:"provider"`
	APIKey            *string `json:"api_key"`
}

type ScanResponse struct {
	ScanID  string `json:"scan_id"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Command string `json:"command,omitempty"`
}

type ScanStatusResponse struct {
	ScanID     string    `json:"scan_id"`
	Status     string    `json:"status"`
	StartedAt  time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Output     *string   `json:"output,omitempty"`
	Error      *string   `json:"error,omitempty"`
}

type ScanListResponse struct {
	ActiveScans    []ScanInfo `json:"active_scans"`
	CompletedScans []ScanInfo  `json:"completed_scans"`
}

// Setup API routes
func setupAPI() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// CORS middleware
	r.Use(corsMiddleware())

	// Root
	r.GET("/", rootHandler)
	r.GET("/health", healthHandler)

	// Scan endpoints
	api := r.Group("/scan")
	{
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
		api.POST("/s3", scanS3)
		api.POST("/github", scanGitHub)
		api.POST("/github_org", scanGitHubOrg)
		api.POST("/lite", scanLite)
		api.GET("/:scan_id/status", getScanStatus)
		api.GET("/:scan_id/results", getScanResults)
		api.GET("/:scan_id/download", downloadScanResults)
	}

	// KeyHack endpoints
	keyhack := r.Group("/keyhack")
	{
		keyhack.POST("/search", keyhackSearch)
		keyhack.POST("/validate", keyhackValidate)
	}

	// Internal endpoints for module file notifications
	internal := r.Group("/internal")
	{
		internal.POST("/send-file", sendFileToDiscord)
	}

	// List all scans
	r.GET("/scans", listScans)

	return r
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
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
		"version": "1.0.0",
		"docs":    "/docs",
		"status":  "operational",
	})
}

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// Scan handlers
func scanSubdomains(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Domain == nil || *req.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain is required"})
		return
	}

	scanID := generateScanID()
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "subdomains", "get", "-d", *req.Domain}

	go executeScan(scanID, command, "subdomains")

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("Subdomain enumeration started for %s", *req.Domain),
		Command: strings.Join(command, " "),
	})
}

func scanLivehosts(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Domain == nil || *req.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain is required"})
		return
	}

	scanID := generateScanID()
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "livehosts", "get", "-d", *req.Domain}

	go executeScan(scanID, command, "livehosts")

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("Live hosts discovery started for %s", *req.Domain),
		Command: strings.Join(command, " "),
	})
}

func scanCnames(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Domain == nil || *req.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain is required"})
		return
	}

	scanID := generateScanID()
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "cnames", "get", "-d", *req.Domain}

	go executeScan(scanID, command, "cnames")

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("CNAME enumeration started for %s", *req.Domain),
		Command: strings.Join(command, " "),
	})
}

func scanURLs(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Domain == nil || *req.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain is required"})
		return
	}

	scanID := generateScanID()
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "urls", "collect", "-d", *req.Domain}

	go executeScan(scanID, command, "urls")

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("URL collection started for %s", *req.Domain),
		Command: strings.Join(command, " "),
	})
}

func scanJS(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Domain == nil || *req.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain is required"})
		return
	}

	scanID := generateScanID()
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "js", "scan", "-d", *req.Domain}

	if req.Subdomain != nil && *req.Subdomain != "" {
		command = append(command, "-s", *req.Subdomain)
	}

	go executeScan(scanID, command, "js")

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("JavaScript scan started for %s", *req.Domain),
		Command: strings.Join(command, " "),
	})
}

func scanReflection(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Domain == nil || *req.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain is required"})
		return
	}

	scanID := generateScanID()
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "reflection", "scan", "-d", *req.Domain}

	go executeScan(scanID, command, "reflection")

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("Reflection scan started for %s", *req.Domain),
		Command: strings.Join(command, " "),
	})
}

func scanNuclei(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if (req.Domain == nil || *req.Domain == "") && (req.URL == nil || *req.URL == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Either domain or url is required"})
		return
	}

	if req.Domain != nil && req.URL != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot use both domain and url together"})
		return
	}

	scanID := generateScanID()
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "nuclei", "run"}

	var target string
	if req.Domain != nil {
		command = append(command, "-d", *req.Domain)
		target = *req.Domain
	} else {
		command = append(command, "-u", *req.URL)
		target = *req.URL
	}

	mode := "full"
	if req.Mode != nil {
		mode = *req.Mode
		if mode != "full" && mode != "cves" && mode != "panels" && mode != "default-logins" && mode != "vulnerabilities" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Mode must be full, cves, panels, default-logins, or vulnerabilities"})
			return
		}
	}
	command = append(command, "-m", mode)

	go executeScan(scanID, command, fmt.Sprintf("nuclei-%s", mode))

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("Nuclei %s scan started for %s", mode, target),
		Command: strings.Join(command, " "),
	})
}

func scanTech(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Domain == nil || *req.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain is required"})
		return
	}

	scanID := generateScanID()
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "tech", "detect", "-d", *req.Domain}

	go executeScan(scanID, command, "tech")

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("Technology detection started for %s", *req.Domain),
		Command: strings.Join(command, " "),
	})
}

func scanPorts(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Domain == nil || *req.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain is required"})
		return
	}

	scanID := generateScanID()
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "ports", "scan", "-d", *req.Domain}

	go executeScan(scanID, command, "ports")

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("Port scan started for %s", *req.Domain),
		Command: strings.Join(command, " "),
	})
}

func scanGF(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Domain == nil || *req.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain is required"})
		return
	}

	scanID := generateScanID()
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "gf", "scan", "-d", *req.Domain}

	go executeScan(scanID, command, "gf")

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("GF pattern scan started for %s", *req.Domain),
		Command: strings.Join(command, " "),
	})
}

func scanDNSTakeover(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Domain == nil || *req.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain is required"})
		return
	}

	scanID := generateScanID()
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "dns", "takeover", "-d", *req.Domain}

	go executeScan(scanID, command, "dns-takeover")

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("DNS takeover scan started for %s", *req.Domain),
		Command: strings.Join(command, " "),
	})
}

func scanS3(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Bucket == nil || *req.Bucket == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bucket name is required"})
		return
	}

	scanID := generateScanID()
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "s3", "scan", "-b", *req.Bucket}

	if req.Region != nil && *req.Region != "" {
		command = append(command, "-r", *req.Region)
	}

	go executeScan(scanID, command, "s3")

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("S3 bucket scan started for %s", *req.Bucket),
		Command: strings.Join(command, " "),
	})
}

func scanGitHub(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Repo == nil || *req.Repo == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Repository (owner/repo) is required"})
		return
	}

	scanID := generateScanID()
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "github", "scan", "-r", *req.Repo}

	go executeScan(scanID, command, "github")

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("GitHub scan started for %s", *req.Repo),
		Command: strings.Join(command, " "),
	})
}

func scanGitHubOrg(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	org := req.Repo
	if org == nil || *org == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Organization name is required (use 'repo' field)"})
		return
	}

	scanID := generateScanID()
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "github", "org", "-o", *org}

	go executeScan(scanID, command, "github_org")

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("GitHub organization scan started for %s", *org),
		Command: strings.Join(command, " "),
	})
}

func scanLite(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Domain == nil || *req.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain is required"})
		return
	}

	scanID := generateScanID()
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "lite", "run", "-d", *req.Domain}

	if req.SkipJS != nil && *req.SkipJS {
		command = append(command, "--skip-js")
	}

	if req.PhaseTimeout != nil && *req.PhaseTimeout > 0 {
		command = append(command, "--phase-timeout", fmt.Sprintf("%d", *req.PhaseTimeout))
	}
	if req.TimeoutLivehosts != nil && *req.TimeoutLivehosts >= 0 {
		command = append(command, "--timeout-livehosts", fmt.Sprintf("%d", *req.TimeoutLivehosts))
	}
	if req.TimeoutReflection != nil && *req.TimeoutReflection >= 0 {
		command = append(command, "--timeout-reflection", fmt.Sprintf("%d", *req.TimeoutReflection))
	}
	if req.TimeoutJS != nil && *req.TimeoutJS >= 0 {
		command = append(command, "--timeout-js", fmt.Sprintf("%d", *req.TimeoutJS))
	}
	if req.TimeoutNuclei != nil && *req.TimeoutNuclei >= 0 {
		command = append(command, "--timeout-nuclei", fmt.Sprintf("%d", *req.TimeoutNuclei))
	}

	go executeScan(scanID, command, "lite")

	message := fmt.Sprintf("Lite scan started for %s (per-phase timeout: 1h default)", *req.Domain)
	if req.PhaseTimeout != nil {
		message = fmt.Sprintf("Lite scan started for %s (default per-phase timeout: %ds)", *req.Domain, *req.PhaseTimeout)
	}
	if req.SkipJS != nil && *req.SkipJS {
		message += " (JavaScript scanning skipped)"
	}

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: message,
		Command: strings.Join(command, " "),
	})
}

func keyhackSearch(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Query == nil || *req.Query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Search query is required"})
		return
	}

	scanID := generateScanID()
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "keyhack", "search", *req.Query}

	go executeScan(scanID, command, "keyhack_search")

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("Searching for templates matching: %s", *req.Query),
		Command: strings.Join(command, " "),
	})
}

func keyhackValidate(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Provider == nil || *req.Provider == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Provider name is required"})
		return
	}

	if req.APIKey == nil || *req.APIKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "API key is required"})
		return
	}

	scanID := generateScanID()
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "keyhack", "validate", *req.Provider, *req.APIKey}

	go executeScan(scanID, command, "keyhack_validate")

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("Generating validation command for %s", *req.Provider),
		Command: strings.Join(command, " "),
	})
}

func getScanStatus(c *gin.Context) {
	scanID := c.Param("scan_id")

	scansMutex.RLock()
	defer scansMutex.RUnlock()

	// Check active scans (from commands.go)
	if scan, ok := activeScans[scanID]; ok {
		c.JSON(http.StatusOK, ScanStatusResponse{
			ScanID:      scanID,
			Status:      scan.Status,
			StartedAt:   scan.StartedAt,
			CompletedAt: scan.CompletedAt,
			Output:      nil,
			Error:       nil,
		})
		return
	}

	// Check completed scans
	if scan, ok := scanResults[scanID]; ok {
		var output *string
		var err *string
		if scan.Output != "" {
			output = &scan.Output
		}
		if scan.Error != "" {
			err = &scan.Error
		}
		c.JSON(http.StatusOK, ScanStatusResponse{
			ScanID:      scanID,
			Status:      scan.Status,
			StartedAt:   scan.StartedAt,
			CompletedAt: scan.CompletedAt,
			Output:      output,
			Error:       err,
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

func listScans(c *gin.Context) {
	scansMutex.RLock()
	defer scansMutex.RUnlock()
	
	apiScansMutex.RLock()
	defer apiScansMutex.RUnlock()

	active := make([]ScanInfo, 0, len(activeScans))
	for _, scan := range activeScans {
		active = append(active, *scan)
	}

	completed := make([]ScanInfo, 0, len(scanResults))
	count := 0
	for _, scan := range scanResults {
		if count >= 20 {
			break
		}
		completed = append(completed, ScanInfo{
			ScanID:      scan.ScanID,
			Type:        scan.ScanType,
			ScanType:    scan.ScanType,
			Target:      scan.ScanID,
			Status:      scan.Status,
			StartTime:   scan.StartedAt,
			StartedAt:   scan.StartedAt,
			CompletedAt: scan.CompletedAt,
		})
		count++
	}

	c.JSON(http.StatusOK, ScanListResponse{
		ActiveScans:    active,
		CompletedScans: completed,
	})
}

// Helper functions
func generateScanID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func executeScan(scanID string, command []string, scanType string) {
	startedAt := time.Now()

	scansMutex.Lock()
	activeScans[scanID] = &ScanInfo{
		ScanID:    scanID,
		Status:    "running",
		ScanType:  scanType,
		StartedAt: startedAt,
		Command:   strings.Join(command, " "),
	}
	scansMutex.Unlock()

	// Execute command
	cmd := exec.Command(command[0], command[1:]...)
	output, err := cmd.CombinedOutput()

	completedAt := time.Now()

	scansMutex.Lock()
	delete(activeScans, scanID)
	scansMutex.Unlock()

	apiScansMutex.Lock()
	defer apiScansMutex.Unlock()

	// Add to results
	result := &ScanResult{
		ScanID:      scanID,
		Status:      "completed",
		ScanType:    scanType,
		StartedAt:   startedAt,
		CompletedAt: &completedAt,
		Output:      string(output),
	}

	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
	}

	scanResults[scanID] = result
}

// sendFileToDiscord handles file uploads from modules
func sendFileToDiscord(c *gin.Context) {
	var req struct {
		ScanID      string `json:"scan_id"`
		FilePath    string `json:"file_path" binding:"required"`
		Description string `json:"description"`
		ChannelID   string `json:"channel_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get channel ID - priority: request > scan_id lookup > environment > default
	var channelID string
	if req.ChannelID != "" {
		channelID = req.ChannelID
	} else if req.ScanID != "" {
		channelID = getChannelID(req.ScanID)
	}
	
	if channelID == "" {
		// Try to get from environment (set by modules)
		channelID = os.Getenv("AUTOAR_CURRENT_CHANNEL_ID")
	}
	
	if channelID == "" {
		// Try default channel from environment
		channelID = os.Getenv("DISCORD_DEFAULT_CHANNEL_ID")
	}
	
	if channelID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no channel ID found. Provide channel_id, scan_id, or set AUTOAR_CURRENT_CHANNEL_ID"})
		return
	}

	// Check if file exists
	if _, err := os.Stat(req.FilePath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}

	// Read file
	fileData, err := os.ReadFile(req.FilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to read file: %v", err)})
		return
	}

	// Get Discord session
	discordSessionMutex.RLock()
	session := globalDiscordSession
	discordSessionMutex.RUnlock()

	if session == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Discord bot not available"})
		return
	}

	// Send file to Discord channel
	fileName := filepath.Base(req.FilePath)
	description := req.Description
	if description == "" {
		description = fmt.Sprintf("📁 %s", fileName)
	}

	_, err = session.ChannelMessageSendComplex(channelID, &discordgo.MessageSend{
		Content: description,
		Files: []*discordgo.File{
			{
				Name:        fileName,
				ContentType: http.DetectContentType(fileData),
				Reader:      strings.NewReader(string(fileData)),
			},
		},
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to send file: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "file sent successfully"})
}

// getCompletedScans returns recent completed scans (for Discord bot)
func getCompletedScans(limit int) []*ScanResult {
	apiScansMutex.RLock()
	defer apiScansMutex.RUnlock()
	
	results := make([]*ScanResult, 0, limit)
	count := 0
	for _, result := range scanResults {
		if count >= limit {
			break
		}
		results = append(results, result)
		count++
	}
	return results
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// getEnv is defined in main.go
