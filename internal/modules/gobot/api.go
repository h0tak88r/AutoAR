package gobot

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/bwmarrin/discordgo"
	"github.com/h0tak88r/AutoAR/internal/modules/r2storage"
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
	Domain            *string   `json:"domain"`
	Subdomain         *string   `json:"subdomain"`
	URL               *string   `json:"url"`
	Bucket            *string   `json:"bucket"`
	Region            *string   `json:"region"`
	Repo              *string   `json:"repo"`
	FilePath          *string   `json:"file_path"`
	Strategy          *string   `json:"strategy"`
	Pattern           *string   `json:"pattern"`
	Interval          *int      `json:"interval"`
	All               *bool     `json:"all"`
	Daemon            *bool     `json:"daemon"`
	Mode              *string   `json:"mode"`
	SkipJS            *bool     `json:"skip_js"`
	PhaseTimeout      *int      `json:"phase_timeout"`
	TimeoutLivehosts  *int      `json:"timeout_livehosts"`
	TimeoutReflection *int      `json:"timeout_reflection"`
	TimeoutJS         *int      `json:"timeout_js"`
	TimeoutNuclei      *int      `json:"timeout_nuclei"`
	Query             *string   `json:"query"`
	Provider          *string   `json:"provider"`
	APIKey            *string   `json:"api_key"`
	// FFuf options
	Target            *string   `json:"target"`            // FFuf target URL
	Wordlist          *string   `json:"wordlist"`         // FFuf wordlist path
	Threads           *int      `json:"threads"`          // FFuf threads
	Recursion         *bool     `json:"recursion"`        // FFuf recursion
	RecursionDepth    *int      `json:"recursion_depth"`  // FFuf recursion depth
	Bypass403         *bool     `json:"bypass_403"`       // FFuf 403 bypass
	Extensions        *[]string `json:"extensions"`       // FFuf extensions
	CustomHeaders     *map[string]string `json:"custom_headers"` // FFuf custom headers
	// Zerodays options
	DomainsFile       *string   `json:"domains_file"`     // Zerodays domains file
	DOSTest           *bool     `json:"dos_test"`         // Zerodays DoS test
	EnableSourceExposure *bool  `json:"enable_source_exposure"` // Zerodays source exposure
	Silent            *bool     `json:"silent"`            // Zerodays silent mode
	CVEs              *[]string `json:"cves"`             // CVEs to check (CVE-2025-55182, CVE-2025-14847)
	MongoDBHost       *string   `json:"mongodb_host"`     // MongoDB host for CVE-2025-14847
	MongoDBPort       *int     `json:"mongodb_port"`       // MongoDB port for CVE-2025-14847
	// JWT options
	Token             *string   `json:"token"`            // JWT token
	SkipCrack         *bool     `json:"skip_crack"`       // JWT skip crack
	SkipPayloads      *bool     `json:"skip_payloads"`    // JWT skip payloads
	WordlistPath      *string   `json:"wordlist_path"`    // JWT wordlist
	MaxCrackAttempts  *int      `json:"max_crack_attempts"` // JWT max crack attempts
	// Misconfig options
	ServiceID         *string   `json:"service_id"`        // Misconfig service ID
	Delay             *int      `json:"delay"`            // Misconfig delay (ms)
	Permutations      *bool     `json:"permutations"`      // Enable permutations (slower but more thorough)
	// DNS options
	DNSType           *string   `json:"dns_type"`         // DNS scan type: takeover, dangling-ip
	// URLs options
	SkipSubdomainEnum *bool     `json:"skip_subdomain_enum"` // URLs: skip subdomain enumeration (treat as single subdomain)
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
	r.GET("/metrics", metricsHandler)
	r.GET("/docs", docsHandler)

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
		api.POST("/dns", scanDNS) // New unified DNS endpoint (supports takeover and dangling-ip)
		api.POST("/s3", scanS3)
		api.POST("/github", scanGitHub)
		api.POST("/github_org", scanGitHubOrg)
		api.POST("/lite", scanLite)
		api.POST("/apkx", scanApkX)
		api.POST("/ffuf", scanFFuf) // FFuf fuzzing
		api.POST("/backup", scanBackup) // Backup file discovery
		api.POST("/misconfig", scanMisconfig) // Cloud misconfiguration scan
		api.POST("/zerodays", scanZerodays) // Zerodays scan (CVE-2025-55182 React2Shell, CVE-2025-14847 MongoDB)
		api.POST("/jwt", scanJWT) // JWT vulnerability scan
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

	// Utility endpoints
	r.POST("/cleanup", cleanupHandler)

	return r
}

// scanApkX performs static analysis on an APK or IPA file using the
// embedded apkX engine. The request must provide an absolute file_path
// that is readable by the AutoAR process.
func scanApkX(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.FilePath == nil || *req.FilePath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file_path is required and must be an absolute path"})
		return
	}

	scanID := generateScanID()
	command := []string{
		getAutoarScriptPath(),
		"apkx", "scan",
		"-i", *req.FilePath,
	}

	go executeScan(scanID, command, "apkx")

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("apkX analysis started for %s", *req.FilePath),
		Command: strings.Join(command, " "),
	})
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
		"version": "3.3.1",
		"docs":    "/docs",
		"status":  "operational",
	})
}

func healthHandler(c *gin.Context) {
	snapshot := getMetricsSnapshot()
	
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"uptime":    snapshot["uptime"],
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
            <div class="version">Version 3.3.1</div>
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
                <div class="endpoint-path"><span class="method post">POST</span> /scan/apkx</div>
                <div class="description">APK/IPA static analysis</div>
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
	command := []string{getAutoarScriptPath(), "subdomains", "get", "-d", *req.Domain}

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
	
	// Add --subdomain flag if SkipSubdomainEnum is set and true
	if req.SkipSubdomainEnum != nil && *req.SkipSubdomainEnum {
		command = append(command, "--subdomain")
	}

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

// scanDNS handles DNS scans (takeover or dangling-ip)
func scanDNS(c *gin.Context) {
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
	dnsType := "takeover"
	if req.DNSType != nil && *req.DNSType != "" {
		dnsType = *req.DNSType
		if dnsType != "takeover" && dnsType != "dangling-ip" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "dns_type must be 'takeover' or 'dangling-ip'"})
			return
		}
	}

	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "dns", dnsType, "-d", *req.Domain}

	go executeScan(scanID, command, fmt.Sprintf("dns-%s", dnsType))

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("DNS %s scan started for %s", dnsType, *req.Domain),
		Command: strings.Join(command, " "),
	})
}

// scanFFuf handles FFuf fuzzing requests
func scanFFuf(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Target == nil || *req.Target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target URL is required"})
		return
	}

	scanID := generateScanID()
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "ffuf", "fuzz", "-u", *req.Target}

	if req.Wordlist != nil && *req.Wordlist != "" {
		command = append(command, "-w", *req.Wordlist)
	}
	if req.Threads != nil && *req.Threads > 0 {
		command = append(command, "-t", fmt.Sprintf("%d", *req.Threads))
	}
	if req.Recursion != nil && *req.Recursion {
		command = append(command, "--recursion")
		if req.RecursionDepth != nil && *req.RecursionDepth > 0 {
			command = append(command, "--recursion-depth", fmt.Sprintf("%d", *req.RecursionDepth))
		}
	}
	if req.Bypass403 != nil && *req.Bypass403 {
		command = append(command, "--bypass-403")
	}
	if req.Extensions != nil && len(*req.Extensions) > 0 {
		command = append(command, "-e", strings.Join(*req.Extensions, ","))
	}
	if req.CustomHeaders != nil && len(*req.CustomHeaders) > 0 {
		for k, v := range *req.CustomHeaders {
			command = append(command, "--header", fmt.Sprintf("%s:%s", k, v))
		}
	}

	go executeScan(scanID, command, "ffuf")

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("FFuf fuzzing started for %s", *req.Target),
		Command: strings.Join(command, " "),
	})
}

// scanBackup handles backup file discovery requests
func scanBackup(c *gin.Context) {
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
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "backup", "scan", "-d", *req.Domain}

	if req.Threads != nil && *req.Threads > 0 {
		command = append(command, "-t", fmt.Sprintf("%d", *req.Threads))
	}

	go executeScan(scanID, command, "backup")

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("Backup file discovery started for %s", *req.Domain),
		Command: strings.Join(command, " "),
	})
}

// scanMisconfig handles cloud misconfiguration scan requests
func scanMisconfig(c *gin.Context) {
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
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "misconfig", "scan", *req.Domain}

	if req.ServiceID != nil && *req.ServiceID != "" {
		command = append(command, "--service", *req.ServiceID)
	}
	if req.Delay != nil && *req.Delay > 0 {
		command = append(command, "--delay", fmt.Sprintf("%d", *req.Delay))
	}
	if req.Permutations != nil && *req.Permutations {
		command = append(command, "--permutations")
	}

	go executeScan(scanID, command, "misconfig")

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("Misconfiguration scan started for %s", *req.Domain),
		Command: strings.Join(command, " "),
	})
}

// scanZerodays handles Zerodays scan requests
func scanZerodays(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if (req.Domain == nil || *req.Domain == "") && (req.DomainsFile == nil || *req.DomainsFile == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Either domain or domains_file is required"})
		return
	}

	if req.Domain != nil && req.DomainsFile != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot use both domain and domains_file together"})
		return
	}

	scanID := generateScanID()
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "zerodays", "scan"}

	if req.Domain != nil {
		command = append(command, "-d", *req.Domain)
	} else {
		command = append(command, "-f", *req.DomainsFile)
	}

	if req.Threads != nil && *req.Threads > 0 {
		command = append(command, "-t", fmt.Sprintf("%d", *req.Threads))
	}
	if req.DOSTest != nil && *req.DOSTest {
		command = append(command, "--dos-test")
	}
	if req.EnableSourceExposure != nil && *req.EnableSourceExposure {
		command = append(command, "--enable-source-exposure")
	}
	if req.CVEs != nil && len(*req.CVEs) > 0 {
		for _, cve := range *req.CVEs {
			command = append(command, "--cve", cve)
		}
	}
	if req.MongoDBHost != nil && *req.MongoDBHost != "" {
		command = append(command, "--mongodb-host", *req.MongoDBHost)
	}
	if req.MongoDBPort != nil && *req.MongoDBPort > 0 {
		command = append(command, "--mongodb-port", fmt.Sprintf("%d", *req.MongoDBPort))
	}
	if req.Silent != nil && *req.Silent {
		command = append(command, "--silent")
	}

	go executeScan(scanID, command, "zerodays")

	target := *req.Domain
	if req.DomainsFile != nil {
		target = *req.DomainsFile
	}

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: fmt.Sprintf("Zerodays scan started for %s", target),
		Command: strings.Join(command, " "),
	})
}

// scanJWT handles JWT vulnerability scan requests
func scanJWT(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Token == nil || *req.Token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "JWT token is required"})
		return
	}

	scanID := generateScanID()
	command := []string{getEnv("AUTOAR_SCRIPT_PATH", "/usr/local/bin/autoar"), "jwt", "scan", "-t", *req.Token}

	if req.SkipCrack != nil && *req.SkipCrack {
		command = append(command, "--skip-crack")
	}
	if req.SkipPayloads != nil && *req.SkipPayloads {
		command = append(command, "--skip-payloads")
	}
	if req.WordlistPath != nil && *req.WordlistPath != "" {
		command = append(command, "--wordlist", *req.WordlistPath)
	}
	if req.MaxCrackAttempts != nil && *req.MaxCrackAttempts > 0 {
		command = append(command, "--max-crack-attempts", fmt.Sprintf("%d", *req.MaxCrackAttempts))
	}

	go executeScan(scanID, command, "jwt")

	c.JSON(http.StatusOK, ScanResponse{
		ScanID:  scanID,
		Status:  "started",
		Message: "JWT vulnerability scan started",
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
			"r2_url":   publicURL,
			"file_size": fileInfo.Size(),
		})
		return
	}

	// Read file for direct Discord upload
	log.Printf("[API] [sendFileToDiscord] Reading file: %s", req.FilePath)
	fileData, err := os.ReadFile(req.FilePath)
	if err != nil {
		log.Printf("[API] [sendFileToDiscord] [ERROR] Failed to read file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to read file: %v", err)})
		return
	}
	log.Printf("[API] [sendFileToDiscord] Read %d bytes from file", len(fileData))

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

	// Send file to Discord channel/thread
	log.Printf("[API] [sendFileToDiscord] Sending file to Discord %s: %s (description: %s)", targetID, fileName, description)
	_, err = session.ChannelMessageSendComplex(targetID, &discordgo.MessageSend{
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
