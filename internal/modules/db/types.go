package db

import "time"

// DB is the interface that all database implementations must satisfy
type DB interface {
	// Init initializes the database connection
	Init() error

	// InitSchema initializes the database schema
	InitSchema() error

	// InsertOrGetDomain inserts a domain or returns existing domain ID
	InsertOrGetDomain(domain string) (int, error)

	// BatchInsertSubdomains inserts multiple subdomains for a domain
	BatchInsertSubdomains(domain string, subdomains []string, isLive bool) error

	// InsertSubdomain inserts or updates a single subdomain
	InsertSubdomain(domain, subdomain string, isLive bool, httpURL, httpsURL string, httpStatus, httpsStatus int) error

	// InsertJSFile inserts or updates a JS file for a subdomain
	InsertJSFile(domain, jsURL, contentHash string) error

	// InsertKeyhackTemplate inserts or updates a KeyHack template
	InsertKeyhackTemplate(keyname, commandTemplate, method, url, header, body, notes, description string) error

	// ListKeyhackTemplates returns all keyhack templates
	ListKeyhackTemplates() ([]KeyhackTemplate, error)

	// SearchKeyhackTemplates searches keyhack templates by keyname or description
	SearchKeyhackTemplates(query string) ([]KeyhackTemplate, error)

	// ListDomains returns all distinct domains stored in the database
	ListDomains() ([]string, error)

	// ListSubdomains returns all subdomains for a given domain
	ListSubdomains(domain string) ([]string, error)
	// ListSubdomainsWithStatus returns all subdomains with their status codes for a given domain
	ListSubdomainsWithStatus(domain string) ([]SubdomainStatus, error)
	// ListLiveSubdomains returns only live subdomains (is_live=true) with their URLs for a given domain
	ListLiveSubdomains(domain string) ([]SubdomainStatus, error)
	// CountSubdomains returns the count of subdomains for a given domain
	CountSubdomains(domain string) (int, error)

	// DeleteDomain deletes a domain and all its related data
	DeleteDomain(domain string) error

	// ListMonitorTargets returns all monitoring targets
	ListMonitorTargets() ([]MonitorTarget, error)

	// AddMonitorTarget adds a new monitoring target
	AddMonitorTarget(url, strategy, pattern string) error

	// RemoveMonitorTarget removes a monitoring target by URL
	RemoveMonitorTarget(url string) error

	// SetMonitorRunningStatus updates the running status of a monitor target
	SetMonitorRunningStatus(id int, isRunning bool) error

	// GetMonitorTargetByID returns a single monitor target by ID
	GetMonitorTargetByID(id int) (*MonitorTarget, error)

	// Subdomain monitoring targets
	// ListSubdomainMonitorTargets returns all subdomain monitoring targets
	ListSubdomainMonitorTargets() ([]SubdomainMonitorTarget, error)

	// AddSubdomainMonitorTarget adds a new subdomain monitoring target
	AddSubdomainMonitorTarget(domain string, interval int, threads int, checkNew bool) error

	// RemoveSubdomainMonitorTarget removes a subdomain monitoring target by domain
	RemoveSubdomainMonitorTarget(domain string) error

	// SetSubdomainMonitorRunningStatus updates the running status of a subdomain monitor target
	SetSubdomainMonitorRunningStatus(id int, isRunning bool) error

	// GetSubdomainMonitorTargetByID returns a single subdomain monitor target by ID
	GetSubdomainMonitorTargetByID(id int) (*SubdomainMonitorTarget, error)

	// UpdateSubdomainMonitorLastRun updates last_run_at to now for a subdomain monitor target
	UpdateSubdomainMonitorLastRun(id int) error

	// UpdateMonitorTargetLastRun updates last_hash and last_run_at for a URL monitor target
	UpdateMonitorTargetLastRun(id int, hash string, changed bool) error

	// InsertMonitorChange records a detected change in the monitor_changes table
	InsertMonitorChange(change *MonitorChange) error

	// ListMonitorChanges lists recent monitor changes, optionally filtered by domain
	ListMonitorChanges(domain string, limit int) ([]MonitorChange, error)

	// ClearMonitorChanges deletes all rows in monitor_changes and resets URL target change_count.
	ClearMonitorChanges() error

	// DNS Takeover Providers
	ListVulnerableDNSProviders() (map[string]string, error)
	AddVulnerableDNSProvider(name, fingerprint string) error

	// Scan tracking
	CreateScan(scan *ScanRecord) error
	UpdateScanProgress(scanID string, progress *ScanProgress) error
	UpdateScanStatus(scanID string, status string) error
	UpdateScanResult(scanID, status, resultURL string) error
	GetScan(scanID string) (*ScanRecord, error)
	ListActiveScans() ([]*ScanRecord, error)
	ListRecentScans(limit int) ([]*ScanRecord, error)
	AppendScanArtifact(artifact *ScanArtifact) error
	ListScanArtifacts(scanID string) ([]*ScanArtifact, error)
	// FailStaleActiveScans marks running/starting/paused/cancelling scans as failed (e.g. after API restart).
	FailStaleActiveScans() (int64, error)
	DeleteScan(scanID string) error
	// ListAllScanIDs returns every scan_id in the scans table (newest first).
	ListAllScanIDs() ([]string, error)
	// ListScanIDsForDomainRoot returns scan IDs whose target is the root domain or a host under it (sub.example.com for example.com).
	ListScanIDsForDomainRoot(domain string) ([]string, error)

	// Close closes the database connection
	Close()
}

// ScanRecord represents a scan stored in the database
type ScanRecord struct {
	ID              int        `json:"id"`
	ScanID          string     `json:"scan_id"`
	ScanType        string     `json:"scan_type"`
	Target          string     `json:"target"`
	Status          string     `json:"status"`
	ChannelID       string     `json:"channel_id,omitempty"`
	ThreadID        string     `json:"thread_id,omitempty"`
	MessageID       string     `json:"message_id,omitempty"`
	CurrentPhase    int        `json:"current_phase"`
	TotalPhases     int        `json:"total_phases"`
	PhaseName       string     `json:"phase_name,omitempty"`
	PhaseStartTime  *time.Time `json:"phase_start_time,omitempty"`
	CompletedPhases []string   `json:"completed_phases,omitempty"`
	FailedPhases    []string   `json:"failed_phases,omitempty"`
	FilesUploaded   int        `json:"files_uploaded"`
	ErrorCount      int        `json:"error_count"`
	StartedAt       time.Time  `json:"started_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	LastUpdate      time.Time  `json:"last_update"`
	Command         string     `json:"command,omitempty"`
	ResultURL       string     `json:"result_url,omitempty"`
}

// ScanArtifact represents an output artifact produced by a scan and stored in R2.
type ScanArtifact struct {
	ID          int       `json:"id"`
	ScanID      string    `json:"scan_id"`
	FileName    string    `json:"file_name"`
	LocalPath   string    `json:"local_path,omitempty"`
	R2Key       string    `json:"r2_key"`
	PublicURL   string    `json:"public_url"`
	SizeBytes   int64     `json:"size_bytes"`
	LineCount   int       `json:"line_count"`
	ContentType string    `json:"content_type,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// ScanProgress represents progress update for a scan
type ScanProgress struct {
	CurrentPhase    int
	TotalPhases     int
	PhaseName       string
	PhaseStartTime  time.Time
	CompletedPhases []string
	FailedPhases    []string
	FilesUploaded   int
	ErrorCount      int
}

// KeyhackTemplate represents a stored key validation template
type KeyhackTemplate struct {
	Keyname         string
	CommandTemplate string
	Method          string
	URL             string
	Header          string
	Body            string
	Notes           string
	Description     string
}

// MonitorTarget represents a URL/page monitoring target
type MonitorTarget struct {
	ID            int
	URL           string
	Strategy      string
	Pattern       string
	IsRunning     bool
	LastHash      string    // hash of last fetched content (for change detection)
	LastRunAt     *time.Time // when this target was last actually checked
	ChangeCount   int       // total number of changes detected
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// SubdomainMonitorTarget represents a subdomain monitoring target
type SubdomainMonitorTarget struct {
	ID        int
	Domain    string
	Interval  int        // Check interval in seconds
	Threads   int        // Threads for httpx
	CheckNew  bool       // Check for new subdomains
	IsRunning bool
	LastRunAt *time.Time // when this target was last actually checked (NOT the same as UpdatedAt)
	CreatedAt time.Time
	UpdatedAt time.Time
}

// MonitorChange records a detected change for history/querying
type MonitorChange struct {
	ID          int
	TargetType  string    // "subdomain" | "url"
	TargetID    int       // FK to subdomain_monitor_targets or updates_targets
	Domain      string    // domain or URL being monitored
	ChangeType  string    // "new_subdomain", "became_live", "became_dead", "status_changed", "content_changed"
	Detail      string    // JSON blob with old/new values
	DetectedAt  time.Time
	Notified    bool      // whether a Discord alert was sent
}

// SubdomainStatus represents a subdomain with its status information
type SubdomainStatus struct {
	Subdomain   string
	HTTPURL     string
	HTTPSURL    string
	HTTPStatus  int
	HTTPSStatus int
	IsLive      bool
}

