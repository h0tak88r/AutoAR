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

	// Scan tracking
	CreateScan(scan *ScanRecord) error
	UpdateScanProgress(scanID string, progress *ScanProgress) error
	UpdateScanStatus(scanID string, status string) error
	GetScan(scanID string) (*ScanRecord, error)
	ListActiveScans() ([]*ScanRecord, error)
	ListRecentScans(limit int) ([]*ScanRecord, error)
	DeleteScan(scanID string) error

	// Close closes the database connection
	Close()
}

// ScanRecord represents a scan stored in the database
type ScanRecord struct {
	ID              int
	ScanID          string
	ScanType        string
	Target          string
	Status          string
	ChannelID       string
	ThreadID        string
	MessageID       string
	CurrentPhase    int
	TotalPhases     int
	PhaseName       string
	PhaseStartTime  *time.Time
	CompletedPhases []string
	FailedPhases    []string
	FilesUploaded   int
	ErrorCount      int
	StartedAt       time.Time
	CompletedAt     *time.Time
	LastUpdate      time.Time
	Command         string
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

// MonitorTarget represents a monitoring target
type MonitorTarget struct {
	ID        int
	URL       string
	Strategy  string
	Pattern   string
	IsRunning bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SubdomainMonitorTarget represents a subdomain monitoring target
type SubdomainMonitorTarget struct {
	ID        int
	Domain    string
	Interval  int // Check interval in seconds
	Threads   int // Threads for httpx
	CheckNew  bool // Check for new subdomains
	IsRunning bool
	CreatedAt time.Time
	UpdatedAt time.Time
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

