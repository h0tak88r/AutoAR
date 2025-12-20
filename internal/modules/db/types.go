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

	// Close closes the database connection
	Close()
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

