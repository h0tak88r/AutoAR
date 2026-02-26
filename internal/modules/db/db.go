package db

import (
	"fmt"
	"log"
	"os"
	"strings"
)

var (
	dbInstance DB
)

// Init initializes the database connection based on DB_TYPE environment variable
func Init() error {
	dbType := getEnv("DB_TYPE", "postgresql")

	switch strings.ToLower(dbType) {
	case "postgresql", "postgres":
		pgDB := &PostgresDB{}
		if err := pgDB.Init(); err != nil {
			return err
		}
		dbInstance = pgDB
		if os.Getenv("AUTOAR_SILENT") != "true" {
			log.Printf("[INFO] Using PostgreSQL database")
		}
		return nil

	case "sqlite", "sqlite3":
		sqliteDB := &SQLiteDB{}
		if err := sqliteDB.Init(); err != nil {
			return err
		}
		dbInstance = sqliteDB
		if os.Getenv("AUTOAR_SILENT") != "true" {
			log.Printf("[INFO] Using SQLite database")
	}
		return nil

	default:
		return fmt.Errorf("unsupported database type: %s (supported: postgresql, sqlite)", dbType)
	}
}

// InitSchema initializes the database schema
func InitSchema() error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.InitSchema()
}

// InsertOrGetDomain inserts a domain or returns existing domain ID
func InsertOrGetDomain(domain string) (int, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return 0, err
		}
	}
	return dbInstance.InsertOrGetDomain(domain)
}

// BatchInsertSubdomains inserts multiple subdomains for a domain
func BatchInsertSubdomains(domain string, subdomains []string, isLive bool) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.BatchInsertSubdomains(domain, subdomains, isLive)
}

// InsertSubdomain inserts or updates a single subdomain
func InsertSubdomain(domain, subdomain string, isLive bool, httpURL, httpsURL string, httpStatus, httpsStatus int) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.InsertSubdomain(domain, subdomain, isLive, httpURL, httpsURL, httpStatus, httpsStatus)
}

// InsertJSFile inserts or updates a JS file for a subdomain
// It extracts the subdomain from the JS URL automatically
func InsertJSFile(domain, jsURL, contentHash string) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.InsertJSFile(domain, jsURL, contentHash)
}

// InsertKeyhackTemplate inserts or updates a KeyHack template
func InsertKeyhackTemplate(keyname, commandTemplate, method, url, header, body, notes, description string) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.InsertKeyhackTemplate(keyname, commandTemplate, method, url, header, body, notes, description)
}

// ListKeyhackTemplates returns all keyhack templates.
func ListKeyhackTemplates() ([]KeyhackTemplate, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}
	return dbInstance.ListKeyhackTemplates()
}

// SearchKeyhackTemplates searches keyhack templates by keyname or description.
func SearchKeyhackTemplates(query string) ([]KeyhackTemplate, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}
	return dbInstance.SearchKeyhackTemplates(query)
}

// ListDomains returns all distinct domains stored in the database.
func ListDomains() ([]string, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}
	return dbInstance.ListDomains()
}

// ListSubdomains returns all subdomains for a given domain.
func ListSubdomains(domain string) ([]string, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}
	return dbInstance.ListSubdomains(domain)
}

// ListSubdomainsWithStatus returns all subdomains with their status codes for a given domain.
func ListSubdomainsWithStatus(domain string) ([]SubdomainStatus, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}
	return dbInstance.ListSubdomainsWithStatus(domain)
}

// ListLiveSubdomains returns only live subdomains (is_live=true) with their URLs for a given domain.
func ListLiveSubdomains(domain string) ([]SubdomainStatus, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}
	return dbInstance.ListLiveSubdomains(domain)
}

// CountSubdomains returns the count of subdomains for a given domain.
func CountSubdomains(domain string) (int, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return 0, err
		}
	}
	return dbInstance.CountSubdomains(domain)
}

// DeleteDomain deletes a domain and all its related data using ON DELETE CASCADE.
func DeleteDomain(domain string) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.DeleteDomain(domain)
}

// ListMonitorTargets returns all monitoring targets
func ListMonitorTargets() ([]MonitorTarget, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}
	return dbInstance.ListMonitorTargets()
}

// AddMonitorTarget adds a new monitoring target
func AddMonitorTarget(url, strategy, pattern string) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.AddMonitorTarget(url, strategy, pattern)
}

// RemoveMonitorTarget removes a monitoring target by URL
func RemoveMonitorTarget(url string) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.RemoveMonitorTarget(url)
}

// SetMonitorRunningStatus updates the running status of a monitor target
func SetMonitorRunningStatus(id int, isRunning bool) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.SetMonitorRunningStatus(id, isRunning)
}

// GetMonitorTargetByID returns a single monitor target by ID.
func GetMonitorTargetByID(id int) (*MonitorTarget, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}
	return dbInstance.GetMonitorTargetByID(id)
}

// ListSubdomainMonitorTargets returns all subdomain monitoring targets
func ListSubdomainMonitorTargets() ([]SubdomainMonitorTarget, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}
	return dbInstance.ListSubdomainMonitorTargets()
}

// AddSubdomainMonitorTarget adds a new subdomain monitoring target
func AddSubdomainMonitorTarget(domain string, interval int, threads int, checkNew bool) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.AddSubdomainMonitorTarget(domain, interval, threads, checkNew)
}

// RemoveSubdomainMonitorTarget removes a subdomain monitoring target by domain
func RemoveSubdomainMonitorTarget(domain string) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.RemoveSubdomainMonitorTarget(domain)
}

// SetSubdomainMonitorRunningStatus updates the running status of a subdomain monitor target
func SetSubdomainMonitorRunningStatus(id int, isRunning bool) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.SetSubdomainMonitorRunningStatus(id, isRunning)
}

// GetSubdomainMonitorTargetByID returns a single subdomain monitor target by ID
func GetSubdomainMonitorTargetByID(id int) (*SubdomainMonitorTarget, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}
	return dbInstance.GetSubdomainMonitorTargetByID(id)
}

// CreateScan creates a new scan record
func CreateScan(scan *ScanRecord) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.CreateScan(scan)
}

// UpdateScanProgress updates scan progress
func UpdateScanProgress(scanID string, progress *ScanProgress) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.UpdateScanProgress(scanID, progress)
}

// UpdateScanStatus updates scan status
func UpdateScanStatus(scanID string, status string) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.UpdateScanStatus(scanID, status)
}

// GetScan retrieves a scan by ID
func GetScan(scanID string) (*ScanRecord, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}
	return dbInstance.GetScan(scanID)
}

// ListActiveScans lists all active scans
func ListActiveScans() ([]*ScanRecord, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}
	return dbInstance.ListActiveScans()
}

// ListRecentScans lists recent scans
func ListRecentScans(limit int) ([]*ScanRecord, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}
	return dbInstance.ListRecentScans(limit)
}

// DeleteScan deletes a scan record
func DeleteScan(scanID string) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.DeleteScan(scanID)
}

// Close closes the database connection pool
func Close() {
	if dbInstance != nil {
		dbInstance.Close()
	}
}

// ListVulnerableDNSProviders returns all vulnerable DNS providers from the database
func ListVulnerableDNSProviders() (map[string]string, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}
	return dbInstance.ListVulnerableDNSProviders()
}

// AddVulnerableDNSProvider adds or updates a vulnerable DNS provider
func AddVulnerableDNSProvider(name, fingerprint string) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.AddVulnerableDNSProvider(name, fingerprint)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
