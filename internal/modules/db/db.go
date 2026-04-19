package db

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
)

var (
	dbInstance DB
	schemaOnce sync.Once
	schemaErr  error
)

// EnsureSchema runs InitSchema at most once per process (avoids repeated migrations/logs on every API call).
func EnsureSchema() error {
	schemaOnce.Do(func() {
		schemaErr = InitSchema()
	})
	return schemaErr
}

// Init initializes the database connection based on DB_TYPE environment variable
func Init() error {
	// Reuse a single pool / connection — calling Init() on every HTTP handler must not
	// allocate new pools (Supabase and other hosts enforce max connections).
	if dbInstance != nil {
		return nil
	}

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

// ListAllSubdomainsPaginated returns a paginated global list of subdomains matching a search.
func ListAllSubdomainsPaginated(search, techFilter, cnameFilter string, statusFilter, limit, offset int) ([]GlobalSubdomain, int, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return nil, 0, err
		}
	}
	return dbInstance.ListAllSubdomainsPaginated(search, techFilter, cnameFilter, statusFilter, limit, offset)
}

// UpdateSubdomainTech updates the technology stack string for a resolved subdomain
func UpdateSubdomainTech(domain, subdomain, techs string) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.UpdateSubdomainTech(domain, subdomain, techs)
}

// UpdateSubdomainFull updates multiple recon fields for a subdomain at once
func UpdateSubdomainFull(domain, subdomain string, techs, title string, statusCode int, isLive bool) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.UpdateSubdomainFull(domain, subdomain, techs, title, statusCode, isLive)
}

// UpdateSubdomainCNAME updates the mapped CNAME record for a subdomain
func UpdateSubdomainCNAME(domain, subdomain, cnames string) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.UpdateSubdomainCNAME(domain, subdomain, cnames)
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

// DeleteDomain deletes a domain row (cascades subdomains, js_files), related scans + artifacts,
// monitor history under that root, and the subdomain monitor target row when present.
func DeleteDomain(domain string) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.DeleteDomain(domain)
}

// ListAllScanIDs returns all scan IDs (newest first).
func ListAllScanIDs() ([]string, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}
	return dbInstance.ListAllScanIDs()
}

// ListScanIDsForDomainRoot lists scans for a root domain and its subdomains.
func ListScanIDsForDomainRoot(domain string) ([]string, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}
	return dbInstance.ListScanIDsForDomainRoot(domain)
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

// UpdateSubdomainMonitorLastRun updates last_run_at for a subdomain monitor target (fixes timer bug)
func UpdateSubdomainMonitorLastRun(id int) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.UpdateSubdomainMonitorLastRun(id)
}

// UpdateMonitorTargetLastRun updates last_hash and last_run_at for a URL monitor target
func UpdateMonitorTargetLastRun(id int, hash string, changed bool) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.UpdateMonitorTargetLastRun(id, hash, changed)
}

// InsertMonitorChange records a detected change in the monitor_changes table
func InsertMonitorChange(change *MonitorChange) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.InsertMonitorChange(change)
}

// ListMonitorChanges lists recent monitor changes, optionally filtered by domain
func ListMonitorChanges(domain string, limit int) ([]MonitorChange, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}
	return dbInstance.ListMonitorChanges(domain, limit)
}

// ClearMonitorChanges deletes monitor change history and resets per-URL change counters.
func ClearMonitorChanges() error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.ClearMonitorChanges()
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

// AppendScanPhase atomically appends a phase name to completed_phases or failed_phases.
func AppendScanPhase(scanID, phaseName string, failed bool) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.AppendScanPhase(scanID, phaseName, failed)
}

// IsPhaseCompleted checks if a specific phase was already successfully completed for a scan.
func IsPhaseCompleted(scanID, phaseName string) bool {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return false
		}
	}
	return dbInstance.IsPhaseCompleted(scanID, phaseName)
}

// UpdateScanResult updates scan status and result URL
func UpdateScanResult(scanID, status, resultURL string) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.UpdateScanResult(scanID, status, resultURL)
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

// FailStaleActiveScans marks in-progress DB scans as failed (no worker after restart).
func FailStaleActiveScans() (int64, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return 0, err
		}
	}
	return dbInstance.FailStaleActiveScans()
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

// AppendScanArtifact stores an artifact generated by a scan.
func AppendScanArtifact(artifact *ScanArtifact) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	return dbInstance.AppendScanArtifact(artifact)
}

// ListScanArtifacts returns artifacts for a scan ordered by newest first.
func ListScanArtifacts(scanID string) ([]*ScanArtifact, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}
	return dbInstance.ListScanArtifacts(scanID)
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

// CountScansWithTargetExcluding counts scans sharing a target except the given scan_id.
func CountScansWithTargetExcluding(excludeScanID, target string) (int, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return 0, err
		}
	}
	return dbInstance.CountScansWithTargetExcluding(excludeScanID, target)
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
