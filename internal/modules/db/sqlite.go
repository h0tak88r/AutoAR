package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteDB implements the DB interface for SQLite
type SQLiteDB struct {
	db *sql.DB
}

// Init initializes the SQLite database connection
func (s *SQLiteDB) Init() error {
	dbPath := getEnv("DB_HOST", "./bughunt.db")
	
	// Expand user home directory if path starts with ~
	if strings.HasPrefix(dbPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %v", err)
		}
		dbPath = filepath.Join(home, dbPath[2:])
	}

	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create database directory: %v", err)
		}
	}

	// Open database connection
	db, err := sql.Open("sqlite", dbPath+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)")
	if err != nil {
		return fmt.Errorf("failed to open SQLite database: %v", err)
	}

	// Configure connection pool settings for SQLite
	// With WAL mode enabled, we can support multiple readers and one writer
	// modernc.org/sqlite supports concurrency well in WAL mode
	db.SetMaxOpenConns(25)              // Allow multiple concurrent connections
	db.SetMaxIdleConns(25)              // Keep up to 25 idle connections
	db.SetConnMaxLifetime(time.Hour)   // Close connections after 1 hour
	db.SetConnMaxIdleTime(time.Minute * 30) // Close idle connections after 30 minutes

	// Test connection
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}

	s.db = db
	if os.Getenv("AUTOAR_SILENT") != "true" {
		log.Printf("[INFO] Connected to SQLite database at %s", dbPath)
	}
	return nil
}

// InitSchema initializes the database schema for SQLite
func (s *SQLiteDB) InitSchema() error {
	if s.db == nil {
		if err := s.Init(); err != nil {
			return err
		}
	}

	schema := `
	-- Create domains table
	CREATE TABLE IF NOT EXISTS domains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT (datetime('now')),
		updated_at TIMESTAMP DEFAULT (datetime('now'))
	);
	
	-- Create unique index on domain
	CREATE UNIQUE INDEX IF NOT EXISTS domains_domain_key ON domains (domain);
	
	-- Create subdomains table
	CREATE TABLE IF NOT EXISTS subdomains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
		subdomain TEXT NOT NULL,
		is_live INTEGER DEFAULT 0,
		http_url TEXT,
		https_url TEXT,
		http_status INTEGER,
		https_status INTEGER,
		created_at TIMESTAMP DEFAULT (datetime('now')),
		updated_at TIMESTAMP DEFAULT (datetime('now'))
	);
	
	-- Create unique index on subdomain
	CREATE UNIQUE INDEX IF NOT EXISTS subdomains_subdomain_key ON subdomains (subdomain);
	
	-- Create js_files table
	CREATE TABLE IF NOT EXISTS js_files (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		subdomain_id INTEGER REFERENCES subdomains(id) ON DELETE CASCADE,
		js_url TEXT NOT NULL,
		content_hash TEXT,
		last_scanned TIMESTAMP,
		created_at TIMESTAMP DEFAULT (datetime('now')),
		updated_at TIMESTAMP DEFAULT (datetime('now'))
	);
	
	-- Create unique index on js_url
	CREATE UNIQUE INDEX IF NOT EXISTS js_files_js_url_key ON js_files (js_url);
	
	-- Create keyhack_templates table
	CREATE TABLE IF NOT EXISTS keyhack_templates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		keyname TEXT NOT NULL,
		command_template TEXT NOT NULL,
		method TEXT DEFAULT 'GET',
		url TEXT NOT NULL,
		header TEXT,
		body TEXT,
		description TEXT,
		notes TEXT,
		created_at TIMESTAMP DEFAULT (datetime('now')),
		updated_at TIMESTAMP DEFAULT (datetime('now'))
	);
	
	-- Create unique index on keyname
	CREATE UNIQUE INDEX IF NOT EXISTS keyhack_templates_keyname_key ON keyhack_templates (keyname);
	
	-- Create updates_targets table for monitoring
	CREATE TABLE IF NOT EXISTS updates_targets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		url TEXT NOT NULL UNIQUE,
		strategy TEXT NOT NULL,
		pattern TEXT,
		is_running INTEGER DEFAULT 0,
		created_at TIMESTAMP DEFAULT (datetime('now')),
		updated_at TIMESTAMP DEFAULT (datetime('now'))
	);
	
	-- Create subdomain_monitor_targets table for subdomain monitoring
	CREATE TABLE IF NOT EXISTS subdomain_monitor_targets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL UNIQUE,
		interval_seconds INTEGER DEFAULT 3600,
		threads INTEGER DEFAULT 100,
		check_new INTEGER DEFAULT 1,
		is_running INTEGER DEFAULT 0,
		created_at TIMESTAMP DEFAULT (datetime('now')),
		updated_at TIMESTAMP DEFAULT (datetime('now'))
	);
	
	-- Create scans table for scan progress tracking
	CREATE TABLE IF NOT EXISTS scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL UNIQUE,
		scan_type TEXT NOT NULL,
		target TEXT NOT NULL,
		status TEXT NOT NULL,
		channel_id TEXT,
		thread_id TEXT,
		message_id TEXT,
		current_phase INTEGER DEFAULT 0,
		total_phases INTEGER DEFAULT 0,
		phase_name TEXT,
		phase_start_time TIMESTAMP,
		completed_phases TEXT,
		failed_phases TEXT,
		files_uploaded INTEGER DEFAULT 0,
		error_count INTEGER DEFAULT 0,
		started_at TIMESTAMP NOT NULL,
		completed_at TIMESTAMP,
		last_update TIMESTAMP NOT NULL,
		command TEXT,
		created_at TIMESTAMP DEFAULT (datetime('now')),
		updated_at TIMESTAMP DEFAULT (datetime('now'))
	);
	
	-- Create dns_takeover_providers table
	CREATE TABLE IF NOT EXISTS dns_takeover_providers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		fingerprint TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT (datetime('now')),
		updated_at TIMESTAMP DEFAULT (datetime('now'))
	);
	
	-- Create indexes
	CREATE INDEX IF NOT EXISTS idx_subdomains_domain_id ON subdomains(domain_id);
	CREATE INDEX IF NOT EXISTS idx_subdomains_is_live ON subdomains(is_live);
	CREATE INDEX IF NOT EXISTS idx_js_files_subdomain_id ON js_files(subdomain_id);
	CREATE INDEX IF NOT EXISTS idx_keyhack_templates_keyname ON keyhack_templates(keyname);
	CREATE INDEX IF NOT EXISTS idx_updates_targets_url ON updates_targets(url);
	CREATE INDEX IF NOT EXISTS idx_subdomain_monitor_targets_domain ON subdomain_monitor_targets(domain);
	CREATE INDEX IF NOT EXISTS idx_subdomain_monitor_targets_is_running ON subdomain_monitor_targets(is_running);
	CREATE INDEX IF NOT EXISTS idx_scans_scan_id ON scans(scan_id);
	CREATE INDEX IF NOT EXISTS scans_channel_id_idx ON scans (channel_id);
	CREATE INDEX IF NOT EXISTS scans_status_idx ON scans (status);
	CREATE INDEX IF NOT EXISTS scans_started_at_idx ON scans (started_at);
	
	-- Create APK cache table for file-based scans
	CREATE TABLE IF NOT EXISTS apk_cache (
		hash TEXT PRIMARY KEY,
		data TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT (datetime('now'))
	);
	
	CREATE INDEX IF NOT EXISTS apk_cache_created_at_idx ON apk_cache (created_at);
	`

	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create schema: %v", err)
	}
	if os.Getenv("AUTOAR_SILENT") != "true" {
		log.Printf("[OK] Database schema initialized")
	}
	return nil
}

// InsertOrGetDomain inserts a domain or returns existing domain ID
func (s *SQLiteDB) InsertOrGetDomain(domain string) (int, error) {
	// First, try to get existing domain
	var domainID int
	err := s.db.QueryRow(`SELECT id FROM domains WHERE domain = ? LIMIT 1;`, domain).Scan(&domainID)

	if err == nil {
		// Domain exists, return its ID
		return domainID, nil
	}

	if err != sql.ErrNoRows {
		// Unexpected error
		return 0, fmt.Errorf("failed to query domain: %v", err)
	}

	// Domain doesn't exist, insert it
	result, err := s.db.Exec(`INSERT INTO domains (domain) VALUES (?);`, domain)
	if err != nil {
		// If insert failed due to race condition (unique constraint), try to get it again
		// Check if it's a unique constraint error
		errStr := err.Error()
		if strings.Contains(errStr, "UNIQUE constraint") || strings.Contains(errStr, "constraint") {
			// Another process inserted it, try to get it
			err = s.db.QueryRow(`SELECT id FROM domains WHERE domain = ? LIMIT 1;`, domain).Scan(&domainID)
			if err != nil {
				return 0, fmt.Errorf("failed to insert/get domain (insert failed: %v, query also failed: %v)", errStr, err)
			}
			return domainID, nil
		}
		// Other error, return it
		return 0, fmt.Errorf("failed to insert domain: %v", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get last insert id: %v", err)
	}
	return int(id), nil
}

// BatchInsertSubdomains inserts multiple subdomains for a domain
func (s *SQLiteDB) BatchInsertSubdomains(domain string, subdomains []string, isLive bool) error {
	domainID, err := s.InsertOrGetDomain(domain)
	if err != nil {
		return fmt.Errorf("failed to get domain ID: %v", err)
	}

	log.Printf("[INFO] Batch inserting %d subdomains for %s (domain_id: %d)", len(subdomains), domain, domainID)

	// Use transaction for better performance
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO subdomains (domain_id, subdomain, is_live, http_url, https_url, http_status, https_status, updated_at)
		VALUES (?, ?, ?, '', '', 0, 0, ?)
		ON CONFLICT (subdomain) DO UPDATE SET 
			updated_at = ?,
			domain_id = excluded.domain_id;
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %v", err)
	}
	defer stmt.Close()

	count := 0
	now := time.Now()
	for _, subdomain := range subdomains {
		subdomain = strings.TrimSpace(subdomain)
		if subdomain == "" {
			continue
		}

		_, err := stmt.Exec(domainID, subdomain, isLive, now, now)
		if err != nil {
			log.Printf("[WARN] Failed to insert subdomain %s: %v", subdomain, err)
			continue
		}
		count++
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	log.Printf("[OK] Inserted %d subdomains for %s", count, domain)
	return nil
}

// InsertSubdomain inserts or updates a single subdomain
func (s *SQLiteDB) InsertSubdomain(domain, subdomain string, isLive bool, httpURL, httpsURL string, httpStatus, httpsStatus int) error {
	domainID, err := s.InsertOrGetDomain(domain)
	if err != nil {
		return fmt.Errorf("failed to get domain ID: %v", err)
	}

	// Check if subdomain already exists
	var existingID int
	err = s.db.QueryRow(`
		SELECT id FROM subdomains WHERE domain_id = ? AND subdomain = ? LIMIT 1;
	`, domainID, subdomain).Scan(&existingID)

	if err == sql.ErrNoRows {
		// Insert new subdomain
		_, err = s.db.Exec(`
			INSERT INTO subdomains (domain_id, subdomain, is_live, http_url, https_url, http_status, https_status)
			VALUES (?, ?, ?, ?, ?, ?, ?);
		`, domainID, subdomain, isLive, httpURL, httpsURL, httpStatus, httpsStatus)
	} else if err == nil {
		// Update existing subdomain
		_, err = s.db.Exec(`
			UPDATE subdomains SET
				is_live = ?,
				http_url = ?,
				https_url = ?,
				http_status = ?,
				https_status = ?,
				updated_at = datetime('now')
			WHERE id = ?;
		`, isLive, httpURL, httpsURL, httpStatus, httpsStatus, existingID)
	}

	if err != nil {
		return fmt.Errorf("failed to insert/update subdomain: %v", err)
	}

	return nil
}

// InsertJSFile inserts or updates a JS file for a subdomain
// It extracts the subdomain from the JS URL automatically
func (s *SQLiteDB) InsertJSFile(domain, jsURL, contentHash string) error {
	// Extract subdomain from URL (e.g., https://sub.example.com/path.js -> sub.example.com)
	subdomain := jsURL
	if strings.HasPrefix(jsURL, "http://") {
		subdomain = strings.TrimPrefix(jsURL, "http://")
	} else if strings.HasPrefix(jsURL, "https://") {
		subdomain = strings.TrimPrefix(jsURL, "https://")
	}
	// Get just the hostname part
	if idx := strings.Index(subdomain, "/"); idx != -1 {
		subdomain = subdomain[:idx]
	}

	domainID, err := s.InsertOrGetDomain(domain)
	if err != nil {
		return fmt.Errorf("failed to get domain ID: %v", err)
	}

	// Get or create subdomain
	var subdomainID int
	err = s.db.QueryRow(`
		SELECT id FROM subdomains WHERE domain_id = ? AND subdomain = ? LIMIT 1;
	`, domainID, subdomain).Scan(&subdomainID)

	if err == sql.ErrNoRows {
		// Create subdomain first
		result, err := s.db.Exec(`
			INSERT INTO subdomains (domain_id, subdomain, is_live, http_url, https_url, http_status, https_status)
			VALUES (?, ?, 0, '', '', 0, 0);
		`, domainID, subdomain)
		if err != nil {
			return fmt.Errorf("failed to create subdomain: %v", err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			return fmt.Errorf("failed to get last insert id: %v", err)
		}
		subdomainID = int(id)
	} else if err != nil {
		return fmt.Errorf("failed to get/create subdomain: %v", err)
	}

	// Insert or update JS file
	_, err = s.db.Exec(`
		INSERT INTO js_files (subdomain_id, js_url, content_hash, last_scanned)
		VALUES (?, ?, ?, datetime('now'))
		ON CONFLICT (js_url) DO UPDATE SET
			content_hash = excluded.content_hash,
			last_scanned = datetime('now'),
			updated_at = datetime('now');
	`, subdomainID, jsURL, contentHash)

	if err != nil {
		return fmt.Errorf("failed to insert/update JS file: %v", err)
	}

	return nil
}

// InsertKeyhackTemplate inserts or updates a KeyHack template
func (s *SQLiteDB) InsertKeyhackTemplate(keyname, commandTemplate, method, url, header, body, notes, description string) error {
	_, err := s.db.Exec(`
		INSERT INTO keyhack_templates (keyname, command_template, method, url, header, body, description, notes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (keyname) DO UPDATE SET
			command_template = excluded.command_template,
			method = excluded.method,
			url = excluded.url,
			header = excluded.header,
			body = excluded.body,
			description = excluded.description,
			notes = excluded.notes,
			updated_at = datetime('now');
	`, keyname, commandTemplate, method, url, header, body, description, notes)

	if err != nil {
		return fmt.Errorf("failed to insert/update keyhack template: %v", err)
	}

	return nil
}

// ListKeyhackTemplates returns all keyhack templates.
func (s *SQLiteDB) ListKeyhackTemplates() ([]KeyhackTemplate, error) {
	rows, err := s.db.Query(`
		SELECT 
			keyname, 
			command_template, 
			COALESCE(method, 'GET') as method, 
			COALESCE(url, '') as url, 
			COALESCE(header, '') as header, 
			COALESCE(body, '') as body, 
			COALESCE(notes, '') as notes, 
			COALESCE(description, '') as description
		FROM keyhack_templates
		ORDER BY keyname;
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query keyhack templates: %v", err)
	}
	defer rows.Close()

	var out []KeyhackTemplate
	for rows.Next() {
		var t KeyhackTemplate
		if err := rows.Scan(&t.Keyname, &t.CommandTemplate, &t.Method, &t.URL, &t.Header, &t.Body, &t.Notes, &t.Description); err != nil {
			return nil, fmt.Errorf("failed to scan keyhack template: %v", err)
		}
		out = append(out, t)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate keyhack templates: %v", rows.Err())
	}
	return out, nil
}

// SearchKeyhackTemplates searches keyhack templates by keyname or description.
func (s *SQLiteDB) SearchKeyhackTemplates(query string) ([]KeyhackTemplate, error) {
	q := "%" + query + "%"
	rows, err := s.db.Query(`
		SELECT 
			keyname, 
			command_template, 
			COALESCE(method, 'GET') as method, 
			COALESCE(url, '') as url, 
			COALESCE(header, '') as header, 
			COALESCE(body, '') as body, 
			COALESCE(notes, '') as notes, 
			COALESCE(description, '') as description
		FROM keyhack_templates
		WHERE LOWER(keyname) LIKE LOWER(?) OR LOWER(description) LIKE LOWER(?)
		ORDER BY keyname;
	`, q, q)
	if err != nil {
		return nil, fmt.Errorf("failed to search keyhack templates: %v", err)
	}
	defer rows.Close()

	var out []KeyhackTemplate
	for rows.Next() {
		var t KeyhackTemplate
		if err := rows.Scan(&t.Keyname, &t.CommandTemplate, &t.Method, &t.URL, &t.Header, &t.Body, &t.Notes, &t.Description); err != nil {
			return nil, fmt.Errorf("failed to scan keyhack template: %v", err)
		}
		out = append(out, t)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate keyhack templates: %v", rows.Err())
	}
	return out, nil
}

// ListDomains returns all distinct domains stored in the database.
func (s *SQLiteDB) ListDomains() ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT domain FROM domains ORDER BY domain;`)
	if err != nil {
		return nil, fmt.Errorf("failed to query domains: %v", err)
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, fmt.Errorf("failed to scan domain: %v", err)
		}
		domains = append(domains, d)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate domains: %v", rows.Err())
	}
	return domains, nil
}

// ListSubdomains returns all subdomains for a given domain.
func (s *SQLiteDB) ListSubdomains(domain string) ([]string, error) {
	rows, err := s.db.Query(`
		SELECT s.subdomain
		FROM subdomains s
		JOIN domains d ON s.domain_id = d.id
		WHERE d.domain = ?
		ORDER BY s.subdomain;
	`, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to query subdomains: %v", err)
	}
	defer rows.Close()

	var subs []string
	for rows.Next() {
		var sub string
		if err := rows.Scan(&sub); err != nil {
			return nil, fmt.Errorf("failed to scan subdomain: %v", err)
		}
		subs = append(subs, sub)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate subdomains: %v", rows.Err())
	}
	return subs, nil
}

// ListSubdomainsWithStatus returns all subdomains with their status codes for a given domain.
func (s *SQLiteDB) ListSubdomainsWithStatus(domain string) ([]SubdomainStatus, error) {
	rows, err := s.db.Query(`
		SELECT s.subdomain, 
		       COALESCE(s.http_url, ''), 
		       COALESCE(s.https_url, ''), 
		       COALESCE(s.http_status, 0), 
		       COALESCE(s.https_status, 0),
		       COALESCE(s.is_live, 0)
		FROM subdomains s
		JOIN domains d ON s.domain_id = d.id
		WHERE d.domain = ?
		ORDER BY s.subdomain;
	`, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to query subdomains with status: %v", err)
	}
	defer rows.Close()

	var subs []SubdomainStatus
	for rows.Next() {
		var s SubdomainStatus
		var isLiveInt int
		if err := rows.Scan(&s.Subdomain, &s.HTTPURL, &s.HTTPSURL, &s.HTTPStatus, &s.HTTPSStatus, &isLiveInt); err != nil {
			return nil, fmt.Errorf("failed to scan subdomain status: %v", err)
		}
		s.IsLive = isLiveInt != 0
		subs = append(subs, s)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate subdomains: %v", rows.Err())
	}
	return subs, nil
}

// ListLiveSubdomains returns only live subdomains (is_live=true) with their URLs for a given domain.
func (s *SQLiteDB) ListLiveSubdomains(domain string) ([]SubdomainStatus, error) {
	rows, err := s.db.Query(`
		SELECT s.subdomain, 
		       COALESCE(s.http_url, ''), 
		       COALESCE(s.https_url, ''), 
		       COALESCE(s.http_status, 0), 
		       COALESCE(s.https_status, 0),
		       COALESCE(s.is_live, 0)
		FROM subdomains s
		JOIN domains d ON s.domain_id = d.id
		WHERE d.domain = ? AND s.is_live = 1
		ORDER BY s.subdomain;
	`, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to query live subdomains: %v", err)
	}
	defer rows.Close()

	var subs []SubdomainStatus
	for rows.Next() {
		var s SubdomainStatus
		var isLiveInt int
		if err := rows.Scan(&s.Subdomain, &s.HTTPURL, &s.HTTPSURL, &s.HTTPStatus, &s.HTTPSStatus, &isLiveInt); err != nil {
			return nil, fmt.Errorf("failed to scan live subdomain status: %v", err)
		}
		s.IsLive = isLiveInt != 0
		subs = append(subs, s)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate live subdomains: %v", rows.Err())
	}
	return subs, nil
}

// CountSubdomains returns the count of subdomains for a given domain.
func (s *SQLiteDB) CountSubdomains(domain string) (int, error) {
	var count int
	err := s.db.QueryRow(`
		SELECT COUNT(s.id)
		FROM subdomains s
		JOIN domains d ON s.domain_id = d.id
		WHERE d.domain = ?;
	`, domain).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count subdomains: %v", err)
	}
	return count, nil
}

// DeleteDomain deletes a domain and all its related data using ON DELETE CASCADE.
func (s *SQLiteDB) DeleteDomain(domain string) error {
	result, err := s.db.Exec(`DELETE FROM domains WHERE domain = ?;`, domain)
	if err != nil {
		return fmt.Errorf("failed to delete domain %s: %v", domain, err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %v", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("domain not found: %s", domain)
	}
	return nil
}

// ListMonitorTargets returns all monitoring targets
func (s *SQLiteDB) ListMonitorTargets() ([]MonitorTarget, error) {
	rows, err := s.db.Query(`
		SELECT id, url, strategy, COALESCE(pattern, '') as pattern, is_running, created_at, updated_at
		FROM updates_targets
		ORDER BY created_at DESC;
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query monitor targets: %v", err)
	}
	defer rows.Close()

	var targets []MonitorTarget
	for rows.Next() {
		var t MonitorTarget
		var isRunning int
		if err := rows.Scan(&t.ID, &t.URL, &t.Strategy, &t.Pattern, &isRunning, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan monitor target: %v", err)
		}
		t.IsRunning = isRunning != 0
		targets = append(targets, t)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate monitor targets: %v", rows.Err())
	}
	return targets, nil
}

// AddMonitorTarget adds a new monitoring target
func (s *SQLiteDB) AddMonitorTarget(url, strategy, pattern string) error {
	_, err := s.db.Exec(`
		INSERT INTO updates_targets (url, strategy, pattern)
		VALUES (?, ?, ?)
		ON CONFLICT (url) DO UPDATE SET
			strategy = excluded.strategy,
			pattern = excluded.pattern,
			updated_at = datetime('now');
	`, url, strategy, pattern)

	if err != nil {
		return fmt.Errorf("failed to add monitor target: %v", err)
	}
	return nil
}

// RemoveMonitorTarget removes a monitoring target by URL
func (s *SQLiteDB) RemoveMonitorTarget(url string) error {
	result, err := s.db.Exec(`DELETE FROM updates_targets WHERE url = ?;`, url)
	if err != nil {
		return fmt.Errorf("failed to remove monitor target: %v", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %v", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("monitor target not found: %s", url)
	}
	return nil
}

// SetMonitorRunningStatus updates the running status of a monitor target
func (s *SQLiteDB) SetMonitorRunningStatus(id int, isRunning bool) error {
	isRunningInt := 0
	if isRunning {
		isRunningInt = 1
	}
	_, err := s.db.Exec(`
		UPDATE updates_targets 
		SET is_running = ?, updated_at = datetime('now')
		WHERE id = ?;
	`, isRunningInt, id)
	if err != nil {
		return fmt.Errorf("failed to update monitor running status: %v", err)
	}
	return nil
}

// GetMonitorTargetByID returns a single monitor target by ID.
func (s *SQLiteDB) GetMonitorTargetByID(id int) (*MonitorTarget, error) {
	var t MonitorTarget
	var isRunning int
	err := s.db.QueryRow(`
		SELECT id, url, strategy, COALESCE(pattern, '') as pattern, is_running, created_at, updated_at
		FROM updates_targets
		WHERE id = ?;
	`, id).Scan(&t.ID, &t.URL, &t.Strategy, &t.Pattern, &isRunning, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("monitor target not found with id: %d", id)
		}
		return nil, fmt.Errorf("failed to get monitor target by id: %v", err)
	}
	t.IsRunning = isRunning != 0
	return &t, nil
}

// ListSubdomainMonitorTargets returns all subdomain monitoring targets
func (s *SQLiteDB) ListSubdomainMonitorTargets() ([]SubdomainMonitorTarget, error) {
	rows, err := s.db.Query(`
		SELECT id, domain, interval_seconds, threads, check_new, is_running, created_at, updated_at
		FROM subdomain_monitor_targets
		ORDER BY domain;
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query subdomain monitor targets: %v", err)
	}
	defer rows.Close()

	var targets []SubdomainMonitorTarget
	for rows.Next() {
		var t SubdomainMonitorTarget
		var checkNewInt, isRunningInt int
		if err := rows.Scan(&t.ID, &t.Domain, &t.Interval, &t.Threads, &checkNewInt, &isRunningInt, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan subdomain monitor target: %v", err)
		}
		t.CheckNew = checkNewInt != 0
		t.IsRunning = isRunningInt != 0
		targets = append(targets, t)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate subdomain monitor targets: %v", rows.Err())
	}
	return targets, nil
}

// AddSubdomainMonitorTarget adds a new subdomain monitoring target
func (s *SQLiteDB) AddSubdomainMonitorTarget(domain string, interval int, threads int, checkNew bool) error {
	if interval <= 0 {
		interval = 3600 // Default 1 hour
	}
	if threads <= 0 {
		threads = 100
	}
	checkNewInt := 0
	if checkNew {
		checkNewInt = 1
	}
	_, err := s.db.Exec(`
		INSERT INTO subdomain_monitor_targets (domain, interval_seconds, threads, check_new)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (domain) DO UPDATE SET
			interval_seconds = excluded.interval_seconds,
			threads = excluded.threads,
			check_new = excluded.check_new,
			updated_at = datetime('now');
	`, domain, interval, threads, checkNewInt)

	if err != nil {
		return fmt.Errorf("failed to add subdomain monitor target: %v", err)
	}
	return nil
}

// RemoveSubdomainMonitorTarget removes a subdomain monitoring target by domain
func (s *SQLiteDB) RemoveSubdomainMonitorTarget(domain string) error {
	result, err := s.db.Exec(`DELETE FROM subdomain_monitor_targets WHERE domain = ?;`, domain)
	if err != nil {
		return fmt.Errorf("failed to remove subdomain monitor target: %v", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %v", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("subdomain monitor target not found: %s", domain)
	}
	return nil
}

// SetSubdomainMonitorRunningStatus updates the running status of a subdomain monitor target
func (s *SQLiteDB) SetSubdomainMonitorRunningStatus(id int, isRunning bool) error {
	isRunningInt := 0
	if isRunning {
		isRunningInt = 1
	}
	_, err := s.db.Exec(`
		UPDATE subdomain_monitor_targets 
		SET is_running = ?, updated_at = datetime('now')
		WHERE id = ?;
	`, isRunningInt, id)
	if err != nil {
		return fmt.Errorf("failed to update subdomain monitor running status: %v", err)
	}
	return nil
}

// GetSubdomainMonitorTargetByID returns a single subdomain monitor target by ID
func (s *SQLiteDB) GetSubdomainMonitorTargetByID(id int) (*SubdomainMonitorTarget, error) {
	var t SubdomainMonitorTarget
	var checkNewInt, isRunningInt int
	err := s.db.QueryRow(`
		SELECT id, domain, interval_seconds, threads, check_new, is_running, created_at, updated_at
		FROM subdomain_monitor_targets
		WHERE id = ?;
	`, id).Scan(&t.ID, &t.Domain, &t.Interval, &t.Threads, &checkNewInt, &isRunningInt, &t.CreatedAt, &t.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("subdomain monitor target not found with id: %d", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get subdomain monitor target by id: %v", err)
	}
	t.CheckNew = checkNewInt != 0
	t.IsRunning = isRunningInt != 0
	return &t, nil
}

// CreateScan creates a new scan record
func (s *SQLiteDB) CreateScan(scan *ScanRecord) error {
	completedPhasesJSON := "[]"
	failedPhasesJSON := "[]"
	
	if len(scan.CompletedPhases) > 0 {
		data, err := json.Marshal(scan.CompletedPhases)
		if err == nil {
			completedPhasesJSON = string(data)
		}
	}
	
	if len(scan.FailedPhases) > 0 {
		data, err := json.Marshal(scan.FailedPhases)
		if err == nil {
			failedPhasesJSON = string(data)
		}
	}
	
	_, err := s.db.Exec(`
		INSERT INTO scans (
			scan_id, scan_type, target, status, channel_id, thread_id, message_id,
			current_phase, total_phases, phase_name, phase_start_time,
			completed_phases, failed_phases, files_uploaded, error_count,
			started_at, last_update, command
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`, scan.ScanID, scan.ScanType, scan.Target, scan.Status, scan.ChannelID, scan.ThreadID, scan.MessageID,
		scan.CurrentPhase, scan.TotalPhases, scan.PhaseName, scan.PhaseStartTime,
		completedPhasesJSON, failedPhasesJSON, scan.FilesUploaded, scan.ErrorCount,
		scan.StartedAt, scan.LastUpdate, scan.Command)
	
	if err != nil {
		return fmt.Errorf("failed to create scan: %v", err)
	}
	return nil
}

// UpdateScanProgress updates scan progress
func (s *SQLiteDB) UpdateScanProgress(scanID string, progress *ScanProgress) error {
	completedPhasesJSON := "[]"
	failedPhasesJSON := "[]"
	
	if len(progress.CompletedPhases) > 0 {
		data, err := json.Marshal(progress.CompletedPhases)
		if err == nil {
			completedPhasesJSON = string(data)
		}
	}
	
	if len(progress.FailedPhases) > 0 {
		data, err := json.Marshal(progress.FailedPhases)
		if err == nil {
			failedPhasesJSON = string(data)
		}
	}
	
	_, err := s.db.Exec(`
		UPDATE scans SET
			current_phase = ?,
			total_phases = ?,
			phase_name = ?,
			phase_start_time = ?,
			completed_phases = ?,
			failed_phases = ?,
			files_uploaded = ?,
			error_count = ?,
			last_update = ?,
			updated_at = datetime('now')
		WHERE scan_id = ?;
	`, progress.CurrentPhase, progress.TotalPhases, progress.PhaseName, progress.PhaseStartTime,
		completedPhasesJSON, failedPhasesJSON, progress.FilesUploaded, progress.ErrorCount,
		time.Now(), scanID)
	
	if err != nil {
		return fmt.Errorf("failed to update scan progress: %v", err)
	}
	return nil
}

// UpdateScanStatus updates scan status
func (s *SQLiteDB) UpdateScanStatus(scanID string, status string) error {
	now := time.Now()
	var err error
	
	if status == "completed" || status == "failed" || status == "cancelled" {
		_, err = s.db.Exec(`
			UPDATE scans SET
				status = ?,
				completed_at = ?,
				last_update = ?,
				updated_at = datetime('now')
			WHERE scan_id = ?;
		`, status, now, now, scanID)
	} else {
		_, err = s.db.Exec(`
			UPDATE scans SET
				status = ?,
				last_update = ?,
				updated_at = datetime('now')
			WHERE scan_id = ?;
		`, status, now, scanID)
	}
	
	if err != nil {
		return fmt.Errorf("failed to update scan status: %v", err)
	}
	return nil
}

// GetScan retrieves a scan by ID
func (s *SQLiteDB) GetScan(scanID string) (*ScanRecord, error) {
	var scan ScanRecord
	var completedPhasesJSON, failedPhasesJSON string
	var phaseStartTime, completedAt sql.NullTime
	
	err := s.db.QueryRow(`
		SELECT id, scan_id, scan_type, target, status, 
			COALESCE(channel_id, ''), COALESCE(thread_id, ''), COALESCE(message_id, ''),
			current_phase, total_phases, COALESCE(phase_name, ''), phase_start_time,
			COALESCE(completed_phases, '[]'), COALESCE(failed_phases, '[]'),
			files_uploaded, error_count, started_at, completed_at, last_update, COALESCE(command, '')
		FROM scans WHERE scan_id = ?;
	`, scanID).Scan(
		&scan.ID, &scan.ScanID, &scan.ScanType, &scan.Target, &scan.Status,
		&scan.ChannelID, &scan.ThreadID, &scan.MessageID,
		&scan.CurrentPhase, &scan.TotalPhases, &scan.PhaseName, &phaseStartTime,
		&completedPhasesJSON, &failedPhasesJSON,
		&scan.FilesUploaded, &scan.ErrorCount, &scan.StartedAt, &completedAt, &scan.LastUpdate, &scan.Command)
	
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("scan not found: %s", scanID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get scan: %v", err)
	}
	
	if phaseStartTime.Valid {
		scan.PhaseStartTime = &phaseStartTime.Time
	}
	if completedAt.Valid {
		scan.CompletedAt = &completedAt.Time
	}
	
	// Unmarshal JSON arrays
	if completedPhasesJSON != "" && completedPhasesJSON != "[]" {
		json.Unmarshal([]byte(completedPhasesJSON), &scan.CompletedPhases)
	}
	if failedPhasesJSON != "" && failedPhasesJSON != "[]" {
		json.Unmarshal([]byte(failedPhasesJSON), &scan.FailedPhases)
	}
	
	return &scan, nil
}

// ListActiveScans lists all active scans
func (s *SQLiteDB) ListActiveScans() ([]*ScanRecord, error) {
	rows, err := s.db.Query(`
		SELECT id, scan_id, scan_type, target, status,
			COALESCE(channel_id, ''), COALESCE(thread_id, ''), COALESCE(message_id, ''),
			current_phase, total_phases, COALESCE(phase_name, ''), phase_start_time,
			COALESCE(completed_phases, '[]'), COALESCE(failed_phases, '[]'),
			files_uploaded, error_count, started_at, completed_at, last_update, COALESCE(command, '')
		FROM scans
		WHERE status = 'running'
		ORDER BY started_at DESC;
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to list active scans: %v", err)
	}
	defer rows.Close()
	
	var scans []*ScanRecord
	for rows.Next() {
		var scan ScanRecord
		var completedPhasesJSON, failedPhasesJSON string
		var phaseStartTime, completedAt sql.NullTime
		
		err := rows.Scan(
			&scan.ID, &scan.ScanID, &scan.ScanType, &scan.Target, &scan.Status,
			&scan.ChannelID, &scan.ThreadID, &scan.MessageID,
			&scan.CurrentPhase, &scan.TotalPhases, &scan.PhaseName, &phaseStartTime,
			&completedPhasesJSON, &failedPhasesJSON,
			&scan.FilesUploaded, &scan.ErrorCount, &scan.StartedAt, &completedAt, &scan.LastUpdate, &scan.Command)
		
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %v", err)
		}
		
		if phaseStartTime.Valid {
			scan.PhaseStartTime = &phaseStartTime.Time
		}
		if completedAt.Valid {
			scan.CompletedAt = &completedAt.Time
		}
		
		// Unmarshal JSON arrays
		if completedPhasesJSON != "" && completedPhasesJSON != "[]" {
			json.Unmarshal([]byte(completedPhasesJSON), &scan.CompletedPhases)
		}
		if failedPhasesJSON != "" && failedPhasesJSON != "[]" {
			json.Unmarshal([]byte(failedPhasesJSON), &scan.FailedPhases)
		}
		
		scans = append(scans, &scan)
	}
	
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate scans: %v", rows.Err())
	}
	return scans, nil
}

// ListRecentScans lists recent scans (completed, failed, cancelled)
func (s *SQLiteDB) ListRecentScans(limit int) ([]*ScanRecord, error) {
	rows, err := s.db.Query(`
		SELECT id, scan_id, scan_type, target, status,
			COALESCE(channel_id, ''), COALESCE(thread_id, ''), COALESCE(message_id, ''),
			current_phase, total_phases, COALESCE(phase_name, ''), phase_start_time,
			COALESCE(completed_phases, '[]'), COALESCE(failed_phases, '[]'),
			files_uploaded, error_count, started_at, completed_at, last_update, COALESCE(command, '')
		FROM scans
		WHERE status IN ('completed', 'failed', 'cancelled')
		ORDER BY started_at DESC
		LIMIT ?;
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list recent scans: %v", err)
	}
	defer rows.Close()
	
	var scans []*ScanRecord
	for rows.Next() {
		var scan ScanRecord
		var completedPhasesJSON, failedPhasesJSON string
		var phaseStartTime, completedAt sql.NullTime
		
		err := rows.Scan(
			&scan.ID, &scan.ScanID, &scan.ScanType, &scan.Target, &scan.Status,
			&scan.ChannelID, &scan.ThreadID, &scan.MessageID,
			&scan.CurrentPhase, &scan.TotalPhases, &scan.PhaseName, &phaseStartTime,
			&completedPhasesJSON, &failedPhasesJSON,
			&scan.FilesUploaded, &scan.ErrorCount, &scan.StartedAt, &completedAt, &scan.LastUpdate, &scan.Command)
		
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %v", err)
		}
		
		if phaseStartTime.Valid {
			scan.PhaseStartTime = &phaseStartTime.Time
		}
		if completedAt.Valid {
			scan.CompletedAt = &completedAt.Time
		}
		
		// Unmarshal JSON arrays
		if completedPhasesJSON != "" && completedPhasesJSON != "[]" {
			json.Unmarshal([]byte(completedPhasesJSON), &scan.CompletedPhases)
		}
		if failedPhasesJSON != "" && failedPhasesJSON != "[]" {
			json.Unmarshal([]byte(failedPhasesJSON), &scan.FailedPhases)
		}
		
		scans = append(scans, &scan)
	}
	
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate scans: %v", rows.Err())
	}
	return scans, nil
}

// DeleteScan deletes a scan record
func (s *SQLiteDB) DeleteScan(scanID string) error {
	_, err := s.db.Exec(`DELETE FROM scans WHERE scan_id = ?;`, scanID)
	if err != nil {
		return fmt.Errorf("failed to delete scan: %v", err)
	}
	return nil
}

// ListVulnerableDNSProviders returns all vulnerable DNS providers from the database for SQLite
func (s *SQLiteDB) ListVulnerableDNSProviders() (map[string]string, error) {
	rows, err := s.db.Query(`
		SELECT name, fingerprint FROM dns_takeover_providers;
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query dns_takeover_providers: %v", err)
	}
	defer rows.Close()

	providers := make(map[string]string)
	for rows.Next() {
		var name, fingerprint string
		if err := rows.Scan(&name, &fingerprint); err != nil {
			return nil, fmt.Errorf("failed to scan dns provider: %v", err)
		}
		providers[name] = fingerprint
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate dns providers: %v", rows.Err())
	}
	return providers, nil
}

// AddVulnerableDNSProvider adds or updates a vulnerable DNS provider for SQLite
func (s *SQLiteDB) AddVulnerableDNSProvider(name, fingerprint string) error {
	_, err := s.db.Exec(`
		INSERT INTO dns_takeover_providers (name, fingerprint)
		VALUES (?, ?)
		ON CONFLICT (name) DO UPDATE SET
			fingerprint = excluded.fingerprint,
			updated_at = datetime('now');
	`, name, fingerprint)
	if err != nil {
		return fmt.Errorf("failed to add dns provider: %v", err)
	}
	return nil
}

// Close closes the database connection
func (s *SQLiteDB) Close() {
	if s.db != nil {
		s.db.Close()
	}
}

