package db

import (
	"database/sql"
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

	// Test connection
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}

	s.db = db
	log.Printf("[INFO] Connected to SQLite database at %s", dbPath)
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
	
	-- Create indexes
	CREATE INDEX IF NOT EXISTS idx_subdomains_domain_id ON subdomains(domain_id);
	CREATE INDEX IF NOT EXISTS idx_subdomains_is_live ON subdomains(is_live);
	CREATE INDEX IF NOT EXISTS idx_js_files_subdomain_id ON js_files(subdomain_id);
	CREATE INDEX IF NOT EXISTS idx_keyhack_templates_keyname ON keyhack_templates(keyname);
	CREATE INDEX IF NOT EXISTS idx_updates_targets_url ON updates_targets(url);
	`

	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create schema: %v", err)
	}
	log.Printf("[OK] Database schema initialized")
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

// Close closes the database connection
func (s *SQLiteDB) Close() {
	if s.db != nil {
		s.db.Close()
	}
}

