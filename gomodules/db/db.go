package db

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	dbPool *pgxpool.Pool
	ctx    = context.Background()
)

// Init initializes the database connection pool
func Init() error {
	dbType := getEnv("DB_TYPE", "postgresql")

	if dbType != "postgresql" {
		return fmt.Errorf("only PostgreSQL is supported")
	}

	// Parse PostgreSQL connection string if provided
	dbHostEnv := os.Getenv("DB_HOST")
	var connStr string

	if strings.HasPrefix(dbHostEnv, "postgresql://") || strings.HasPrefix(dbHostEnv, "postgres://") {
		// Use connection string directly
		connStr = dbHostEnv
	} else {
		// Build connection string from individual environment variables
		dbHost := getEnv("DB_HOST", "localhost")
		dbPort := getEnv("DB_PORT", "5432")
		dbUser := getEnv("DB_USER", "autoar")
		dbPass := os.Getenv("DB_PASSWORD")
		dbName := getEnv("DB_NAME", "autoar")

		connStr = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
			dbHost, dbPort, dbUser, dbPass, dbName)
	}

	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return fmt.Errorf("failed to parse connection string: %v", err)
	}

	// Configure pool settings
	config.MaxConns = 25
	config.MinConns = 2
	config.MaxConnLifetime = time.Hour
	config.MaxConnIdleTime = time.Minute * 30

	dbPool, err = pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to create connection pool: %v", err)
	}

	// Test connection
	if err := dbPool.Ping(ctx); err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}

	log.Printf("[INFO] Connected to PostgreSQL database")
	return nil
}

// InitSchema initializes the database schema
func InitSchema() error {
	if dbPool == nil {
		if err := Init(); err != nil {
			return err
		}
	}

	schema := `
	-- Create domains table with proper constraints
	CREATE TABLE IF NOT EXISTS domains (
		id SERIAL PRIMARY KEY,
		domain VARCHAR(255) NOT NULL,
		created_at TIMESTAMP DEFAULT NOW()
	);
	
	-- Create unique index if it doesn't exist, handling duplicates
	DO $$ 
	BEGIN
		-- Check if index already exists
		IF NOT EXISTS (
			SELECT 1 FROM pg_indexes 
			WHERE schemaname = 'public' 
			AND indexname = 'domains_domain_key'
		) THEN
			-- Remove duplicates before creating unique index (keep the one with highest id)
			DELETE FROM domains d1
			WHERE EXISTS (
				SELECT 1 FROM domains d2 
				WHERE d2.domain = d1.domain 
				AND d2.id > d1.id
			);
			
			-- Now create the unique index
			CREATE UNIQUE INDEX domains_domain_key ON domains (domain);
		END IF;
	END $$;
	
	-- Ensure updated_at column exists (for backward compatibility)
	DO $$ 
	BEGIN
		IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='domains' AND column_name='updated_at') THEN
			ALTER TABLE domains ADD COLUMN updated_at TIMESTAMP DEFAULT NOW();
		END IF;
	END $$;
	
	-- Create subdomains table with proper constraints
	CREATE TABLE IF NOT EXISTS subdomains (
		id SERIAL PRIMARY KEY,
		domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
		subdomain VARCHAR(255) NOT NULL,
		is_live BOOLEAN DEFAULT FALSE,
		http_url VARCHAR(512),
		https_url VARCHAR(512),
		http_status INTEGER,
		https_status INTEGER,
		created_at TIMESTAMP DEFAULT NOW(),
		updated_at TIMESTAMP DEFAULT NOW()
	);
	
	-- Create unique index if it doesn't exist, handling duplicates
	DO $$ 
	BEGIN
		-- Check if index already exists
		IF NOT EXISTS (
			SELECT 1 FROM pg_indexes 
			WHERE schemaname = 'public' 
			AND indexname = 'subdomains_subdomain_key'
		) THEN
			-- Remove duplicates before creating unique index (keep the one with highest id)
			DELETE FROM subdomains s1
			WHERE EXISTS (
				SELECT 1 FROM subdomains s2 
				WHERE s2.subdomain = s1.subdomain 
				AND s2.id > s1.id
			);
			
			-- Now create the unique index
			CREATE UNIQUE INDEX subdomains_subdomain_key ON subdomains (subdomain);
		END IF;
	END $$;
	
	-- Create js_files table with proper constraints
	CREATE TABLE IF NOT EXISTS js_files (
		id SERIAL PRIMARY KEY,
		subdomain_id INTEGER REFERENCES subdomains(id) ON DELETE CASCADE,
		js_url VARCHAR(1024) NOT NULL,
		content_hash VARCHAR(64),
		last_scanned TIMESTAMP,
		created_at TIMESTAMP DEFAULT NOW(),
		updated_at TIMESTAMP DEFAULT NOW()
	);
	
	-- Create unique index if it doesn't exist, handling duplicates
	DO $$ 
	BEGIN
		-- Check if index already exists
		IF NOT EXISTS (
			SELECT 1 FROM pg_indexes 
			WHERE schemaname = 'public' 
			AND indexname = 'js_files_js_url_key'
		) THEN
			-- Remove duplicates before creating unique index (keep the one with highest id)
			DELETE FROM js_files j1
			WHERE EXISTS (
				SELECT 1 FROM js_files j2 
				WHERE j2.js_url = j1.js_url 
				AND j2.id > j1.id
			);
			
			-- Now create the unique index
			CREATE UNIQUE INDEX js_files_js_url_key ON js_files (js_url);
		END IF;
	END $$;
	
	-- Create keyhack_templates table with proper constraints
	CREATE TABLE IF NOT EXISTS keyhack_templates (
		id SERIAL PRIMARY KEY,
		keyname VARCHAR(255) NOT NULL,
		command_template TEXT NOT NULL,
		method VARCHAR(10) DEFAULT 'GET',
		url TEXT NOT NULL,
		header TEXT,
		body TEXT,
		description TEXT,
		notes TEXT,
		created_at TIMESTAMP DEFAULT NOW(),
		updated_at TIMESTAMP DEFAULT NOW()
	);
	
	-- Create unique index if it doesn't exist, handling duplicates
	DO $$ 
	BEGIN
		-- Check if index already exists
		IF NOT EXISTS (
			SELECT 1 FROM pg_indexes 
			WHERE schemaname = 'public' 
			AND indexname = 'keyhack_templates_keyname_key'
		) THEN
			-- Remove duplicates before creating unique index (keep the one with highest id)
			DELETE FROM keyhack_templates k1
			WHERE EXISTS (
				SELECT 1 FROM keyhack_templates k2 
				WHERE k2.keyname = k1.keyname 
				AND k2.id > k1.id
			);
			
			-- Now create the unique index
			CREATE UNIQUE INDEX keyhack_templates_keyname_key ON keyhack_templates (keyname);
		END IF;
	END $$;
	
	-- Create updates_targets table for monitoring
	CREATE TABLE IF NOT EXISTS updates_targets (
		id SERIAL PRIMARY KEY,
		url TEXT NOT NULL UNIQUE,
		strategy TEXT NOT NULL,
		pattern TEXT,
		created_at TIMESTAMP DEFAULT NOW(),
		updated_at TIMESTAMP DEFAULT NOW()
	);
	
	CREATE INDEX IF NOT EXISTS idx_subdomains_domain_id ON subdomains(domain_id);
	CREATE INDEX IF NOT EXISTS idx_subdomains_is_live ON subdomains(is_live);
	CREATE INDEX IF NOT EXISTS idx_js_files_subdomain_id ON js_files(subdomain_id);
	CREATE INDEX IF NOT EXISTS idx_keyhack_templates_keyname ON keyhack_templates(keyname);
	CREATE INDEX IF NOT EXISTS idx_updates_targets_url ON updates_targets(url);
	`

	_, err := dbPool.Exec(ctx, schema)
	if err != nil {
		return fmt.Errorf("failed to create schema: %v", err)
	}
	log.Printf("[OK] Database schema initialized")
	return nil
}

// InsertOrGetDomain inserts a domain or returns existing domain ID
func InsertOrGetDomain(domain string) (int, error) {
	if dbPool == nil {
		if err := Init(); err != nil {
			return 0, err
		}
	}

	// First, try to get existing domain
	var domainID int
	err := dbPool.QueryRow(ctx, `
		SELECT id FROM domains WHERE domain = $1 LIMIT 1;
	`, domain).Scan(&domainID)

	if err == nil {
		// Domain exists, return its ID
		return domainID, nil
	}

	if err != pgx.ErrNoRows {
		// Unexpected error
		return 0, fmt.Errorf("failed to query domain: %v", err)
	}

	// Domain doesn't exist, insert it
	err = dbPool.QueryRow(ctx, `
		INSERT INTO domains (domain) 
		VALUES ($1) 
		RETURNING id;
	`, domain).Scan(&domainID)

	if err != nil {
		// If insert failed due to race condition (another goroutine inserted it), try to get it again
		if err := dbPool.QueryRow(ctx, `
			SELECT id FROM domains WHERE domain = $1 LIMIT 1;
		`, domain).Scan(&domainID); err != nil {
			return 0, fmt.Errorf("failed to insert/get domain: %v", err)
		}
	}

	return domainID, nil
}

// BatchInsertSubdomains inserts multiple subdomains for a domain
func BatchInsertSubdomains(domain string, subdomains []string, isLive bool) error {
	if dbPool == nil {
		if err := Init(); err != nil {
			return err
		}
	}

	domainID, err := InsertOrGetDomain(domain)
	if err != nil {
		return fmt.Errorf("failed to get domain ID: %v", err)
	}

	log.Printf("[INFO] Batch inserting %d subdomains for %s (domain_id: %d)", len(subdomains), domain, domainID)

	// Use transaction for better performance
	tx, err := dbPool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback(ctx)

	// Prepare statement for batch insert
	_, err = tx.Prepare(ctx, "batch_insert_subdomains", `
		INSERT INTO subdomains (domain_id, subdomain, is_live, http_url, https_url, http_status, https_status)
		VALUES ($1, $2, $3, '', '', 0, 0)
		ON CONFLICT (subdomain) DO UPDATE SET 
			updated_at = $4,
			domain_id = EXCLUDED.domain_id;
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %v", err)
	}

	count := 0
	for _, subdomain := range subdomains {
		subdomain = strings.TrimSpace(subdomain)
		if subdomain == "" {
			continue
		}

		_, err := tx.Exec(ctx, "batch_insert_subdomains", domainID, subdomain, isLive, time.Now())
		if err != nil {
			log.Printf("[WARN] Failed to insert subdomain %s: %v", subdomain, err)
			continue
		}
		count++
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	log.Printf("[OK] Inserted %d subdomains for %s", count, domain)
	return nil
}

// InsertSubdomain inserts or updates a single subdomain
func InsertSubdomain(domain, subdomain string, isLive bool, httpURL, httpsURL string, httpStatus, httpsStatus int) error {
	if dbPool == nil {
		if err := Init(); err != nil {
			return err
		}
	}

	domainID, err := InsertOrGetDomain(domain)
	if err != nil {
		return fmt.Errorf("failed to get domain ID: %v", err)
	}

	// Check if subdomain already exists
	var existingID int
	err = dbPool.QueryRow(ctx, `
		SELECT id FROM subdomains WHERE domain_id = $1 AND subdomain = $2 LIMIT 1;
	`, domainID, subdomain).Scan(&existingID)

	if err == pgx.ErrNoRows {
		// Insert new subdomain
		_, err = dbPool.Exec(ctx, `
			INSERT INTO subdomains (domain_id, subdomain, is_live, http_url, https_url, http_status, https_status)
			VALUES ($1, $2, $3, $4, $5, $6, $7);
		`, domainID, subdomain, isLive, httpURL, httpsURL, httpStatus, httpsStatus)
	} else if err == nil {
		// Update existing subdomain
		_, err = dbPool.Exec(ctx, `
			UPDATE subdomains SET
				is_live = $1,
				http_url = $2,
				https_url = $3,
				http_status = $4,
				https_status = $5,
				updated_at = NOW()
			WHERE id = $6;
		`, isLive, httpURL, httpsURL, httpStatus, httpsStatus, existingID)
	}

	if err != nil {
		return fmt.Errorf("failed to insert/update subdomain: %v", err)
	}

	return nil
}

// InsertJSFile inserts or updates a JS file for a subdomain
// It extracts the subdomain from the JS URL automatically
func InsertJSFile(domain, jsURL, contentHash string) error {
	if dbPool == nil {
		if err := Init(); err != nil {
			return err
		}
	}

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

	domainID, err := InsertOrGetDomain(domain)
	if err != nil {
		return fmt.Errorf("failed to get domain ID: %v", err)
	}

	// Get or create subdomain
	var subdomainID int
	err = dbPool.QueryRow(ctx, `
		SELECT id FROM subdomains WHERE domain_id = $1 AND subdomain = $2 LIMIT 1;
	`, domainID, subdomain).Scan(&subdomainID)

	if err == pgx.ErrNoRows {
		// Create subdomain first
		err = dbPool.QueryRow(ctx, `
			INSERT INTO subdomains (domain_id, subdomain, is_live, http_url, https_url, http_status, https_status)
			VALUES ($1, $2, false, '', '', 0, 0)
			RETURNING id;
		`, domainID, subdomain).Scan(&subdomainID)
	}

	if err != nil {
		return fmt.Errorf("failed to get/create subdomain: %v", err)
	}

	// Insert or update JS file
	_, err = dbPool.Exec(ctx, `
		INSERT INTO js_files (subdomain_id, js_url, content_hash, last_scanned)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (js_url) DO UPDATE SET
			content_hash = EXCLUDED.content_hash,
			last_scanned = NOW(),
			updated_at = NOW();
	`, subdomainID, jsURL, contentHash)

	if err != nil {
		return fmt.Errorf("failed to insert/update JS file: %v", err)
	}

	return nil
}

// InsertKeyhackTemplate inserts or updates a KeyHack template
func InsertKeyhackTemplate(keyname, commandTemplate, method, url, header, body, notes, description string) error {
	if dbPool == nil {
		if err := Init(); err != nil {
			return err
		}
	}

	_, err := dbPool.Exec(ctx, `
		INSERT INTO keyhack_templates (keyname, command_template, method, url, header, body, description, notes)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (keyname) DO UPDATE SET
			command_template = EXCLUDED.command_template,
			method = EXCLUDED.method,
			url = EXCLUDED.url,
			header = EXCLUDED.header,
			body = EXCLUDED.body,
			description = EXCLUDED.description,
			notes = EXCLUDED.notes,
			updated_at = NOW();
	`, keyname, commandTemplate, method, url, header, body, description, notes)

	if err != nil {
		return fmt.Errorf("failed to insert/update keyhack template: %v", err)
	}

	return nil
}

// KeyhackTemplate represents a stored key validation template.
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

// ListKeyhackTemplates returns all keyhack templates.
func ListKeyhackTemplates() ([]KeyhackTemplate, error) {
	if dbPool == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}

	rows, err := dbPool.Query(ctx, `
		SELECT keyname, command_template, method, url, header, body, notes, description
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
func SearchKeyhackTemplates(query string) ([]KeyhackTemplate, error) {
	if dbPool == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}

	q := "%" + query + "%"
	rows, err := dbPool.Query(ctx, `
		SELECT keyname, command_template, method, url, header, body, notes, description
		FROM keyhack_templates
		WHERE keyname ILIKE $1 OR description ILIKE $1
		ORDER BY keyname;
	`, q)
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
func ListDomains() ([]string, error) {
	if dbPool == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}

	rows, err := dbPool.Query(ctx, `SELECT DISTINCT domain FROM domains ORDER BY domain;`)
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
func ListSubdomains(domain string) ([]string, error) {
	if dbPool == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}

	rows, err := dbPool.Query(ctx, `
		SELECT s.subdomain
		FROM subdomains s
		JOIN domains d ON s.domain_id = d.id
		WHERE d.domain = $1
		ORDER BY s.subdomain;
	`, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to query subdomains: %v", err)
	}
	defer rows.Close()

	var subs []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("failed to scan subdomain: %v", err)
		}
		subs = append(subs, s)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate subdomains: %v", rows.Err())
	}
	return subs, nil
}

// DeleteDomain deletes a domain and all its related data using ON DELETE CASCADE.
func DeleteDomain(domain string) error {
	if dbPool == nil {
		if err := Init(); err != nil {
			return err
		}
	}

	cmdTag, err := dbPool.Exec(ctx, `DELETE FROM domains WHERE domain = $1;`, domain)
	if err != nil {
		return fmt.Errorf("failed to delete domain %s: %v", domain, err)
	}
	if cmdTag.RowsAffected() == 0 {
		return fmt.Errorf("domain not found: %s", domain)
	}
	return nil
}

// MonitorTarget represents a monitoring target
type MonitorTarget struct {
	ID       int
	URL      string
	Strategy string
	Pattern  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ListMonitorTargets returns all monitoring targets
func ListMonitorTargets() ([]MonitorTarget, error) {
	if dbPool == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}

	rows, err := dbPool.Query(ctx, `
		SELECT id, url, strategy, pattern, created_at, updated_at
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
		if err := rows.Scan(&t.ID, &t.URL, &t.Strategy, &t.Pattern, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan monitor target: %v", err)
		}
		targets = append(targets, t)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate monitor targets: %v", rows.Err())
	}
	return targets, nil
}

// AddMonitorTarget adds a new monitoring target
func AddMonitorTarget(url, strategy, pattern string) error {
	if dbPool == nil {
		if err := Init(); err != nil {
			return err
		}
	}

	_, err := dbPool.Exec(ctx, `
		INSERT INTO updates_targets (url, strategy, pattern)
		VALUES ($1, $2, $3)
		ON CONFLICT (url) DO UPDATE SET
			strategy = EXCLUDED.strategy,
			pattern = EXCLUDED.pattern,
			updated_at = NOW();
	`, url, strategy, pattern)

	if err != nil {
		return fmt.Errorf("failed to add monitor target: %v", err)
	}
	return nil
}

// RemoveMonitorTarget removes a monitoring target by URL
func RemoveMonitorTarget(url string) error {
	if dbPool == nil {
		if err := Init(); err != nil {
			return err
		}
	}

	cmdTag, err := dbPool.Exec(ctx, `DELETE FROM updates_targets WHERE url = $1;`, url)
	if err != nil {
		return fmt.Errorf("failed to remove monitor target: %v", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return fmt.Errorf("monitor target not found: %s", url)
	}
	return nil
}

// GetPool returns the database connection pool (for advanced use)
func GetPool() *pgxpool.Pool {
	return dbPool
}

// Close closes the database connection pool
func Close() {
	if dbPool != nil {
		dbPool.Close()
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
