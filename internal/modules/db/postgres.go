package db

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresDB implements the DB interface for PostgreSQL
type PostgresDB struct {
	pool *pgxpool.Pool
	ctx  context.Context
}

// Init initializes the PostgreSQL database connection pool
func (p *PostgresDB) Init() error {
	// Parse PostgreSQL connection string if provided.
	// Prefer DB_HOST; fall back to DATABASE_URL (common in hosting / copied .env files).
	dbHostEnv := strings.TrimSpace(os.Getenv("DB_HOST"))
	if dbHostEnv == "" {
		dbHostEnv = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	}
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

	// Disable prepared statements for compatibility with PgBouncer/Supabase poolers
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	// Pool size: default low for Supabase transaction pooler (shared max connections).
	maxConns := int32(10)
	if v := os.Getenv("DB_MAX_CONNS"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 32); err == nil && n > 0 && n <= 100 {
			maxConns = int32(n)
		}
	}
	minConns := int32(2)
	if maxConns < minConns {
		minConns = maxConns
	}

	config.MaxConns = maxConns
	config.MinConns = minConns
	config.MaxConnLifetime = time.Hour
	config.MaxConnIdleTime = time.Minute * 30

	p.ctx = context.Background()
	p.pool, err = pgxpool.NewWithConfig(p.ctx, config)
	if err != nil {
		return fmt.Errorf("failed to create connection pool: %v", err)
	}

	// Test connection
	if err := p.pool.Ping(p.ctx); err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}

	if os.Getenv("AUTOAR_SILENT") != "true" {
		log.Printf("[INFO] Connected to PostgreSQL database")
	}
	return nil
}

// InitSchema initializes the database schema
func (p *PostgresDB) InitSchema() error {
	if p.pool == nil {
		if err := p.Init(); err != nil {
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
	
	-- Ensure notes column exists (for backward compatibility)
	DO $$ 
	BEGIN
		IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='keyhack_templates' AND column_name='notes') THEN
			ALTER TABLE keyhack_templates ADD COLUMN notes TEXT;
		END IF;
	END $$;
	
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
		is_running BOOLEAN DEFAULT FALSE,
		last_hash TEXT,
		last_run_at TIMESTAMP,
		change_count INTEGER DEFAULT 0,
		created_at TIMESTAMP DEFAULT NOW(),
		updated_at TIMESTAMP DEFAULT NOW()
	);
	
	-- Ensure new columns exist (for backward compatibility)
	DO $$ 
	BEGIN
		IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='updates_targets' AND column_name='is_running') THEN
			ALTER TABLE updates_targets ADD COLUMN is_running BOOLEAN DEFAULT FALSE;
		END IF;
		IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='updates_targets' AND column_name='last_hash') THEN
			ALTER TABLE updates_targets ADD COLUMN last_hash TEXT;
		END IF;
		IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='updates_targets' AND column_name='last_run_at') THEN
			ALTER TABLE updates_targets ADD COLUMN last_run_at TIMESTAMP;
		END IF;
		IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='updates_targets' AND column_name='change_count') THEN
			ALTER TABLE updates_targets ADD COLUMN change_count INTEGER DEFAULT 0;
		END IF;
	END $$;
	
	-- Create subdomain_monitor_targets table for subdomain monitoring
	CREATE TABLE IF NOT EXISTS subdomain_monitor_targets (
		id SERIAL PRIMARY KEY,
		domain VARCHAR(255) NOT NULL UNIQUE,
		interval_seconds INTEGER DEFAULT 3600,
		threads INTEGER DEFAULT 100,
		check_new BOOLEAN DEFAULT TRUE,
		is_running BOOLEAN DEFAULT FALSE,
		last_run_at TIMESTAMP,
		created_at TIMESTAMP DEFAULT NOW(),
		updated_at TIMESTAMP DEFAULT NOW()
	);
	
	-- Ensure last_run_at exists (for backward compatibility)
	DO $$
	BEGIN
		IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='subdomain_monitor_targets' AND column_name='last_run_at') THEN
			ALTER TABLE subdomain_monitor_targets ADD COLUMN last_run_at TIMESTAMP;
		END IF;
	END $$;

	-- Create monitor_changes table for change history
	CREATE TABLE IF NOT EXISTS monitor_changes (
		id SERIAL PRIMARY KEY,
		target_type VARCHAR(20) NOT NULL,
		target_id INTEGER NOT NULL,
		domain TEXT NOT NULL,
		change_type VARCHAR(50) NOT NULL,
		detail TEXT,
		detected_at TIMESTAMP DEFAULT NOW(),
		notified BOOLEAN DEFAULT FALSE
	);
	CREATE INDEX IF NOT EXISTS idx_monitor_changes_domain ON monitor_changes(domain);
	CREATE INDEX IF NOT EXISTS idx_monitor_changes_detected_at ON monitor_changes(detected_at);
	CREATE INDEX IF NOT EXISTS idx_monitor_changes_change_type ON monitor_changes(change_type);
	
	-- Create scans table for scan progress tracking
	CREATE TABLE IF NOT EXISTS scans (
		id SERIAL PRIMARY KEY,
		scan_id VARCHAR(255) NOT NULL UNIQUE,
		scan_type VARCHAR(50) NOT NULL,
		target VARCHAR(255) NOT NULL,
		status VARCHAR(50) NOT NULL,
		channel_id VARCHAR(100),
		thread_id VARCHAR(100),
		message_id VARCHAR(100),
		current_phase INTEGER DEFAULT 0,
		total_phases INTEGER DEFAULT 0,
		phase_name VARCHAR(255),
		phase_start_time TIMESTAMP,
		completed_phases JSONB,
		failed_phases JSONB,
		files_uploaded INTEGER DEFAULT 0,
		error_count INTEGER DEFAULT 0,
		started_at TIMESTAMP NOT NULL,
		completed_at TIMESTAMP,
		last_update TIMESTAMP NOT NULL,
		command TEXT,
		result_url TEXT,
		created_at TIMESTAMP DEFAULT NOW(),
		updated_at TIMESTAMP DEFAULT NOW()
	);

	-- Create scan_artifacts table for R2 indexed outputs
	CREATE TABLE IF NOT EXISTS scan_artifacts (
		id SERIAL PRIMARY KEY,
		scan_id VARCHAR(255) NOT NULL,
		file_name TEXT,
		local_path TEXT,
		r2_key TEXT NOT NULL,
		public_url TEXT NOT NULL,
		size_bytes BIGINT DEFAULT 0,
		line_count INTEGER DEFAULT 0,
		content_type TEXT,
		created_at TIMESTAMP DEFAULT NOW()
	);
	
	-- Create dns_takeover_providers table
	CREATE TABLE IF NOT EXISTS dns_takeover_providers (
		id SERIAL PRIMARY KEY,
		name VARCHAR(255) NOT NULL UNIQUE,
		fingerprint TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT NOW(),
		updated_at TIMESTAMP DEFAULT NOW()
	);
	
	CREATE INDEX IF NOT EXISTS idx_subdomains_domain_id ON subdomains(domain_id);
	CREATE INDEX IF NOT EXISTS idx_subdomains_is_live ON subdomains(is_live);
	CREATE INDEX IF NOT EXISTS idx_js_files_subdomain_id ON js_files(subdomain_id);
	CREATE INDEX IF NOT EXISTS idx_keyhack_templates_keyname ON keyhack_templates(keyname);
	CREATE INDEX IF NOT EXISTS idx_updates_targets_url ON updates_targets(url);
	CREATE INDEX IF NOT EXISTS idx_subdomain_monitor_targets_domain ON subdomain_monitor_targets(domain);
	CREATE INDEX IF NOT EXISTS idx_subdomain_monitor_targets_is_running ON subdomain_monitor_targets(is_running);
	CREATE INDEX IF NOT EXISTS idx_scans_scan_id ON scans(scan_id);
	CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
	CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
	CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at);
	CREATE INDEX IF NOT EXISTS idx_scan_artifacts_scan_id ON scan_artifacts(scan_id);
	CREATE INDEX IF NOT EXISTS idx_scan_artifacts_created_at ON scan_artifacts(created_at);
	`

	_, err := p.pool.Exec(p.ctx, schema)
	if err != nil {
		return fmt.Errorf("failed to create schema: %v", err)
	}

	// Migrate legacy DBs: CREATE TABLE IF NOT EXISTS does not add new columns to existing scans tables.
	_, err = p.pool.Exec(p.ctx, `ALTER TABLE scans ADD COLUMN IF NOT EXISTS result_url TEXT`)
	if err != nil {
		return fmt.Errorf("failed to migrate scans.result_url: %v", err)
	}

	// Migrate scan_artifacts table: add module and category columns
	_, _ = p.pool.Exec(p.ctx, `ALTER TABLE scan_artifacts ADD COLUMN IF NOT EXISTS module TEXT`)
	_, _ = p.pool.Exec(p.ctx, `ALTER TABLE scan_artifacts ADD COLUMN IF NOT EXISTS category TEXT`)

	// Deduplicate legacy artifact rows before enforcing uniqueness.
	_, _ = p.pool.Exec(p.ctx, `
		DELETE FROM scan_artifacts a
		USING scan_artifacts b
		WHERE a.scan_id = b.scan_id
		  AND a.r2_key = b.r2_key
		  AND a.id < b.id;
	`)
	if _, idxErr := p.pool.Exec(p.ctx, `
		CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_artifacts_scan_r2_key_uniq
		ON scan_artifacts(scan_id, r2_key);
	`); idxErr != nil {
		log.Printf("[WARN] Could not enforce unique scan artifact index: %v", idxErr)
	}

	if os.Getenv("AUTOAR_SILENT") != "true" {
		log.Printf("[OK] Database schema initialized")
	}
	return nil
}

// InsertOrGetDomain inserts a domain or returns existing domain ID
func (p *PostgresDB) InsertOrGetDomain(domain string) (int, error) {
	// First, try to get existing domain
	var domainID int
	err := p.pool.QueryRow(p.ctx, `
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
	err = p.pool.QueryRow(p.ctx, `
		INSERT INTO domains (domain) 
		VALUES ($1) 
		RETURNING id;
	`, domain).Scan(&domainID)

	if err != nil {
		// If insert failed due to race condition (another goroutine inserted it), try to get it again
		if err := p.pool.QueryRow(p.ctx, `
			SELECT id FROM domains WHERE domain = $1 LIMIT 1;
		`, domain).Scan(&domainID); err != nil {
			return 0, fmt.Errorf("failed to insert/get domain: %v", err)
		}
	}

	return domainID, nil
}

// BatchInsertSubdomains inserts multiple subdomains for a domain
func (p *PostgresDB) BatchInsertSubdomains(domain string, subdomains []string, isLive bool) error {
	domainID, err := p.InsertOrGetDomain(domain)
	if err != nil {
		return fmt.Errorf("failed to get domain ID: %v", err)
	}

	log.Printf("[INFO] Batch inserting %d subdomains for %s (domain_id: %d)", len(subdomains), domain, domainID)

	// Use a transaction for atomic batch insert.
	// #14: Do NOT use tx.Prepare with a named statement ("batch_insert_subdomains") —
	// with pgxpool each connection is different and the name can collide across goroutines.
	// Use inline SQL with direct tx.Exec instead.
	tx, err := p.pool.Begin(p.ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback(p.ctx)

	const batchSQL = `
		INSERT INTO subdomains (domain_id, subdomain, is_live, http_url, https_url, http_status, https_status)
		VALUES ($1, $2, $3, '', '', 0, 0)
		ON CONFLICT (subdomain) DO UPDATE SET 
			updated_at = $4,
			domain_id = EXCLUDED.domain_id;
	`

	count := 0
	for _, subdomain := range subdomains {
		subdomain = strings.TrimSpace(subdomain)
		if subdomain == "" {
			continue
		}

		_, err := tx.Exec(p.ctx, batchSQL, domainID, subdomain, isLive, time.Now())
		if err != nil {
			log.Printf("[WARN] Failed to insert subdomain %s: %v", subdomain, err)
			continue
		}
		count++
	}

	if err := tx.Commit(p.ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	log.Printf("[OK] Inserted %d subdomains for %s", count, domain)
	return nil
}

// InsertSubdomain inserts or updates a single subdomain
func (p *PostgresDB) InsertSubdomain(domain, subdomain string, isLive bool, httpURL, httpsURL string, httpStatus, httpsStatus int) error {
	domainID, err := p.InsertOrGetDomain(domain)
	if err != nil {
		return fmt.Errorf("failed to get domain ID: %v", err)
	}

	// Check if subdomain already exists
	var existingID int
	err = p.pool.QueryRow(p.ctx, `
		SELECT id FROM subdomains WHERE domain_id = $1 AND subdomain = $2 LIMIT 1;
	`, domainID, subdomain).Scan(&existingID)

	if err == pgx.ErrNoRows {
		// Insert new subdomain
		_, err = p.pool.Exec(p.ctx, `
			INSERT INTO subdomains (domain_id, subdomain, is_live, http_url, https_url, http_status, https_status)
			VALUES ($1, $2, $3, $4, $5, $6, $7);
		`, domainID, subdomain, isLive, httpURL, httpsURL, httpStatus, httpsStatus)
	} else if err == nil {
		// Update existing subdomain
		_, err = p.pool.Exec(p.ctx, `
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

// InsertJSFile inserts or updates a JS file for a subdomain.
// #15: Use net/url.Parse to correctly extract hostnames (handles ports, auth, etc.).
func (p *PostgresDB) InsertJSFile(domain, jsURL, contentHash string) error {
	// Extract hostname from JS URL — correctly handles ports.
	var subdomain string
	if parsed, err := url.Parse(jsURL); err == nil && parsed.Hostname() != "" {
		subdomain = parsed.Hostname() // strips port correctly (e.g. sub.example.com:8080 → sub.example.com)
	} else {
		subdomain = jsURL // fallback: store as-is if not a valid URL
	}

	domainID, err := p.InsertOrGetDomain(domain)
	if err != nil {
		return fmt.Errorf("failed to get domain ID: %v", err)
	}

	// Get or create subdomain
	var subdomainID int
	err = p.pool.QueryRow(p.ctx, `
		SELECT id FROM subdomains WHERE domain_id = $1 AND subdomain = $2 LIMIT 1;
	`, domainID, subdomain).Scan(&subdomainID)

	if err == pgx.ErrNoRows {
		// Create subdomain first
		err = p.pool.QueryRow(p.ctx, `
			INSERT INTO subdomains (domain_id, subdomain, is_live, http_url, https_url, http_status, https_status)
			VALUES ($1, $2, false, '', '', 0, 0)
			RETURNING id;
		`, domainID, subdomain).Scan(&subdomainID)
	}

	if err != nil {
		return fmt.Errorf("failed to get/create subdomain: %v", err)
	}

	// Insert or update JS file
	_, err = p.pool.Exec(p.ctx, `
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
func (p *PostgresDB) InsertKeyhackTemplate(keyname, commandTemplate, method, url, header, body, notes, description string) error {
	_, err := p.pool.Exec(p.ctx, `
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

// ListKeyhackTemplates returns all keyhack templates.
func (p *PostgresDB) ListKeyhackTemplates() ([]KeyhackTemplate, error) {
	rows, err := p.pool.Query(p.ctx, `
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
func (p *PostgresDB) SearchKeyhackTemplates(query string) ([]KeyhackTemplate, error) {
	q := "%" + query + "%"
	rows, err := p.pool.Query(p.ctx, `
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
func (p *PostgresDB) ListDomains() ([]string, error) {
	rows, err := p.pool.Query(p.ctx, `SELECT DISTINCT domain FROM domains ORDER BY domain;`)
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
func (p *PostgresDB) ListSubdomains(domain string) ([]string, error) {
	rows, err := p.pool.Query(p.ctx, `
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

// ListSubdomainsWithStatus returns all subdomains with their status codes for a given domain.
func (p *PostgresDB) ListSubdomainsWithStatus(domain string) ([]SubdomainStatus, error) {
	rows, err := p.pool.Query(p.ctx, `
		SELECT s.subdomain, 
		       COALESCE(s.http_url, ''), 
		       COALESCE(s.https_url, ''), 
		       COALESCE(s.http_status, 0), 
		       COALESCE(s.https_status, 0),
		       COALESCE(s.is_live, false)
		FROM subdomains s
		JOIN domains d ON s.domain_id = d.id
		WHERE d.domain = $1
		ORDER BY s.subdomain;
	`, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to query subdomains with status: %v", err)
	}
	defer rows.Close()

	var subs []SubdomainStatus
	for rows.Next() {
		var s SubdomainStatus
		if err := rows.Scan(&s.Subdomain, &s.HTTPURL, &s.HTTPSURL, &s.HTTPStatus, &s.HTTPSStatus, &s.IsLive); err != nil {
			return nil, fmt.Errorf("failed to scan subdomain status: %v", err)
		}
		subs = append(subs, s)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate subdomains: %v", rows.Err())
	}
	return subs, nil
}

// ListLiveSubdomains returns only live subdomains (is_live=true) with their URLs for a given domain.
func (p *PostgresDB) ListLiveSubdomains(domain string) ([]SubdomainStatus, error) {
	rows, err := p.pool.Query(p.ctx, `
		SELECT s.subdomain, 
		       COALESCE(s.http_url, ''), 
		       COALESCE(s.https_url, ''), 
		       COALESCE(s.http_status, 0), 
		       COALESCE(s.https_status, 0),
		       COALESCE(s.is_live, false)
		FROM subdomains s
		JOIN domains d ON s.domain_id = d.id
		WHERE d.domain = $1 AND s.is_live = true
		ORDER BY s.subdomain;
	`, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to query live subdomains: %v", err)
	}
	defer rows.Close()

	var subs []SubdomainStatus
	for rows.Next() {
		var s SubdomainStatus
		if err := rows.Scan(&s.Subdomain, &s.HTTPURL, &s.HTTPSURL, &s.HTTPStatus, &s.HTTPSStatus, &s.IsLive); err != nil {
			return nil, fmt.Errorf("failed to scan live subdomain status: %v", err)
		}
		subs = append(subs, s)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate live subdomains: %v", rows.Err())
	}
	return subs, nil
}

// CountSubdomains returns the count of subdomains for a given domain.
func (p *PostgresDB) CountSubdomains(domain string) (int, error) {
	var count int
	err := p.pool.QueryRow(p.ctx, `
		SELECT COUNT(s.id)
		FROM subdomains s
		JOIN domains d ON s.domain_id = d.id
		WHERE d.domain = $1;
	`, domain).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count subdomains: %v", err)
	}
	return count, nil
}

// DeleteDomain deletes scan history, monitor rows, monitor target, then the domain (cascades subdomains / js_files).
func (p *PostgresDB) DeleteDomain(domain string) error {
	tx, err := p.pool.Begin(p.ctx)
	if err != nil {
		return fmt.Errorf("failed to begin delete domain: %v", err)
	}
	defer tx.Rollback(p.ctx)

	scanMatch := `target = $1 OR (char_length(target) > char_length($1) AND right(target, char_length($1) + 1) = '.' || $1)`
	domainMatch := `domain = $1 OR (char_length(domain) > char_length($1) AND right(domain, char_length($1) + 1) = '.' || $1)`

	if _, err := tx.Exec(p.ctx, `DELETE FROM scan_artifacts WHERE scan_id IN (SELECT scan_id FROM scans WHERE `+scanMatch+`);`, domain); err != nil {
		return fmt.Errorf("failed to delete scan artifacts for domain %s: %v", domain, err)
	}
	if _, err := tx.Exec(p.ctx, `DELETE FROM scans WHERE `+scanMatch+`;`, domain); err != nil {
		return fmt.Errorf("failed to delete scans for domain %s: %v", domain, err)
	}
	if _, err := tx.Exec(p.ctx, `DELETE FROM monitor_changes WHERE `+domainMatch+`;`, domain); err != nil {
		return fmt.Errorf("failed to delete monitor changes for domain %s: %v", domain, err)
	}
	if _, err := tx.Exec(p.ctx, `DELETE FROM subdomain_monitor_targets WHERE domain = $1;`, domain); err != nil {
		return fmt.Errorf("failed to delete subdomain monitor target: %v", err)
	}
	cmdTag, err := tx.Exec(p.ctx, `DELETE FROM domains WHERE domain = $1;`, domain)
	if err != nil {
		return fmt.Errorf("failed to delete domain %s: %v", domain, err)
	}
	if cmdTag.RowsAffected() == 0 {
		return fmt.Errorf("domain not found: %s", domain)
	}
	if err := tx.Commit(p.ctx); err != nil {
		return fmt.Errorf("failed to commit delete domain: %v", err)
	}
	return nil
}

// ListAllScanIDs returns all scan_id values, newest first.
func (p *PostgresDB) ListAllScanIDs() ([]string, error) {
	rows, err := p.pool.Query(p.ctx, `SELECT scan_id FROM scans ORDER BY started_at DESC NULLS LAST, id DESC;`)
	if err != nil {
		return nil, fmt.Errorf("failed to list scan ids: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan scan_id: %v", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ListScanIDsForDomainRoot returns scan IDs for the root domain or hosts under it.
func (p *PostgresDB) ListScanIDsForDomainRoot(domain string) ([]string, error) {
	q := `
		SELECT scan_id FROM scans
		WHERE target = $1
		   OR (char_length(target) > char_length($1) AND right(target, char_length($1) + 1) = '.' || $1)
		ORDER BY started_at DESC NULLS LAST, id DESC;
	`
	rows, err := p.pool.Query(p.ctx, q, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to list scans for domain: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan scan_id: %v", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ListMonitorTargets returns all monitoring targets
func (p *PostgresDB) ListMonitorTargets() ([]MonitorTarget, error) {
	rows, err := p.pool.Query(p.ctx, `
		SELECT id, url, strategy, COALESCE(pattern, '') AS pattern, is_running,
		       COALESCE(last_hash, '') AS last_hash, last_run_at, COALESCE(change_count, 0) AS change_count,
		       created_at, updated_at
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
		if err := rows.Scan(&t.ID, &t.URL, &t.Strategy, &t.Pattern, &t.IsRunning,
			&t.LastHash, &t.LastRunAt, &t.ChangeCount, &t.CreatedAt, &t.UpdatedAt); err != nil {
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
func (p *PostgresDB) AddMonitorTarget(url, strategy, pattern string) error {
	_, err := p.pool.Exec(p.ctx, `
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
func (p *PostgresDB) RemoveMonitorTarget(url string) error {
	cmdTag, err := p.pool.Exec(p.ctx, `DELETE FROM updates_targets WHERE url = $1;`, url)
	if err != nil {
		return fmt.Errorf("failed to remove monitor target: %v", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return fmt.Errorf("monitor target not found: %s", url)
	}
	return nil
}

// SetMonitorRunningStatus updates the running status of a monitor target
func (p *PostgresDB) SetMonitorRunningStatus(id int, isRunning bool) error {
	_, err := p.pool.Exec(p.ctx, `
		UPDATE updates_targets 
		SET is_running = $1, updated_at = NOW()
		WHERE id = $2;
	`, isRunning, id)
	if err != nil {
		return fmt.Errorf("failed to update monitor running status: %v", err)
	}
	return nil
}

// GetMonitorTargetByID returns a single monitor target by ID.
func (p *PostgresDB) GetMonitorTargetByID(id int) (*MonitorTarget, error) {
	var t MonitorTarget
	err := p.pool.QueryRow(p.ctx, `
		SELECT id, url, strategy, COALESCE(pattern, '') AS pattern, is_running,
		       COALESCE(last_hash, '') AS last_hash, last_run_at, COALESCE(change_count, 0) AS change_count,
		       created_at, updated_at
		FROM updates_targets
		WHERE id = $1;
	`, id).Scan(&t.ID, &t.URL, &t.Strategy, &t.Pattern, &t.IsRunning,
		&t.LastHash, &t.LastRunAt, &t.ChangeCount, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("monitor target not found with id: %d", id)
		}
		return nil, fmt.Errorf("failed to get monitor target by id: %v", err)
	}
	return &t, nil
}

// ListSubdomainMonitorTargets returns all subdomain monitoring targets
func (p *PostgresDB) ListSubdomainMonitorTargets() ([]SubdomainMonitorTarget, error) {
	rows, err := p.pool.Query(p.ctx, `
		SELECT id, domain, interval_seconds, threads, check_new, is_running, last_run_at, created_at, updated_at
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
		if err := rows.Scan(&t.ID, &t.Domain, &t.Interval, &t.Threads, &t.CheckNew, &t.IsRunning, &t.LastRunAt, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan subdomain monitor target: %v", err)
		}
		targets = append(targets, t)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate subdomain monitor targets: %v", rows.Err())
	}
	return targets, nil
}

// AddSubdomainMonitorTarget adds a new subdomain monitoring target
func (p *PostgresDB) AddSubdomainMonitorTarget(domain string, interval int, threads int, checkNew bool) error {
	if interval <= 0 {
		interval = 3600 // Default 1 hour
	}
	if threads <= 0 {
		threads = 100
	}
	_, err := p.pool.Exec(p.ctx, `
		INSERT INTO subdomain_monitor_targets (domain, interval_seconds, threads, check_new)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (domain) DO UPDATE SET
			interval_seconds = EXCLUDED.interval_seconds,
			threads = EXCLUDED.threads,
			check_new = EXCLUDED.check_new,
			updated_at = NOW();
	`, domain, interval, threads, checkNew)

	if err != nil {
		return fmt.Errorf("failed to add subdomain monitor target: %v", err)
	}
	return nil
}

// RemoveSubdomainMonitorTarget removes a subdomain monitoring target by domain
func (p *PostgresDB) RemoveSubdomainMonitorTarget(domain string) error {
	cmdTag, err := p.pool.Exec(p.ctx, `DELETE FROM subdomain_monitor_targets WHERE domain = $1;`, domain)
	if err != nil {
		return fmt.Errorf("failed to remove subdomain monitor target: %v", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return fmt.Errorf("subdomain monitor target not found: %s", domain)
	}
	return nil
}

// SetSubdomainMonitorRunningStatus updates the running status of a subdomain monitor target
func (p *PostgresDB) SetSubdomainMonitorRunningStatus(id int, isRunning bool) error {
	_, err := p.pool.Exec(p.ctx, `
		UPDATE subdomain_monitor_targets 
		SET is_running = $1, updated_at = NOW()
		WHERE id = $2;
	`, isRunning, id)
	if err != nil {
		return fmt.Errorf("failed to update subdomain monitor running status: %v", err)
	}
	return nil
}

// GetSubdomainMonitorTargetByID returns a single subdomain monitor target by ID
func (p *PostgresDB) GetSubdomainMonitorTargetByID(id int) (*SubdomainMonitorTarget, error) {
	var t SubdomainMonitorTarget
	err := p.pool.QueryRow(p.ctx, `
		SELECT id, domain, interval_seconds, threads, check_new, is_running, last_run_at, created_at, updated_at
		FROM subdomain_monitor_targets
		WHERE id = $1;
	`, id).Scan(&t.ID, &t.Domain, &t.Interval, &t.Threads, &t.CheckNew, &t.IsRunning, &t.LastRunAt, &t.CreatedAt, &t.UpdatedAt)

	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("subdomain monitor target not found with id: %d", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get subdomain monitor target by id: %v", err)
	}
	return &t, nil
}

// UpdateSubdomainMonitorLastRun updates last_run_at to now for a subdomain monitor target
func (p *PostgresDB) UpdateSubdomainMonitorLastRun(id int) error {
	_, err := p.pool.Exec(p.ctx, `
		UPDATE subdomain_monitor_targets
		SET last_run_at = NOW()
		WHERE id = $1;
	`, id)
	if err != nil {
		return fmt.Errorf("failed to update subdomain monitor last_run_at: %v", err)
	}
	return nil
}

// UpdateMonitorTargetLastRun updates last_hash, last_run_at, and optionally increments change_count
func (p *PostgresDB) UpdateMonitorTargetLastRun(id int, hash string, changed bool) error {
	_, err := p.pool.Exec(p.ctx, `
		UPDATE updates_targets
		SET last_hash = $1,
		    last_run_at = NOW(),
		    change_count = CASE WHEN $2 THEN change_count + 1 ELSE change_count END
		WHERE id = $3;
	`, hash, changed, id)
	if err != nil {
		return fmt.Errorf("failed to update monitor target last run: %v", err)
	}
	return nil
}

// InsertMonitorChange records a detected change in the monitor_changes table
func (p *PostgresDB) InsertMonitorChange(change *MonitorChange) error {
	_, err := p.pool.Exec(p.ctx, `
		INSERT INTO monitor_changes (target_type, target_id, domain, change_type, detail, notified)
		VALUES ($1, $2, $3, $4, $5, $6);
	`, change.TargetType, change.TargetID, change.Domain, change.ChangeType, change.Detail, change.Notified)
	if err != nil {
		return fmt.Errorf("failed to insert monitor change: %v", err)
	}
	return nil
}

// ClearMonitorChanges deletes all monitor change rows and resets URL monitor change_count.
func (p *PostgresDB) ClearMonitorChanges() error {
	tx, err := p.pool.Begin(p.ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(p.ctx)
	if _, err := tx.Exec(p.ctx, `DELETE FROM monitor_changes;`); err != nil {
		return fmt.Errorf("clear monitor_changes: %w", err)
	}
	if _, err := tx.Exec(p.ctx, `UPDATE updates_targets SET change_count = 0;`); err != nil {
		return fmt.Errorf("reset change_count: %w", err)
	}
	if err := tx.Commit(p.ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// ListMonitorChanges lists recent monitor changes, optionally filtered by domain
func (p *PostgresDB) ListMonitorChanges(domain string, limit int) ([]MonitorChange, error) {
	if limit <= 0 {
		limit = 100
	}
	var rows interface{ Close() }
	var err error
	var query string
	var args []interface{}

	if domain != "" {
		query = `SELECT id, target_type, target_id, domain, change_type, COALESCE(detail,'') as detail, detected_at, notified
				 FROM monitor_changes WHERE domain = $1 ORDER BY detected_at DESC LIMIT $2;`
		args = []interface{}{domain, limit}
	} else {
		query = `SELECT id, target_type, target_id, domain, change_type, COALESCE(detail,'') as detail, detected_at, notified
				 FROM monitor_changes ORDER BY detected_at DESC LIMIT $1;`
		args = []interface{}{limit}
	}

	pgRows, pgErr := p.pool.Query(p.ctx, query, args...)
	if pgErr != nil {
		return nil, fmt.Errorf("failed to query monitor changes: %v", pgErr)
	}
	rows = pgRows
	defer pgRows.Close()

	var changes []MonitorChange
	for pgRows.Next() {
		var c MonitorChange
		if err = pgRows.Scan(&c.ID, &c.TargetType, &c.TargetID, &c.Domain, &c.ChangeType, &c.Detail, &c.DetectedAt, &c.Notified); err != nil {
			return nil, fmt.Errorf("failed to scan monitor change: %v", err)
		}
		changes = append(changes, c)
	}
	_ = rows
	if pgRows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate monitor changes: %v", pgRows.Err())
	}
	return changes, nil
}

// CreateScan creates a new scan record
func (p *PostgresDB) CreateScan(scan *ScanRecord) error {
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
	
	_, err := p.pool.Exec(p.ctx, `
		INSERT INTO scans (
			scan_id, scan_type, target, status, channel_id, thread_id, message_id,
			current_phase, total_phases, phase_name, phase_start_time,
			completed_phases, failed_phases, files_uploaded, error_count,
			started_at, last_update, command, result_url
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19);
	`, scan.ScanID, scan.ScanType, scan.Target, scan.Status, scan.ChannelID, scan.ThreadID, scan.MessageID,
		scan.CurrentPhase, scan.TotalPhases, scan.PhaseName, scan.PhaseStartTime,
		completedPhasesJSON, failedPhasesJSON, scan.FilesUploaded, scan.ErrorCount,
		scan.StartedAt, scan.LastUpdate, scan.Command, scan.ResultURL)
	
	if err != nil {
		return fmt.Errorf("failed to create scan: %v", err)
	}
	return nil
}

// UpdateScanProgress updates scan progress
func (p *PostgresDB) UpdateScanProgress(scanID string, progress *ScanProgress) error {
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
	
	_, err := p.pool.Exec(p.ctx, `
		UPDATE scans SET
			current_phase = $1,
			total_phases = $2,
			phase_name = $3,
			phase_start_time = $4,
			completed_phases = $5,
			failed_phases = $6,
			files_uploaded = $7,
			error_count = $8,
			last_update = $9,
			updated_at = NOW()
		WHERE scan_id = $10;
	`, progress.CurrentPhase, progress.TotalPhases, progress.PhaseName, progress.PhaseStartTime,
		completedPhasesJSON, failedPhasesJSON, progress.FilesUploaded, progress.ErrorCount,
		time.Now(), scanID)
	
	if err != nil {
		return fmt.Errorf("failed to update scan progress: %v", err)
	}
	return nil
}

// UpdateScanResult updates scan status and result URL
func (p *PostgresDB) UpdateScanResult(scanID, status, resultURL string) error {
	now := time.Now()
	_, err := p.pool.Exec(p.ctx, `
		UPDATE scans SET
			status = $1,
			result_url = $2,
			completed_at = $3,
			last_update = $4,
			updated_at = NOW()
		WHERE scan_id = $5;
	`, status, resultURL, now, now, scanID)
	
	if err != nil {
		return fmt.Errorf("failed to update scan result: %v", err)
	}
	return nil
}

// UpdateScanStatus updates scan status
func (p *PostgresDB) UpdateScanStatus(scanID string, status string) error {
	now := time.Now()
	var err error
	
	if status == "completed" || status == "failed" || status == "cancelled" {
		_, err = p.pool.Exec(p.ctx, `
			UPDATE scans SET
				status = $1,
				completed_at = $2,
				last_update = $3,
				updated_at = NOW()
			WHERE scan_id = $4;
		`, status, now, now, scanID)
	} else {
		_, err = p.pool.Exec(p.ctx, `
			UPDATE scans SET
				status = $1,
				last_update = $2,
				updated_at = NOW()
			WHERE scan_id = $3;
		`, status, now, scanID)
	}
	
	if err != nil {
		return fmt.Errorf("failed to update scan status: %v", err)
	}
	return nil
}

// GetScan retrieves a scan by ID
func (p *PostgresDB) GetScan(scanID string) (*ScanRecord, error) {
	var scan ScanRecord
	var completedPhasesJSON, failedPhasesJSON []byte
	var phaseStartTime, completedAt *time.Time

	err := p.pool.QueryRow(p.ctx, `
		SELECT id, scan_id, scan_type, target, status, 
			COALESCE(channel_id, ''), COALESCE(thread_id, ''), COALESCE(message_id, ''),
			current_phase, total_phases, COALESCE(phase_name, ''), phase_start_time,
			COALESCE(completed_phases, '[]'::jsonb), COALESCE(failed_phases, '[]'::jsonb),
			files_uploaded, error_count, started_at, completed_at, last_update, 
			COALESCE(command, ''), COALESCE(result_url, '')
		FROM scans WHERE scan_id = $1;
	`, scanID).Scan(
		&scan.ID, &scan.ScanID, &scan.ScanType, &scan.Target, &scan.Status,
		&scan.ChannelID, &scan.ThreadID, &scan.MessageID,
		&scan.CurrentPhase, &scan.TotalPhases, &scan.PhaseName, &phaseStartTime,
		&completedPhasesJSON, &failedPhasesJSON,
		&scan.FilesUploaded, &scan.ErrorCount, &scan.StartedAt, &completedAt, &scan.LastUpdate, &scan.Command, &scan.ResultURL)
	
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("scan not found: %s", scanID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get scan: %v", err)
	}
	
	scan.PhaseStartTime = phaseStartTime
	scan.CompletedAt = completedAt
	
	// Unmarshal JSON arrays
	if len(completedPhasesJSON) > 0 {
		json.Unmarshal(completedPhasesJSON, &scan.CompletedPhases)
	}
	if len(failedPhasesJSON) > 0 {
		json.Unmarshal(failedPhasesJSON, &scan.FailedPhases)
	}
	
	return &scan, nil
}

// ListActiveScans lists all active scans
func (p *PostgresDB) ListActiveScans() ([]*ScanRecord, error) {
	rows, err := p.pool.Query(p.ctx, `
		SELECT id, scan_id, scan_type, target, status,
			COALESCE(channel_id, ''), COALESCE(thread_id, ''), COALESCE(message_id, ''),
			current_phase, total_phases, COALESCE(phase_name, ''), phase_start_time,
			COALESCE(completed_phases, '[]'::jsonb), COALESCE(failed_phases, '[]'::jsonb),
			files_uploaded, error_count, started_at, completed_at, last_update, COALESCE(command, ''), COALESCE(result_url, '')
		FROM scans
		WHERE status IN ('running', 'starting', 'paused')
		ORDER BY started_at DESC;
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to list active scans: %v", err)
	}
	defer rows.Close()
	
	var scans []*ScanRecord
	for rows.Next() {
		var scan ScanRecord
		var completedPhasesJSON, failedPhasesJSON []byte
		var phaseStartTime, completedAt *time.Time
		
		err := rows.Scan(
			&scan.ID, &scan.ScanID, &scan.ScanType, &scan.Target, &scan.Status,
			&scan.ChannelID, &scan.ThreadID, &scan.MessageID,
			&scan.CurrentPhase, &scan.TotalPhases, &scan.PhaseName, &phaseStartTime,
			&completedPhasesJSON, &failedPhasesJSON,
			&scan.FilesUploaded, &scan.ErrorCount, &scan.StartedAt, &completedAt, &scan.LastUpdate, &scan.Command, &scan.ResultURL)
		
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %v", err)
		}
		
		scan.PhaseStartTime = phaseStartTime
		scan.CompletedAt = completedAt
		
		// Unmarshal JSON arrays
		if len(completedPhasesJSON) > 0 {
			json.Unmarshal(completedPhasesJSON, &scan.CompletedPhases)
		}
		if len(failedPhasesJSON) > 0 {
			json.Unmarshal(failedPhasesJSON, &scan.FailedPhases)
		}
		
		scans = append(scans, &scan)
	}
	
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate scans: %v", rows.Err())
	}
	return scans, nil
}

// FailStaleActiveScans sets non-terminal scans to failed — workers are gone after process restart.
func (p *PostgresDB) FailStaleActiveScans() (int64, error) {
	now := time.Now()
	tag, err := p.pool.Exec(p.ctx, `
		UPDATE scans SET
			status = 'failed',
			completed_at = $1,
			last_update = $1,
			updated_at = NOW()
		WHERE status IN ('running', 'starting', 'paused', 'cancelling');
	`, now)
	if err != nil {
		return 0, fmt.Errorf("failed to fail stale scans: %v", err)
	}
	return tag.RowsAffected(), nil
}

// ListRecentScans lists recent scans (completed, failed, cancelled)
func (p *PostgresDB) ListRecentScans(limit int) ([]*ScanRecord, error) {
	rows, err := p.pool.Query(p.ctx, `
		SELECT id, scan_id, scan_type, target, status,
			COALESCE(channel_id, ''), COALESCE(thread_id, ''), COALESCE(message_id, ''),
			current_phase, total_phases, COALESCE(phase_name, ''), phase_start_time,
			COALESCE(completed_phases, '[]'::jsonb), COALESCE(failed_phases, '[]'::jsonb),
			files_uploaded, error_count, started_at, completed_at, last_update, COALESCE(command, ''), COALESCE(result_url, '')
		FROM scans
		WHERE status IN ('completed', 'failed', 'cancelled')
		ORDER BY started_at DESC
		LIMIT $1;
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list recent scans: %v", err)
	}
	defer rows.Close()
	
	var scans []*ScanRecord
	for rows.Next() {
		var scan ScanRecord
		var completedPhasesJSON, failedPhasesJSON []byte
		var phaseStartTime, completedAt *time.Time
		
		err := rows.Scan(
			&scan.ID, &scan.ScanID, &scan.ScanType, &scan.Target, &scan.Status,
			&scan.ChannelID, &scan.ThreadID, &scan.MessageID,
			&scan.CurrentPhase, &scan.TotalPhases, &scan.PhaseName, &phaseStartTime,
			&completedPhasesJSON, &failedPhasesJSON,
			&scan.FilesUploaded, &scan.ErrorCount, &scan.StartedAt, &completedAt, &scan.LastUpdate, &scan.Command, &scan.ResultURL)
		
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %v", err)
		}
		
		scan.PhaseStartTime = phaseStartTime
		scan.CompletedAt = completedAt
		
		// Unmarshal JSON arrays
		if len(completedPhasesJSON) > 0 {
			json.Unmarshal(completedPhasesJSON, &scan.CompletedPhases)
		}
		if len(failedPhasesJSON) > 0 {
			json.Unmarshal(failedPhasesJSON, &scan.FailedPhases)
		}
		
		scans = append(scans, &scan)
	}
	
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate scans: %v", rows.Err())
	}
	return scans, nil
}

// AppendScanArtifact stores a scan output artifact.
func (p *PostgresDB) AppendScanArtifact(artifact *ScanArtifact) error {
	if artifact == nil {
		return fmt.Errorf("artifact is nil")
	}
	_, err := p.pool.Exec(p.ctx, `
		INSERT INTO scan_artifacts (
			scan_id, file_name, local_path, r2_key, public_url, size_bytes, line_count, content_type, module, category
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (scan_id, r2_key) DO UPDATE SET
			file_name=EXCLUDED.file_name,
			local_path=EXCLUDED.local_path,
			public_url=EXCLUDED.public_url,
			size_bytes=EXCLUDED.size_bytes,
			line_count=EXCLUDED.line_count,
			content_type=EXCLUDED.content_type,
			module=EXCLUDED.module,
			category=EXCLUDED.category,
			created_at=NOW()
	`, artifact.ScanID, artifact.FileName, artifact.LocalPath, artifact.R2Key, artifact.PublicURL, artifact.SizeBytes, artifact.LineCount, artifact.ContentType, artifact.Module, artifact.Category)
	if err != nil {
		return fmt.Errorf("failed to append scan artifact: %v", err)
	}
	return nil
}

// ListScanArtifacts returns artifacts for a scan, newest first.
func (p *PostgresDB) ListScanArtifacts(scanID string) ([]*ScanArtifact, error) {
	rows, err := p.pool.Query(p.ctx, `
		SELECT id, scan_id, COALESCE(file_name, ''), COALESCE(local_path, ''), COALESCE(r2_key, ''),
			COALESCE(public_url, ''), COALESCE(size_bytes, 0), COALESCE(line_count, 0),
			COALESCE(content_type, ''), COALESCE(module, ''), COALESCE(category, ''), created_at
		FROM scan_artifacts
		WHERE scan_id = $1
		ORDER BY created_at DESC, id DESC
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to list scan artifacts: %v", err)
	}
	defer rows.Close()

	var out []*ScanArtifact
	for rows.Next() {
		var a ScanArtifact
		if err := rows.Scan(&a.ID, &a.ScanID, &a.FileName, &a.LocalPath, &a.R2Key, &a.PublicURL, &a.SizeBytes, &a.LineCount, &a.ContentType, &a.Module, &a.Category, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan artifact row: %v", err)
		}
		out = append(out, &a)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate scan artifacts: %v", rows.Err())
	}
	return out, nil
}

// DeleteScan deletes a scan record
func (p *PostgresDB) DeleteScan(scanID string) error {
	tx, err := p.pool.Begin(p.ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback(p.ctx)

	if _, err := tx.Exec(p.ctx, `DELETE FROM scan_artifacts WHERE scan_id = $1;`, scanID); err != nil {
		return fmt.Errorf("failed to delete scan artifacts: %v", err)
	}
	if _, err := tx.Exec(p.ctx, `DELETE FROM scans WHERE scan_id = $1;`, scanID); err != nil {
		return fmt.Errorf("failed to delete scan: %v", err)
	}
	if err := tx.Commit(p.ctx); err != nil {
		return fmt.Errorf("failed to commit delete scan: %v", err)
	}
	return nil
}

// CountScansWithTargetExcluding returns how many scans share this target besides excludeScanID.
func (p *PostgresDB) CountScansWithTargetExcluding(excludeScanID, target string) (int, error) {
	var n int
	err := p.pool.QueryRow(p.ctx,
		`SELECT COUNT(*)::int FROM scans WHERE target = $1 AND scan_id != $2`,
		target, excludeScanID,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count scans by target: %v", err)
	}
	return n, nil
}

// ListVulnerableDNSProviders returns all vulnerable DNS providers from the database
func (p *PostgresDB) ListVulnerableDNSProviders() (map[string]string, error) {
	rows, err := p.pool.Query(p.ctx, `
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

// AddVulnerableDNSProvider adds or updates a vulnerable DNS provider
func (p *PostgresDB) AddVulnerableDNSProvider(name, fingerprint string) error {
	_, err := p.pool.Exec(p.ctx, `
		INSERT INTO dns_takeover_providers (name, fingerprint)
		VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE SET
			fingerprint = EXCLUDED.fingerprint,
			updated_at = NOW();
	`, name, fingerprint)
	if err != nil {
		return fmt.Errorf("failed to add dns provider: %v", err)
	}
	return nil
}

// Close closes the database connection pool
func (p *PostgresDB) Close() {
	if p.pool != nil {
		p.pool.Close()
	}
}

