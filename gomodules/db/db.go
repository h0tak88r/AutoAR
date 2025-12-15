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
	CREATE TABLE IF NOT EXISTS domains (
		id SERIAL PRIMARY KEY,
		domain VARCHAR(255) UNIQUE NOT NULL,
		created_at TIMESTAMP DEFAULT NOW()
	);
	
	-- Add updated_at column if it doesn't exist (for backward compatibility)
	DO $$ 
	BEGIN
		IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='domains' AND column_name='updated_at') THEN
			ALTER TABLE domains ADD COLUMN updated_at TIMESTAMP DEFAULT NOW();
		END IF;
	END $$;
	
	CREATE TABLE IF NOT EXISTS subdomains (
		id SERIAL PRIMARY KEY,
		domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
		subdomain VARCHAR(255) UNIQUE NOT NULL,
		is_live BOOLEAN DEFAULT FALSE,
		http_url VARCHAR(512),
		https_url VARCHAR(512),
		http_status INTEGER,
		https_status INTEGER,
		created_at TIMESTAMP DEFAULT NOW(),
		updated_at TIMESTAMP DEFAULT NOW()
	);
	
	CREATE TABLE IF NOT EXISTS js_files (
		id SERIAL PRIMARY KEY,
		subdomain_id INTEGER REFERENCES subdomains(id) ON DELETE CASCADE,
		js_url VARCHAR(1024) UNIQUE NOT NULL,
		content_hash VARCHAR(64),
		last_scanned TIMESTAMP,
		created_at TIMESTAMP DEFAULT NOW(),
		updated_at TIMESTAMP DEFAULT NOW()
	);
	
	CREATE TABLE IF NOT EXISTS keyhack_templates (
		id SERIAL PRIMARY KEY,
		keyname VARCHAR(255) UNIQUE NOT NULL,
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
	
	CREATE INDEX IF NOT EXISTS idx_subdomains_domain_id ON subdomains(domain_id);
	CREATE INDEX IF NOT EXISTS idx_subdomains_is_live ON subdomains(is_live);
	CREATE INDEX IF NOT EXISTS idx_js_files_subdomain_id ON js_files(subdomain_id);
	CREATE INDEX IF NOT EXISTS idx_keyhack_templates_keyname ON keyhack_templates(keyname);
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
	
	var domainID int
	
	// Try to insert, on conflict get existing
	err := dbPool.QueryRow(ctx, `
		INSERT INTO domains (domain) 
		VALUES ($1) 
		ON CONFLICT (domain) DO NOTHING 
		RETURNING id;
	`, domain).Scan(&domainID)
	
	if err == pgx.ErrNoRows {
		// Domain already exists, get its ID
		err = dbPool.QueryRow(ctx, `
			SELECT id FROM domains WHERE domain = $1 LIMIT 1;
		`, domain).Scan(&domainID)
	}
	
	if err != nil {
		if err == pgx.ErrNoRows {
			// Try one more time with SELECT
			err = dbPool.QueryRow(ctx, `
				SELECT id FROM domains WHERE domain = $1 LIMIT 1;
			`, domain).Scan(&domainID)
		}
		if err != nil {
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
	
	_, err = tx.Prepare(ctx, "batch_insert_subdomains", `
		INSERT INTO subdomains (domain_id, subdomain, is_live, http_url, https_url, http_status, https_status)
		VALUES ($1, $2, $3, '', '', 0, 0)
		ON CONFLICT (subdomain) DO UPDATE SET updated_at = $4;
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
			content_hash = $3,
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
			command_template = $2,
			method = $3,
			url = $4,
			header = $5,
			body = $6,
			description = $7,
			notes = $8,
			updated_at = NOW();
	`, keyname, commandTemplate, method, url, header, body, description, notes)
	
	if err != nil {
		return fmt.Errorf("failed to insert/update keyhack template: %v", err)
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
