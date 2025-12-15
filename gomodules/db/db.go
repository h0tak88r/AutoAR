package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
)

var (
	dbConn   *sql.DB
	dbType   string
	dbHost   string
	dbPort   string
	dbUser   string
	dbPass   string
	dbName   string
)

// Init initializes the database connection
func Init() error {
	dbType = getEnv("DB_TYPE", "postgresql")
	
	if dbType == "postgresql" {
		// Parse PostgreSQL connection string if provided
		dbHostEnv := os.Getenv("DB_HOST")
		if strings.HasPrefix(dbHostEnv, "postgresql://") || strings.HasPrefix(dbHostEnv, "postgres://") {
			// Parse connection string: postgresql://user:password@host:port/database
			connStr := dbHostEnv
			var err error
			dbConn, err = sql.Open("postgres", connStr)
			if err != nil {
				return fmt.Errorf("failed to parse PostgreSQL connection string: %v", err)
			}
		} else {
			// Use individual environment variables
			dbHost = getEnv("DB_HOST", "localhost")
			dbPort = getEnv("DB_PORT", "5432")
			dbUser = getEnv("DB_USER", "autoar")
			dbPass = os.Getenv("DB_PASSWORD")
			dbName = getEnv("DB_NAME", "autoar")
			
			connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
				dbHost, dbPort, dbUser, dbPass, dbName)
			var err error
			dbConn, err = sql.Open("postgres", connStr)
			if err != nil {
				return fmt.Errorf("failed to connect to PostgreSQL: %v", err)
			}
		}
		
		// Test connection
		if err := dbConn.Ping(); err != nil {
			return fmt.Errorf("failed to ping database: %v", err)
		}
		log.Printf("[INFO] Connected to PostgreSQL database")
	}
	
	return nil
}

// InitSchema initializes the database schema
func InitSchema() error {
	if dbConn == nil {
		if err := Init(); err != nil {
			return err
		}
	}
	
	if dbType == "postgresql" {
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
		
		_, err := dbConn.Exec(schema)
		if err != nil {
			return fmt.Errorf("failed to create schema: %v", err)
		}
		log.Printf("[OK] Database schema initialized")
	}
	
	return nil
}

// InsertOrGetDomain inserts a domain or returns existing domain ID
func InsertOrGetDomain(domain string) (int, error) {
	if dbConn == nil {
		if err := Init(); err != nil {
			return 0, err
		}
	}
	
	var domainID int
	
	// Try to insert, on conflict get existing
	err := dbConn.QueryRow(`
		INSERT INTO domains (domain) 
		VALUES ($1) 
		ON CONFLICT (domain) DO NOTHING 
		RETURNING id;
	`, domain).Scan(&domainID)
	
	if err == sql.ErrNoRows {
		// Domain already exists, get its ID
		err = dbConn.QueryRow(`
			SELECT id FROM domains WHERE domain = $1 LIMIT 1;
		`, domain).Scan(&domainID)
	}
	
	if err != nil {
		if err == sql.ErrNoRows {
			// Try one more time with SELECT
			err = dbConn.QueryRow(`
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
	if dbConn == nil {
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
	tx, err := dbConn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()
	
	stmt, err := tx.Prepare(`
		INSERT INTO subdomains (domain_id, subdomain, is_live, http_url, https_url, http_status, https_status)
		VALUES ($1, $2, $3, '', '', 0, 0)
		ON CONFLICT (subdomain) DO UPDATE SET updated_at = $4;
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %v", err)
	}
	defer stmt.Close()
	
	count := 0
	for _, subdomain := range subdomains {
		subdomain = strings.TrimSpace(subdomain)
		if subdomain == "" {
			continue
		}
		
		_, err := stmt.Exec(domainID, subdomain, isLive, time.Now())
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
func InsertSubdomain(domain, subdomain string, isLive bool, httpURL, httpsURL string, httpStatus, httpsStatus int) error {
	if dbConn == nil {
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
	err = dbConn.QueryRow(`
		SELECT id FROM subdomains WHERE domain_id = $1 AND subdomain = $2 LIMIT 1;
	`, domainID, subdomain).Scan(&existingID)
	
	if err == sql.ErrNoRows {
		// Insert new subdomain
		_, err = dbConn.Exec(`
			INSERT INTO subdomains (domain_id, subdomain, is_live, http_url, https_url, http_status, https_status)
			VALUES ($1, $2, $3, $4, $5, $6, $7);
		`, domainID, subdomain, isLive, httpURL, httpsURL, httpStatus, httpsStatus)
	} else if err == nil {
		// Update existing subdomain
		_, err = dbConn.Exec(`
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

// GetConnection returns the database connection (for advanced use)
func GetConnection() *sql.DB {
	return dbConn
}

// Close closes the database connection
func Close() error {
	if dbConn != nil {
		return dbConn.Close()
	}
	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
