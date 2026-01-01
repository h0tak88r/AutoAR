package db

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/v3/internal/modules/r2storage"
)

// BackupDatabase creates a backup of the database and optionally uploads to R2
func BackupDatabase(uploadToR2 bool) (string, string, error) {
	dbType := getEnv("DB_TYPE", "postgresql")
	
	var backupPath string
	var err error

	switch strings.ToLower(dbType) {
	case "sqlite", "sqlite3":
		backupPath, err = backupSQLite()
	case "postgresql", "postgres":
		backupPath, err = backupPostgreSQL()
	default:
		return "", "", fmt.Errorf("unsupported database type: %s", dbType)
	}

	if err != nil {
		return "", "", fmt.Errorf("failed to create database backup: %w", err)
	}

	var r2URL string
	if uploadToR2 && r2storage.IsEnabled() {
		log.Printf("[DB] Uploading database backup to R2...")
		r2URL, err = r2storage.UploadDatabaseBackup(backupPath, dbType)
		if err != nil {
			log.Printf("[DB] ⚠️  Failed to upload backup to R2: %v", err)
			// Don't fail the backup if R2 upload fails
		} else {
			log.Printf("[DB] ✅ Database backup uploaded to R2: %s", r2URL)
		}
	}

	return backupPath, r2URL, nil
}

// backupSQLite creates a backup of SQLite database
func backupSQLite() (string, error) {
	dbPath := getEnv("DB_HOST", "./bughunt.db")
	
	// Expand user home directory if path starts with ~
	if strings.HasPrefix(dbPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get home directory: %v", err)
		}
		dbPath = filepath.Join(home, dbPath[2:])
	}

	// Check if database file exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return "", fmt.Errorf("database file not found: %s", dbPath)
	}

	// Create backup directory
	backupDir := filepath.Join(filepath.Dir(dbPath), "backups")
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Create backup filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("bughunt-%s.db", timestamp))

	// Copy database file
	sourceFile, err := os.Open(dbPath)
	if err != nil {
		return "", fmt.Errorf("failed to open database file: %w", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(backupPath)
	if err != nil {
		return "", fmt.Errorf("failed to create backup file: %w", err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return "", fmt.Errorf("failed to copy database file: %w", err)
	}

	log.Printf("[DB] ✅ SQLite backup created: %s", backupPath)
	return backupPath, nil
}

// backupPostgreSQL creates a backup of PostgreSQL database using pg_dump
func backupPostgreSQL() (string, error) {
	// Get database connection details
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "5432")
	dbUser := getEnv("DB_USER", "postgres")
	dbPassword := getEnv("DB_PASSWORD", "")
	dbName := getEnv("DB_NAME", "bughunt")

	// Check if pg_dump is available
	pgDumpPath, err := exec.LookPath("pg_dump")
	if err != nil {
		return "", fmt.Errorf("pg_dump not found. Please install PostgreSQL client tools")
	}

	// Create backup directory
	backupDir := "./backups"
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Create backup filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("bughunt-%s.sql", timestamp))

	// Build pg_dump command
	// Set PGPASSWORD environment variable for password authentication
	cmd := exec.Command(pgDumpPath,
		"-h", dbHost,
		"-p", dbPort,
		"-U", dbUser,
		"-d", dbName,
		"-F", "c", // Custom format (compressed)
		"-f", backupPath,
	)

	// Set PGPASSWORD if provided
	if dbPassword != "" {
		cmd.Env = append(os.Environ(), fmt.Sprintf("PGPASSWORD=%s", dbPassword))
	}

	// Run pg_dump
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("pg_dump failed: %w (output: %s)", err, string(output))
	}

	// Check if backup file was created
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return "", fmt.Errorf("backup file was not created")
	}

	log.Printf("[DB] ✅ PostgreSQL backup created: %s", backupPath)
	return backupPath, nil
}

