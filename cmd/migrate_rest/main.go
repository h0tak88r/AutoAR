package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

var (
	SupabaseURL = os.Getenv("SUPABASE_URL")
	SupabaseKey = os.Getenv("SUPABASE_KEY")
)

func postChunk(table string, records []map[string]interface{}) error {
	if len(records) == 0 {
		return nil
	}

	url := fmt.Sprintf("%s/rest/v1/%s", SupabaseURL, table)
	
	jsonData, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("apikey", SupabaseKey)
	req.Header.Set("Authorization", "Bearer "+SupabaseKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Prefer", "resolution=merge-duplicates")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

func nullStr(ns sql.NullString) interface{} {
	if ns.Valid && ns.String != "" {
		return ns.String
	}
	return nil
}

func nullInt(ni sql.NullInt64) interface{} {
	if ni.Valid {
		return ni.Int64
	}
	return nil
}

func main() {
	if SupabaseURL == "" || SupabaseKey == "" {
		log.Fatal("ERROR: Please set SUPABASE_URL and SUPABASE_KEY (service_role tier) environment variables.")
	}

	sqliteDB, err := sql.Open("sqlite", "./bughunt.db?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)")
	if err != nil {
		log.Fatalf("Failed to open SQLite: %v", err)
	}
	defer sqliteDB.Close()

	const batchSize = 1000

	// 1. DOMAINS (Skip, likely already migrated)
	// But let's re-run it since merge-duplicates handles it.
	fmt.Println("[*] Migrating domains...")
	rows, _ := sqliteDB.Query(`SELECT id, domain, created_at, updated_at FROM domains`)
	var domainBatch []map[string]interface{}
	totalDomains := 0

	for rows.Next() {
		var id int
		var domain string
		var ca, ua sql.NullString
		rows.Scan(&id, &domain, &ca, &ua)

		domainBatch = append(domainBatch, map[string]interface{}{
			"id":         id,
			"domain":     domain,
			"created_at": nullStr(ca),
			"updated_at": nullStr(ua),
		})
		
		if len(domainBatch) >= batchSize {
			if err := postChunk("domains", domainBatch); err != nil {
				log.Fatalf("Failed to post domain chunk: %v", err)
			}
			totalDomains += len(domainBatch)
			domainBatch = nil
		}
	}
	if len(domainBatch) > 0 {
		if err := postChunk("domains", domainBatch); err != nil {
			log.Fatalf("Failed to post final domain chunk: %v", err)
		}
		totalDomains += len(domainBatch)
	}
	rows.Close()
	fmt.Printf("[+] Uploaded %d domains\n", totalDomains)

	// 2. SUBDOMAINS
	fmt.Println("[*] Migrating subdomains (batching 1000 at a time)...")
	rows, _ = sqliteDB.Query(`SELECT id, domain_id, subdomain, is_live, http_url, https_url, http_status, https_status, created_at, updated_at FROM subdomains`)
	var subBatch []map[string]interface{}
	totalSubs := 0

	for rows.Next() {
		var id, domain_id, is_live int
		var http_status, https_status sql.NullInt64
		var subdomain string
		var ca, ua, h_url, hs_url sql.NullString
		
		rows.Scan(&id, &domain_id, &subdomain, &is_live, &h_url, &hs_url, &http_status, &https_status, &ca, &ua)

		subBatch = append(subBatch, map[string]interface{}{
			"id":           id,
			"domain_id":    domain_id,
			"subdomain":    subdomain,
			"is_live":      is_live != 0,
			"http_url":     nullStr(h_url),
			"https_url":    nullStr(hs_url),
			"http_status":  nullInt(http_status),
			"https_status": nullInt(https_status),
			"created_at":   nullStr(ca),
			"updated_at":   nullStr(ua),
		})
		
		if len(subBatch) >= batchSize {
			if err := postChunk("subdomains", subBatch); err != nil {
				log.Fatalf("Failed to post subdomain chunk: %v", err)
			}
			totalSubs += len(subBatch)
			fmt.Printf("    ... pushed %d subdomains\n", totalSubs)
			subBatch = nil
		}
	}
	if len(subBatch) > 0 {
		if err := postChunk("subdomains", subBatch); err != nil {
			log.Fatalf("Failed to post final subdomain chunk: %v", err)
		}
		totalSubs += len(subBatch)
	}
	rows.Close()
	fmt.Printf("[+] Uploaded %d subdomains\n", totalSubs)

	// 3. SCANS
	fmt.Println("[*] Migrating scans...")
	rows, _ = sqliteDB.Query(`SELECT id, scan_id, scan_type, target, status, channel_id, thread_id, message_id, current_phase, total_phases, phase_name, started_at, completed_at, last_update, command, created_at, updated_at FROM scans`)
	var scanBatch []map[string]interface{}
	totalScans := 0

	for rows.Next() {
		var id, cp, tp int
		var sid, stype, tar, stat, lu string
		var cid, tid, mid, pname, sa, ca_at, cmd, ca, ua sql.NullString
		
		rows.Scan(&id, &sid, &stype, &tar, &stat, &cid, &tid, &mid, &cp, &tp, &pname, &sa, &ca_at, &lu, &cmd, &ca, &ua)

		scanBatch = append(scanBatch, map[string]interface{}{
			"id":             id,
			"scan_id":        sid,
			"scan_type":      stype,
			"target":         tar,
			"status":         stat,
			"current_phase":  cp,
			"total_phases":   tp,
			"last_update":    lu,
			"channel_id":     nullStr(cid),
			"thread_id":      nullStr(tid),
			"message_id":     nullStr(mid),
			"phase_name":     nullStr(pname),
			"started_at":     nullStr(sa),
			"completed_at":   nullStr(ca_at),
			"command":        nullStr(cmd),
			"created_at":     nullStr(ca),
			"updated_at":     nullStr(ua),
		})
		
		if len(scanBatch) >= batchSize {
			if err := postChunk("scans", scanBatch); err != nil {
				log.Fatalf("Failed to post scan chunk: %v", err)
			}
			totalScans += len(scanBatch)
			scanBatch = nil
		}
	}
	if len(scanBatch) > 0 {
		if err := postChunk("scans", scanBatch); err != nil {
			log.Fatalf("Failed to post final scan chunk: %v", err)
		}
		totalScans += len(scanBatch)
	}
	rows.Close()
	fmt.Printf("[+] Uploaded %d scans\n", totalScans)

	fmt.Println("\n[SUCCESS] REST API Migration completed successfully!")
}
