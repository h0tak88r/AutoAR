package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

func esc(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func main() {
	sqliteDB, err := sql.Open("sqlite", "./bughunt.db?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)")
	if err != nil {
		log.Fatalf("Failed to open SQLite: %v", err)
	}
	defer sqliteDB.Close()

	f, err := os.Create("supabase_import.sql")
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer f.Close()

	w := func(s string) { f.WriteString(s + "\n") }

	w("-- AutoAR Database Export for Supabase")
	w(fmt.Sprintf("-- Generated at: %s", time.Now().Format(time.RFC3339)))
	w("-- Instructions: Paste this into the Supabase SQL Editor and run it.")
	w("")
	w("-- Disable triggers for fast import")
	w("SET session_replication_role = replica;")
	w("")

	// 1. Domains
	w("-- DOMAINS TABLE")
	rows, _ := sqliteDB.Query(`SELECT id, domain, created_at, updated_at FROM domains`)
	count := 0
	for rows.Next() {
		var id int
		var domain string
		var created_at, updated_at sql.NullString
		rows.Scan(&id, &domain, &created_at, &updated_at)
		ca := "NOW()"; if created_at.Valid { ca = esc(created_at.String) }
		ua := "NOW()"; if updated_at.Valid { ua = esc(updated_at.String) }
		w(fmt.Sprintf("INSERT INTO domains (id, domain, created_at, updated_at) VALUES (%d, %s, %s, %s) ON CONFLICT (domain) DO NOTHING;", id, esc(domain), ca, ua))
		count++
	}
	rows.Close()
	w(fmt.Sprintf("SELECT setval('domains_id_seq', COALESCE((SELECT MAX(id) FROM domains), 1));"))
	log.Printf("[+] Exported %d domains", count)
	w("")

	// 2. Subdomains
	w("-- SUBDOMAINS TABLE")
	rows, _ = sqliteDB.Query(`SELECT id, domain_id, subdomain, is_live, COALESCE(http_url,''), COALESCE(https_url,''), COALESCE(http_status,0), COALESCE(https_status,0), created_at, updated_at FROM subdomains`)
	count = 0
	for rows.Next() {
		var id, domain_id, is_live, http_status, https_status int
		var subdomain, http_url, https_url string
		var created_at, updated_at sql.NullString
		rows.Scan(&id, &domain_id, &subdomain, &is_live, &http_url, &https_url, &http_status, &https_status, &created_at, &updated_at)
		ca := "NOW()"; if created_at.Valid { ca = esc(created_at.String) }
		ua := "NOW()"; if updated_at.Valid { ua = esc(updated_at.String) }
		isLive := "FALSE"; if is_live != 0 { isLive = "TRUE" }
		w(fmt.Sprintf("INSERT INTO subdomains (id, domain_id, subdomain, is_live, http_url, https_url, http_status, https_status, created_at, updated_at) VALUES (%d, %d, %s, %s, %s, %s, %d, %d, %s, %s) ON CONFLICT (subdomain) DO NOTHING;", id, domain_id, esc(subdomain), isLive, esc(http_url), esc(https_url), http_status, https_status, ca, ua))
		count++
	}
	rows.Close()
	w("SELECT setval('subdomains_id_seq', COALESCE((SELECT MAX(id) FROM subdomains), 1));")
	log.Printf("[+] Exported %d subdomains", count)
	w("")

	// 3. JS Files
	w("-- JS_FILES TABLE")
	rows, _ = sqliteDB.Query(`SELECT id, subdomain_id, js_url, COALESCE(content_hash,''), COALESCE(last_scanned,''), created_at, updated_at FROM js_files`)
	count = 0
	for rows.Next() {
		var id, subdomain_id int
		var js_url, content_hash, last_scanned string
		var created_at, updated_at sql.NullString
		rows.Scan(&id, &subdomain_id, &js_url, &content_hash, &last_scanned, &created_at, &updated_at)
		ca := "NOW()"; if created_at.Valid { ca = esc(created_at.String) }
		ua := "NOW()"; if updated_at.Valid { ua = esc(updated_at.String) }
		ls := "NOW()"; if last_scanned != "" { ls = esc(last_scanned) }
		w(fmt.Sprintf("INSERT INTO js_files (id, subdomain_id, js_url, content_hash, last_scanned, created_at, updated_at) VALUES (%d, %d, %s, %s, %s, %s, %s) ON CONFLICT (js_url) DO NOTHING;", id, subdomain_id, esc(js_url), esc(content_hash), ls, ca, ua))
		count++
	}
	rows.Close()
	w("SELECT setval('js_files_id_seq', COALESCE((SELECT MAX(id) FROM js_files), 1));")
	log.Printf("[+] Exported %d JS files", count)
	w("")

	// 4. Keyhack Templates
	w("-- KEYHACK_TEMPLATES TABLE")
	rows, _ = sqliteDB.Query(`SELECT id, keyname, command_template, COALESCE(method,'GET'), url, COALESCE(header,''), COALESCE(body,''), COALESCE(description,''), COALESCE(notes,''), created_at, updated_at FROM keyhack_templates`)
	count = 0
	for rows.Next() {
		var id int
		var keyname, command_template, method, url, header, body, description, notes string
		var created_at, updated_at sql.NullString
		rows.Scan(&id, &keyname, &command_template, &method, &url, &header, &body, &description, &notes, &created_at, &updated_at)
		ca := "NOW()"; if created_at.Valid { ca = esc(created_at.String) }
		ua := "NOW()"; if updated_at.Valid { ua = esc(updated_at.String) }
		w(fmt.Sprintf("INSERT INTO keyhack_templates (id, keyname, command_template, method, url, header, body, description, notes, created_at, updated_at) VALUES (%d, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (keyname) DO NOTHING;", id, esc(keyname), esc(command_template), esc(method), esc(url), esc(header), esc(body), esc(description), esc(notes), ca, ua))
		count++
	}
	rows.Close()
	w("SELECT setval('keyhack_templates_id_seq', COALESCE((SELECT MAX(id) FROM keyhack_templates), 1));")
	log.Printf("[+] Exported %d keyhack templates", count)
	w("")

	// 5. Scans
	w("-- SCANS TABLE")
	rows, _ = sqliteDB.Query(`SELECT id, scan_id, scan_type, target, status, COALESCE(channel_id,''), COALESCE(thread_id,''), COALESCE(message_id,''), current_phase, total_phases, COALESCE(phase_name,''), COALESCE(started_at,''), COALESCE(completed_at,''), last_update, COALESCE(command,''), created_at, updated_at FROM scans`)
	count = 0
	for rows.Next() {
		var id, current_phase, total_phases int
		var scan_id, scan_type, target, status, channel_id, thread_id, message_id, phase_name, started_at, completed_at, last_update, command string
		var created_at, updated_at sql.NullString
		rows.Scan(&id, &scan_id, &scan_type, &target, &status, &channel_id, &thread_id, &message_id, &current_phase, &total_phases, &phase_name, &started_at, &completed_at, &last_update, &command, &created_at, &updated_at)
		ca := "NOW()"; if created_at.Valid { ca = esc(created_at.String) }
		ua := "NOW()"; if updated_at.Valid { ua = esc(updated_at.String) }
		sa := "NOW()"; if started_at != "" { sa = esc(started_at) }
		w(fmt.Sprintf("INSERT INTO scans (id, scan_id, scan_type, target, status, channel_id, thread_id, message_id, current_phase, total_phases, phase_name, started_at, last_update, command, created_at, updated_at) VALUES (%d, %s, %s, %s, %s, %s, %s, %s, %d, %d, %s, %s, %s, %s, %s, %s) ON CONFLICT (scan_id) DO NOTHING;",
			id, esc(scan_id), esc(scan_type), esc(target), esc(status), esc(channel_id), esc(thread_id), esc(message_id), current_phase, total_phases, esc(phase_name), sa, esc(last_update), esc(command), ca, ua))
		count++
	}
	rows.Close()
	w("SELECT setval('scans_id_seq', COALESCE((SELECT MAX(id) FROM scans), 1));")
	log.Printf("[+] Exported %d scans", count)
	w("")

	w("-- Re-enable triggers")
	w("SET session_replication_role = DEFAULT;")
	w("")
	w("-- Done!")

	log.Printf("[SUCCESS] SQL export written to: supabase_import.sql")
	log.Printf("Now: 1) Open Supabase SQL Editor  2) Paste the file contents  3) Click Run")
}
