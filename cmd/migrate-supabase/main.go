// cmd/migrate-supabase/main.go
// One-time migration: pulls data from Supabase REST API → local PostgreSQL.
// Run: go run ./cmd/migrate-supabase/
// Env required: SUPABASE_URL, SUPABASE_SECRET_KEY (or SUPABASE_ANON_KEY), DB_HOST (local PG)

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

// ── Supabase REST client ──────────────────────────────────────────────────────

type sbClient struct {
	base   string
	apiKey string
	http   *http.Client
}

func newSBClient(baseURL, apiKey string) *sbClient {
	return &sbClient{
		base:   strings.TrimSuffix(baseURL, "/"),
		apiKey: apiKey,
		http:   &http.Client{Timeout: 30 * time.Second},
	}
}

// fetchAll pages through a Supabase table via the REST API (limit 1000 rows/page).
func (s *sbClient) fetchAll(table string) ([]map[string]interface{}, error) {
	var all []map[string]interface{}
	offset := 0
	limit := 1000
	for {
		url := fmt.Sprintf("%s/rest/v1/%s?limit=%d&offset=%d", s.base, table, limit, offset)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("apikey", s.apiKey)
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Prefer", "count=exact")

		resp, err := s.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("GET %s: %w", url, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
			log.Printf("[WARN] table %q HTTP %d: %s", table, resp.StatusCode, string(body))
			return all, nil
		}

		var rows []map[string]interface{}
		if err := json.Unmarshal(body, &rows); err != nil {
			return nil, fmt.Errorf("decode %s: %w", table, err)
		}
		all = append(all, rows...)
		if len(rows) < limit {
			break
		}
		offset += limit
	}
	return all, nil
}

// ── Local PG helpers ──────────────────────────────────────────────────────────

func mustStr(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok && v != nil {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func mustBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key]; ok && v != nil {
		switch t := v.(type) {
		case bool:
			return t
		case string:
			return strings.EqualFold(t, "true")
		}
	}
	return false
}

func mustInt(m map[string]interface{}, key string) int64 {
	if v, ok := m[key]; ok && v != nil {
		switch t := v.(type) {
		case float64:
			return int64(t)
		case int64:
			return t
		case string:
			var n int64
			fmt.Sscan(t, &n)
			return n
		}
	}
	return 0
}

func mustJSON(m map[string]interface{}, key string) *string {
	if v, ok := m[key]; ok && v != nil {
		b, _ := json.Marshal(v)
		s := string(b)
		return &s
	}
	return nil
}

func mustTime(m map[string]interface{}, key string) *time.Time {
	s := mustStr(m, key)
	if s == "" {
		return nil
	}
	// Try several formats Supabase may use
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

// ── Migrate tables ────────────────────────────────────────────────────────────

func migrateDomains(ctx context.Context, pool *pgxpool.Pool, rows []map[string]interface{}) (int, error) {
	n := 0
	for _, r := range rows {
		domain := mustStr(r, "domain")
		if domain == "" {
			continue
		}
		_, err := pool.Exec(ctx, `
			INSERT INTO domains (domain, created_at)
			VALUES ($1, $2)
			ON CONFLICT DO NOTHING`,
			domain,
			mustTime(r, "created_at"),
		)
		if err != nil {
			log.Printf("[WARN] domain %q: %v", domain, err)
			continue
		}
		n++
	}
	return n, nil
}

// domainIDMap builds domain → local id after insert so subdomains FK resolves.
func domainIDMap(ctx context.Context, pool *pgxpool.Pool) (map[string]int, error) {
	rows, err := pool.Query(ctx, `SELECT id, domain FROM domains`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]int{}
	for rows.Next() {
		var id int
		var d string
		if err := rows.Scan(&id, &d); err == nil {
			m[d] = id
		}
	}
	return m, rows.Err()
}

func migrateSubdomains(ctx context.Context, pool *pgxpool.Pool, rows []map[string]interface{}, domIDs map[string]int) (int, error) {
	n := 0
	for _, r := range rows {
		sub := mustStr(r, "subdomain")
		if sub == "" {
			continue
		}
		// Supabase stores domain_id directly
		domainID := int(mustInt(r, "domain_id"))
		if domainID == 0 {
			continue
		}
		// Remap to local domain_id (may differ)
		// First get the domain name from Supabase domain_id.
		// Since we migrated domains already and domIDs is keyed by name,
		// we need to store a reverse map from old_id → domain. We solve this
		// by just trusting that our local IDs match (if tables were empty) OR
		// by re-querying. We do a best-effort: try to find matching local domain by name.
		// The safest approach: skip FK remap and use domain_id as-is for now if tables were empty.
		// Better: ignore domain_id from Supabase and extract from "domain" column if present.
		actualDomainName := mustStr(r, "domain")
		if actualDomainName != "" {
			if id, ok := domIDs[actualDomainName]; ok {
				domainID = id
			}
		}

		_, err := pool.Exec(ctx, `
			INSERT INTO subdomains (domain_id, subdomain, is_live, http_url, https_url, http_status, https_status, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (subdomain) DO NOTHING`,
			domainID,
			sub,
			mustBool(r, "is_live"),
			mustStr(r, "http_url"),
			mustStr(r, "https_url"),
			int(mustInt(r, "http_status")),
			int(mustInt(r, "https_status")),
			mustTime(r, "created_at"),
			mustTime(r, "updated_at"),
		)
		if err != nil {
			log.Printf("[WARN] subdomain %q: %v", sub, err)
			continue
		}
		n++
	}
	return n, nil
}

func migrateScans(ctx context.Context, pool *pgxpool.Pool, rows []map[string]interface{}) (int, error) {
	n := 0
	for _, r := range rows {
		scanID := mustStr(r, "scan_id")
		if scanID == "" {
			continue
		}
		startedAt := mustTime(r, "started_at")
		if startedAt == nil {
			now := time.Now()
			startedAt = &now
		}
		lastUpdate := mustTime(r, "last_update")
		if lastUpdate == nil {
			lastUpdate = startedAt
		}
		completedPhasesJSON := mustJSON(r, "completed_phases")
		failedPhasesJSON := mustJSON(r, "failed_phases")

		_, err := pool.Exec(ctx, `
			INSERT INTO scans (
				scan_id, scan_type, target, status,
				channel_id, thread_id, message_id,
				current_phase, total_phases, phase_name,
				completed_phases, failed_phases,
				files_uploaded, error_count,
				started_at, completed_at, last_update,
				command, result_url, created_at, updated_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
			ON CONFLICT (scan_id) DO NOTHING`,
			scanID,
			mustStr(r, "scan_type"),
			mustStr(r, "target"),
			mustStr(r, "status"),
			mustStr(r, "channel_id"),
			mustStr(r, "thread_id"),
			mustStr(r, "message_id"),
			int(mustInt(r, "current_phase")),
			int(mustInt(r, "total_phases")),
			mustStr(r, "phase_name"),
			completedPhasesJSON,
			failedPhasesJSON,
			int(mustInt(r, "files_uploaded")),
			int(mustInt(r, "error_count")),
			startedAt,
			mustTime(r, "completed_at"),
			lastUpdate,
			mustStr(r, "command"),
			mustStr(r, "result_url"),
			mustTime(r, "created_at"),
			mustTime(r, "updated_at"),
		)
		if err != nil {
			log.Printf("[WARN] scan %q: %v", scanID, err)
			continue
		}
		n++
	}
	return n, nil
}

func migrateScanArtifacts(ctx context.Context, pool *pgxpool.Pool, rows []map[string]interface{}) (int, error) {
	n := 0
	for _, r := range rows {
		scanID := mustStr(r, "scan_id")
		r2Key := mustStr(r, "r2_key")
		if scanID == "" || r2Key == "" {
			continue
		}
		_, err := pool.Exec(ctx, `
			INSERT INTO scan_artifacts (
				scan_id, file_name, local_path, r2_key, public_url,
				size_bytes, line_count, content_type, module, category, created_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
			ON CONFLICT (scan_id, r2_key) DO NOTHING`,
			scanID,
			mustStr(r, "file_name"),
			mustStr(r, "local_path"),
			r2Key,
			mustStr(r, "public_url"),
			mustInt(r, "size_bytes"),
			int(mustInt(r, "line_count")),
			mustStr(r, "content_type"),
			mustStr(r, "module"),
			mustStr(r, "category"),
			mustTime(r, "created_at"),
		)
		if err != nil {
			log.Printf("[WARN] artifact scan=%q r2=%q: %v", scanID, r2Key, err)
			continue
		}
		n++
	}
	return n, nil
}

func migrateMonitorTargets(ctx context.Context, pool *pgxpool.Pool, rows []map[string]interface{}) (int, error) {
	n := 0
	for _, r := range rows {
		u := mustStr(r, "url")
		if u == "" {
			continue
		}
		strategy := mustStr(r, "strategy")
		if strategy == "" {
			strategy = "hash"
		}
		_, err := pool.Exec(ctx, `
			INSERT INTO updates_targets (url, strategy, pattern, is_running, last_hash, last_run_at, change_count, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (url) DO NOTHING`,
			u,
			strategy,
			mustStr(r, "pattern"),
			mustBool(r, "is_running"),
			mustStr(r, "last_hash"),
			mustTime(r, "last_run_at"),
			int(mustInt(r, "change_count")),
			mustTime(r, "created_at"),
			mustTime(r, "updated_at"),
		)
		if err != nil {
			log.Printf("[WARN] monitor target %q: %v", u, err)
			continue
		}
		n++
	}
	return n, nil
}

func migrateSubdomainMonitors(ctx context.Context, pool *pgxpool.Pool, rows []map[string]interface{}) (int, error) {
	n := 0
	for _, r := range rows {
		domain := mustStr(r, "domain")
		if domain == "" {
			continue
		}
		interval := int(mustInt(r, "interval_seconds"))
		if interval == 0 {
			interval = 3600
		}
		threads := int(mustInt(r, "threads"))
		if threads == 0 {
			threads = 100
		}
		_, err := pool.Exec(ctx, `
			INSERT INTO subdomain_monitor_targets (domain, interval_seconds, threads, check_new, is_running, last_run_at, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (domain) DO NOTHING`,
			domain,
			interval,
			threads,
			mustBool(r, "check_new"),
			mustBool(r, "is_running"),
			mustTime(r, "last_run_at"),
			mustTime(r, "created_at"),
			mustTime(r, "updated_at"),
		)
		if err != nil {
			log.Printf("[WARN] subdomain monitor %q: %v", domain, err)
			continue
		}
		n++
	}
	return n, nil
}

func migrateMonitorChanges(ctx context.Context, pool *pgxpool.Pool, rows []map[string]interface{}) (int, error) {
	n := 0
	for _, r := range rows {
		domain := mustStr(r, "domain")
		changeType := mustStr(r, "change_type")
		targetType := mustStr(r, "target_type")
		if domain == "" || changeType == "" {
			continue
		}
		detectedAt := mustTime(r, "detected_at")
		if detectedAt == nil {
			now := time.Now()
			detectedAt = &now
		}
		_, err := pool.Exec(ctx, `
			INSERT INTO monitor_changes (target_type, target_id, domain, change_type, detail, detected_at, notified)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			targetType,
			int(mustInt(r, "target_id")),
			domain,
			changeType,
			mustStr(r, "detail"),
			detectedAt,
			mustBool(r, "notified"),
		)
		if err != nil {
			log.Printf("[WARN] monitor change %q/%q: %v", domain, changeType, err)
			continue
		}
		n++
	}
	return n, nil
}

func migrateKeyhackTemplates(ctx context.Context, pool *pgxpool.Pool, rows []map[string]interface{}) (int, error) {
	n := 0
	for _, r := range rows {
		keyname := mustStr(r, "keyname")
		if keyname == "" {
			continue
		}
		_, err := pool.Exec(ctx, `
			INSERT INTO keyhack_templates (keyname, command_template, method, url, header, body, description, notes, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (keyname) DO NOTHING`,
			keyname,
			mustStr(r, "command_template"),
			mustStr(r, "method"),
			mustStr(r, "url"),
			mustStr(r, "header"),
			mustStr(r, "body"),
			mustStr(r, "description"),
			mustStr(r, "notes"),
			mustTime(r, "created_at"),
			mustTime(r, "updated_at"),
		)
		if err != nil {
			log.Printf("[WARN] keyhack %q: %v", keyname, err)
			continue
		}
		n++
	}
	return n, nil
}

func migrateDNSProviders(ctx context.Context, pool *pgxpool.Pool, rows []map[string]interface{}) (int, error) {
	n := 0
	for _, r := range rows {
		name := mustStr(r, "name")
		fp := mustStr(r, "fingerprint")
		if name == "" || fp == "" {
			continue
		}
		_, err := pool.Exec(ctx, `
			INSERT INTO dns_takeover_providers (name, fingerprint, created_at, updated_at)
			VALUES ($1,$2,$3,$4)
			ON CONFLICT (name) DO NOTHING`,
			name, fp,
			mustTime(r, "created_at"),
			mustTime(r, "updated_at"),
		)
		if err != nil {
			log.Printf("[WARN] dns provider %q: %v", name, err)
			continue
		}
		n++
	}
	return n, nil
}

func migrateJSFiles(ctx context.Context, pool *pgxpool.Pool, rows []map[string]interface{}) (int, error) {
	n := 0
	for _, r := range rows {
		jsURL := mustStr(r, "js_url")
		if jsURL == "" {
			continue
		}
		subdomainID := int(mustInt(r, "subdomain_id"))
		_, err := pool.Exec(ctx, `
			INSERT INTO js_files (subdomain_id, js_url, content_hash, last_scanned, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (js_url) DO NOTHING`,
			subdomainID,
			jsURL,
			mustStr(r, "content_hash"),
			mustTime(r, "last_scanned"),
			mustTime(r, "created_at"),
			mustTime(r, "updated_at"),
		)
		if err != nil {
			log.Printf("[WARN] js_file %q: %v", jsURL, err)
			continue
		}
		n++
	}
	return n, nil
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	// Load .env
	if err := godotenv.Load(".env"); err != nil {
		log.Printf("[WARN] Could not load .env: %v (proceeding with environment)", err)
	}

	sbURL := strings.TrimSpace(os.Getenv("SUPABASE_URL"))
	// Prefer service-role key (full access, bypasses RLS)
	sbKey := strings.TrimSpace(os.Getenv("SUPABASE_SECRET_KEY"))
	if sbKey == "" {
		sbKey = strings.TrimSpace(os.Getenv("SUPABASE_ANON_KEY"))
	}
	localDSN := strings.TrimSpace(os.Getenv("DB_HOST"))
	if localDSN == "" {
		localDSN = os.Getenv("DATABASE_URL")
	}

	if sbURL == "" {
		log.Fatal("SUPABASE_URL is not set (uncomment it in .env temporarily for migration)")
	}
	if sbKey == "" {
		log.Fatal("SUPABASE_SECRET_KEY or SUPABASE_ANON_KEY must be set")
	}
	if localDSN == "" {
		log.Fatal("DB_HOST (local PostgreSQL DSN) is not set")
	}

	sb := newSBClient(sbURL, sbKey)

	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(localDSN)
	if err != nil {
		log.Fatalf("invalid local DSN: %v", err)
	}
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		log.Fatalf("connect local PG: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("ping local PG: %v", err)
	}
	log.Println("✅ Connected to local PostgreSQL")

	type table struct {
		name    string
		migrate func([]map[string]interface{}) (int, error)
	}

	tables := []table{
		{"domains", func(rows []map[string]interface{}) (int, error) {
			n, err := migrateDomains(ctx, pool, rows)
			if err != nil {
				return n, err
			}
			return n, nil
		}},
		{"keyhack_templates", func(rows []map[string]interface{}) (int, error) {
			return migrateKeyhackTemplates(ctx, pool, rows)
		}},
		{"dns_takeover_providers", func(rows []map[string]interface{}) (int, error) {
			return migrateDNSProviders(ctx, pool, rows)
		}},
		{"scans", func(rows []map[string]interface{}) (int, error) {
			return migrateScans(ctx, pool, rows)
		}},
		{"scan_artifacts", func(rows []map[string]interface{}) (int, error) {
			return migrateScanArtifacts(ctx, pool, rows)
		}},
		{"updates_targets", func(rows []map[string]interface{}) (int, error) {
			return migrateMonitorTargets(ctx, pool, rows)
		}},
		{"subdomain_monitor_targets", func(rows []map[string]interface{}) (int, error) {
			return migrateSubdomainMonitors(ctx, pool, rows)
		}},
		{"monitor_changes", func(rows []map[string]interface{}) (int, error) {
			return migrateMonitorChanges(ctx, pool, rows)
		}},
	}

	for _, t := range tables {
		log.Printf("📥 Fetching table: %s …", t.name)
		rows, err := sb.fetchAll(t.name)
		if err != nil {
			log.Printf("  [ERR] fetch %s: %v — skipping", t.name, err)
			continue
		}
		log.Printf("  → %d rows fetched", len(rows))
		if len(rows) == 0 {
			log.Printf("  → (empty, skipping)")
			continue
		}
		n, err := t.migrate(rows)
		if err != nil {
			log.Printf("  [ERR] migrate %s: %v", t.name, err)
		} else {
			log.Printf("  ✅ %d rows inserted into %s", n, t.name)
		}
	}

	// Subdomains are migrated after domains so FK lookup works
	log.Printf("📥 Fetching table: subdomains …")
	domIDs, _ := domainIDMap(ctx, pool)
	subRows, err := sb.fetchAll("subdomains")
	if err != nil {
		log.Printf("  [ERR] fetch subdomains: %v — skipping", err)
	} else {
		log.Printf("  → %d rows fetched", len(subRows))
		n, err := migrateSubdomains(ctx, pool, subRows, domIDs)
		if err != nil {
			log.Printf("  [ERR] migrate subdomains: %v", err)
		} else {
			log.Printf("  ✅ %d rows inserted into subdomains", n)
		}
	}

	// JS files last (depend on subdomain IDs)
	log.Printf("📥 Fetching table: js_files …")
	jsRows, err := sb.fetchAll("js_files")
	if err != nil {
		log.Printf("  [ERR] fetch js_files: %v — skipping", err)
	} else {
		log.Printf("  → %d rows fetched", len(jsRows))
		n, _ := migrateJSFiles(ctx, pool, jsRows)
		log.Printf("  ✅ %d rows inserted into js_files", n)
	}

	log.Println("\n🎉 Migration complete!")
}
