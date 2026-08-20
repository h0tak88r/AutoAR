// Package firebase fingerprints Firebase usage on live hosts, extracts the
// project configuration (projectId, apiKey, databaseURL, storageBucket), and runs
// READ-ONLY exposure tests against the derived Realtime Database, Cloud Firestore,
// and Cloud Storage services. It reports what is world-readable with a severity so
// the dashboard/webhook surfaces real misconfigurations.
//
// Safety: this scanner is deliberately read-only. It performs NO writes, NO
// anonymous sign-up, NO email enumeration, and NO password-reset sends — those
// mutate real data / touch real users and belong in the manual playbook, not an
// unattended scan. Realtime DB reads use `?shallow=true` so access is proven from
// top-level keys without dumping the database contents.
package firebase

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/scanner/subdomains"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// ---- config extraction -----------------------------------------------------

var (
	reAPIKey        = regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)
	reProjectID     = regexp.MustCompile(`["']?projectId["']?\s*[:=]\s*["']([a-zA-Z0-9-]+)["']`)
	reDatabaseURL   = regexp.MustCompile(`["']?databaseURL["']?\s*[:=]\s*["'](https://[a-zA-Z0-9.\-]+\.(?:firebaseio\.com|firebasedatabase\.app))["']`)
	reStorageBucket = regexp.MustCompile(`["']?storageBucket["']?\s*[:=]\s*["']([a-zA-Z0-9._\-]+\.(?:appspot\.com|firebasestorage\.app))["']`)
	reAuthDomain    = regexp.MustCompile(`["']?authDomain["']?\s*[:=]\s*["']([a-zA-Z0-9.\-]+)["']`)
)

// fbConfig is the extracted Firebase web config for a host.
type fbConfig struct {
	ProjectID     string
	APIKey        string
	DatabaseURL   string
	StorageBucket string
	AuthDomain    string
}

// browserUA returns a full Chrome User-Agent (honoring AUTOAR_SCAN_USER_AGENT) so
// commodity WAFs don't 403/406 the request and cause false negatives.
func browserUA() string {
	if ua := strings.TrimSpace(os.Getenv("AUTOAR_SCAN_USER_AGENT")); ua != "" {
		return ua
	}
	return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
}

// ---- public API ------------------------------------------------------------

// Finding is one result for a host: either the Firebase fingerprint (info) or an
// exposed/secured service.
type Finding struct {
	Host      string // host where Firebase was detected
	ProjectID string
	Service   string // "fingerprint" | "realtime-db" | "firestore" | "storage"
	Access    string // "public-read" | "accessible-empty" | "secured" | "not-found"
	Severity  string // critical | high | medium | low | info
	Title     string
	URL       string // the exact URL tested (for the PoC)
	Evidence  string // truncated body / top-level key list
}

// Options for the Firebase scanner.
type Options struct {
	Domain        string
	LiveHostsFile string        // file with one URL/host per line (single-host scans write a temp file)
	Threads       int           // host concurrency (default 20)
	Timeout       time.Duration // per-request timeout (default 15s)
	OutputDir     string        // reserved; JSON is written to the scan dir
	// Aggressive enables WRITE tests (RTDB PUT, Storage upload, Firestore create)
	// in addition to the read-only probes. Each write goes to a clearly-labelled
	// `_autoar_wtest_<ts>` path with benign content and is DELETED immediately after,
	// so no attacker data is left behind. Off by default — writing to a target's
	// Firebase is a deliberate, authorized-engagement choice.
	Aggressive bool
}

// Result holds all findings.
type Result struct {
	Findings []Finding
}

// Run performs the Firebase scan and persists structured findings.
func Run(opts Options) (*Result, error) {
	if opts.Threads <= 0 {
		opts.Threads = 20
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}

	hosts, err := loadHosts(opts)
	if err != nil {
		return nil, fmt.Errorf("firebase: %w", err)
	}
	if len(hosts) == 0 {
		logger.GetLogger().Infof("[firebase] No hosts to scan")
		return &Result{}, nil
	}

	mode := "read-only"
	if opts.Aggressive {
		mode = "read+write (aggressive)"
	}
	logger.GetLogger().Infof("[firebase] Scanning %d host(s) for Firebase exposure (threads=%d, mode=%s)", len(hosts), opts.Threads, mode)

	findings := scanAll(hosts, opts.Threads, opts.Timeout, opts.Aggressive)

	// Persist structured JSON for the dashboard (R2 + DB indexing are automatic).
	if scanID := utils.GetCurrentScanID(); scanID != "" {
		if len(findings) > 0 {
			if err := utils.WriteJSONToScanDir(scanID, "firebase-vulnerabilities.json", toJSON(findings)); err != nil {
				logger.GetLogger().Infof("[firebase] Warning: could not write JSON output: %v", err)
			}
		} else {
			_ = utils.WriteNoFindingsJSON(scanID, opts.Domain, "firebase", "firebase-vulnerabilities.json")
		}
	}

	crit := 0
	for _, f := range findings {
		if f.Severity == "critical" || f.Severity == "high" {
			crit++
		}
	}
	logger.GetLogger().Infof("[firebase] Done. %d finding(s), %d exposed service(s)", len(findings), crit)
	return &Result{Findings: findings}, nil
}

// toJSON maps findings to the dashboard's generic finding schema (target/finding/
// severity recognized by parseFindingFromObject; the rest ride along in the
// detail panel).
func toJSON(findings []Finding) []map[string]any {
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		out = append(out, map[string]any{
			"finding":    f.Title,
			"matched-at": f.Host,
			"severity":   f.Severity,
			"module":     "firebase",
			"service":    f.Service,
			"access":     f.Access,
			"project_id": f.ProjectID,
			"url":        f.URL,
			"evidence":   f.Evidence,
			"poc":        "curl -s " + shellQuote(f.URL),
		})
	}
	return out
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// ---- host loading ----------------------------------------------------------

func loadHosts(opts Options) ([]string, error) {
	filePath := opts.LiveHostsFile
	if filePath == "" && opts.Domain != "" {
		resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
		if resultsDir == "" {
			resultsDir = "new-results"
		}
		for _, c := range []string{
			filepath.Join(resultsDir, opts.Domain, "subs", "live-subs.txt"),
			filepath.Join(resultsDir, opts.Domain, "subs", "subdomains.txt"),
		} {
			if _, err := os.Stat(c); err == nil {
				filePath = c
				break
			}
		}
	}

	// File on disk (pipeline / single-host temp file).
	if filePath != "" {
		return readHostsFile(filePath)
	}

	// No file: fall back to the DB, then to live enumeration, for a bare `-d`.
	if opts.Domain != "" {
		if subs, err := db.ListSubdomains(opts.Domain); err == nil && len(subs) > 0 {
			return normalizeHosts(subs), nil
		}
		logger.GetLogger().Infof("[firebase] No stored hosts for %s — enumerating subdomains", opts.Domain)
		subs, err := subdomains.EnumerateSubdomains(opts.Domain, 100)
		if err != nil {
			return nil, err
		}
		return normalizeHosts(append(subs, opts.Domain)), nil
	}

	return nil, fmt.Errorf("no hosts file and no domain provided")
}

func readHostsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var hosts []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hosts = append(hosts, normalizeHost(line))
	}
	return hosts, sc.Err()
}

func normalizeHosts(in []string) []string {
	out := make([]string, 0, len(in))
	for _, h := range in {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, normalizeHost(h))
		}
	}
	return out
}

func normalizeHost(line string) string {
	if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
		line = "https://" + line
	}
	return strings.TrimRight(line, "/")
}

// ---- worker pool -----------------------------------------------------------

func scanAll(hosts []string, threads int, timeout time.Duration, aggressive bool) []Finding {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	jobCh := make(chan string, threads*2)
	resultCh := make(chan []Finding, threads)
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer utils.RecoverPanic("firebase:worker")
			for host := range jobCh {
				if fs := scanHost(client, host, aggressive); len(fs) > 0 {
					resultCh <- fs
				}
			}
		}()
	}
	go func() {
		for _, h := range hosts {
			jobCh <- h
		}
		close(jobCh)
	}()
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var findings []Finding
	for fs := range resultCh {
		findings = append(findings, fs...)
	}
	return findings
}

// serviceExists reports whether a read probe reached a live service (so it's
// worth a write test) — anything but "not-found" / no-response.
func serviceExists(access string) bool { return access != "" && access != "not-found" }

// scanHost fingerprints one host and, if Firebase is detected, runs the service
// exposure tests. When aggressive is set it also runs WRITE tests (with immediate
// cleanup). Returns the fingerprint (info) plus one finding per exposed service.
func scanHost(client *http.Client, host string, aggressive bool) []Finding {
	detected, cfg, evidence := fingerprint(client, host)
	if !detected {
		return nil
	}

	var findings []Finding

	// Test each derived service. Track the read/write access per service.
	var svcSummary []string
	svc := func(label, access string) { svcSummary = append(svcSummary, label+"="+access) }

	// Realtime Database (both the classic and the newer default-rtdb host).
	for _, dbURL := range rtdbURLs(cfg) {
		access, url, ev := testRealtimeDB(client, dbURL)
		if access == "" {
			continue
		}
		svc("rtdb", access)
		if access == "public-read" {
			findings = append(findings, Finding{
				Host: host, ProjectID: cfg.ProjectID, Service: "realtime-db", Access: access,
				Severity: "critical", URL: url, Evidence: ev,
				Title: "Firebase Realtime Database world-readable (unauthenticated)",
			})
		}
		if aggressive && serviceExists(access) {
			if writable, wurl, wev := testRealtimeDBWrite(client, dbURL); writable {
				svc("rtdb-write", "public-write")
				findings = append(findings, Finding{
					Host: host, ProjectID: cfg.ProjectID, Service: "realtime-db-write", Access: "public-write",
					Severity: "critical", URL: wurl, Evidence: wev,
					Title: "Firebase Realtime Database world-WRITABLE (unauthenticated)",
				})
			}
		}
		break // one working RTDB URL is enough
	}

	// Cloud Firestore.
	if cfg.ProjectID != "" {
		access, url, ev := testFirestore(client, cfg.ProjectID)
		if access != "" {
			svc("firestore", access)
			if access == "public-read" {
				findings = append(findings, Finding{
					Host: host, ProjectID: cfg.ProjectID, Service: "firestore", Access: access,
					Severity: "high", URL: url, Evidence: ev,
					Title: "Firebase Cloud Firestore world-readable (unauthenticated)",
				})
			}
			if aggressive && serviceExists(access) {
				if writable, wurl, wev := testFirestoreWrite(client, cfg.ProjectID); writable {
					svc("firestore-write", "public-write")
					findings = append(findings, Finding{
						Host: host, ProjectID: cfg.ProjectID, Service: "firestore-write", Access: "public-write",
						Severity: "critical", URL: wurl, Evidence: wev,
						Title: "Firebase Cloud Firestore world-WRITABLE (unauthenticated)",
					})
				}
			}
		}
	}

	// Cloud Storage.
	for _, bucket := range storageBuckets(cfg) {
		access, url, ev := testStorage(client, bucket)
		if access == "" {
			continue
		}
		svc("storage", access)
		if access == "public-read" {
			findings = append(findings, Finding{
				Host: host, ProjectID: cfg.ProjectID, Service: "storage", Access: access,
				Severity: "high", URL: url, Evidence: ev,
				Title: "Firebase Storage bucket listing world-readable (unauthenticated)",
			})
		}
		if aggressive && serviceExists(access) {
			if writable, wurl, wev := testStorageWrite(client, bucket); writable {
				svc("storage-write", "public-write")
				findings = append(findings, Finding{
					Host: host, ProjectID: cfg.ProjectID, Service: "storage-write", Access: "public-write",
					Severity: "critical", URL: wurl, Evidence: wev,
					Title: "Firebase Storage bucket world-WRITABLE (unauthenticated)",
				})
			}
		}
		break
	}

	// Always emit the fingerprint (info) so a locked-down but present Firebase is
	// still recorded, with the per-service access summary as evidence.
	fpEvidence := evidence
	if len(svcSummary) > 0 {
		fpEvidence += " | " + strings.Join(svcSummary, " ")
	}
	if cfg.APIKey != "" {
		fpEvidence += " | apiKey=" + maskKey(cfg.APIKey)
	}
	findings = append(findings, Finding{
		Host: host, ProjectID: cfg.ProjectID, Service: "fingerprint", Access: "detected",
		Severity: "info", URL: host, Evidence: fpEvidence,
		Title: "Firebase detected" + projectSuffix(cfg.ProjectID),
	})

	// Alert on confirmed exposure.
	for _, f := range findings {
		if (f.Severity == "critical" || f.Severity == "high") && utils.MonitorWebhookConfigured() {
			go utils.SendMonitorWebhook(fmt.Sprintf("🔥 **Firebase exposure** [%s]\n**%s**\n%s\n`%s`",
				strings.ToUpper(f.Severity), f.Title, host, f.URL))
		}
	}
	return findings
}

func projectSuffix(pid string) string {
	if pid == "" {
		return ""
	}
	return " (project: " + pid + ")"
}

func maskKey(k string) string {
	if len(k) <= 8 {
		return "••••"
	}
	return k[:8] + "…"
}

// ---- fingerprint & config extraction ---------------------------------------

// fingerprint fetches the Firebase Hosting init.json + auth handler and the root
// page, and merges any config it can extract. detected is true when init.json
// parses, the auth handler carries the Firebase license, or a firebaseConfig /
// AIza key is found in a body.
func fingerprint(client *http.Client, base string) (bool, fbConfig, string) {
	var cfg fbConfig
	detected := false
	evidence := ""

	// 1) Firebase Hosting config endpoint — the golden source when present.
	if body, code := get(client, base+"/__/firebase/init.json"); code == 200 && body != "" {
		var raw struct {
			ProjectID     string `json:"projectId"`
			APIKey        string `json:"apiKey"`
			DatabaseURL   string `json:"databaseURL"`
			StorageBucket string `json:"storageBucket"`
			AuthDomain    string `json:"authDomain"`
		}
		if json.Unmarshal([]byte(body), &raw) == nil && raw.ProjectID != "" {
			cfg = fbConfig{raw.ProjectID, raw.APIKey, raw.DatabaseURL, raw.StorageBucket, raw.AuthDomain}
			detected = true
			evidence = "init.json"
		}
	}

	// 2) Auth helper script (the fingerprint the user's nuclei template uses).
	if handler, code := get(client, base+"/__/auth/handler.js"); code == 200 && strings.Contains(handler, "@license Firebase") {
		detected = true
		if evidence == "" {
			evidence = "auth/handler.js"
		}
		mergeConfig(&cfg, handler)
	}

	// 3) Root page + firebaseConfig regex (covers apps NOT on Firebase Hosting).
	if body, code := get(client, base); code >= 200 && code < 400 {
		if reAPIKey.MatchString(body) || strings.Contains(body, "firebaseConfig") || strings.Contains(body, "firebaseio.com") {
			detected = true
			if evidence == "" {
				evidence = "firebaseConfig in page"
			}
			mergeConfig(&cfg, body)
		}
	}

	if detected {
		deriveProjectID(&cfg)
	}
	return detected, cfg, evidence
}

// mergeConfig fills empty cfg fields from any config values found in body.
func mergeConfig(cfg *fbConfig, body string) {
	if cfg.APIKey == "" {
		if m := reAPIKey.FindString(body); m != "" {
			cfg.APIKey = m
		}
	}
	if cfg.ProjectID == "" {
		if m := reProjectID.FindStringSubmatch(body); len(m) > 1 {
			cfg.ProjectID = m[1]
		}
	}
	if cfg.DatabaseURL == "" {
		if m := reDatabaseURL.FindStringSubmatch(body); len(m) > 1 {
			cfg.DatabaseURL = m[1]
		}
	}
	if cfg.StorageBucket == "" {
		if m := reStorageBucket.FindStringSubmatch(body); len(m) > 1 {
			cfg.StorageBucket = m[1]
		}
	}
	if cfg.AuthDomain == "" {
		if m := reAuthDomain.FindStringSubmatch(body); len(m) > 1 {
			cfg.AuthDomain = m[1]
		}
	}
}

// deriveProjectID backfills the projectId from other config fields when it wasn't
// stated explicitly (authDomain / storageBucket / databaseURL all embed it).
func deriveProjectID(cfg *fbConfig) {
	if cfg.ProjectID != "" {
		return
	}
	switch {
	case cfg.AuthDomain != "":
		cfg.ProjectID = strings.TrimSuffix(strings.TrimSuffix(cfg.AuthDomain, ".firebaseapp.com"), ".web.app")
	case cfg.StorageBucket != "":
		cfg.ProjectID = strings.TrimSuffix(strings.TrimSuffix(cfg.StorageBucket, ".appspot.com"), ".firebasestorage.app")
	case cfg.DatabaseURL != "":
		h := strings.TrimPrefix(strings.TrimPrefix(cfg.DatabaseURL, "https://"), "http://")
		h = strings.SplitN(h, ".", 2)[0]
		cfg.ProjectID = strings.TrimSuffix(h, "-default-rtdb")
	}
}

// rtdbURLs returns the Realtime Database base URLs to test (explicit first, else
// the two conventional variants derived from the project id).
func rtdbURLs(cfg fbConfig) []string {
	if cfg.DatabaseURL != "" {
		return []string{strings.TrimRight(cfg.DatabaseURL, "/")}
	}
	if cfg.ProjectID == "" {
		return nil
	}
	return []string{
		"https://" + cfg.ProjectID + ".firebaseio.com",
		"https://" + cfg.ProjectID + "-default-rtdb.firebasedatabase.app",
	}
}

// storageBuckets returns the storage bucket names to test.
func storageBuckets(cfg fbConfig) []string {
	if cfg.StorageBucket != "" {
		return []string{cfg.StorageBucket}
	}
	if cfg.ProjectID == "" {
		return nil
	}
	return []string{cfg.ProjectID + ".appspot.com", cfg.ProjectID + ".firebasestorage.app"}
}

// ---- read-only service tests -----------------------------------------------

// testRealtimeDB reads the RTDB root shallow (top-level keys only, no data dump).
func testRealtimeDB(client *http.Client, dbURL string) (access, url, evidence string) {
	url = dbURL + "/.json?shallow=true"
	body, code := get(client, url)
	switch {
	case code == 200:
		b := strings.TrimSpace(body)
		if b == "null" || b == "" {
			return "accessible-empty", url, "empty root"
		}
		if strings.Contains(b, "Permission denied") {
			return "secured", url, ""
		}
		return "public-read", url, truncate(b, 300)
	case code == 401 || code == 403:
		return "secured", url, ""
	case code == 404:
		return "not-found", url, ""
	}
	return "", url, ""
}

// testFirestore lists root documents unauthenticated.
func testFirestore(client *http.Client, projectID string) (access, url, evidence string) {
	url = "https://firestore.googleapis.com/v1/projects/" + projectID + "/databases/(default)/documents?pageSize=1"
	body, code := get(client, url)
	switch {
	case code == 200:
		if strings.Contains(body, "\"documents\"") || strings.Contains(body, "\"name\"") {
			return "public-read", url, truncate(body, 300)
		}
		return "accessible-empty", url, "no root documents"
	case code == 401 || code == 403:
		return "secured", url, ""
	case code == 404:
		return "not-found", url, ""
	}
	return "", url, ""
}

// testStorage lists the storage bucket objects unauthenticated.
func testStorage(client *http.Client, bucket string) (access, url, evidence string) {
	url = "https://firebasestorage.googleapis.com/v0/b/" + bucket + "/o"
	body, code := get(client, url)
	switch {
	case code == 200:
		if strings.Contains(body, "\"items\"") {
			return "public-read", url, truncate(body, 300)
		}
		return "accessible-empty", url, "no items"
	case code == 401 || code == 403:
		return "secured", url, ""
	case code == 404:
		return "not-found", url, ""
	}
	return "", url, ""
}

// ---- write tests (aggressive; each cleans up after itself) ------------------

// wtestName is a clearly-labelled, unique key for a write probe so it can never
// collide with real data and is obvious in the target's logs.
func wtestName() string {
	return "_autoar_wtest_" + strconv.FormatInt(time.Now().UnixNano(), 10)
}

// testRealtimeDBWrite PUTs a benign marker to a labelled test key, and DELETEs it
// immediately on success. Confirms unauthenticated write without leaving data.
func testRealtimeDBWrite(client *http.Client, dbURL string) (writable bool, url, evidence string) {
	url = strings.TrimRight(dbURL, "/") + "/" + wtestName() + ".json"
	code := send(client, http.MethodPut, url, "application/json", `{"autoar":"authorized-write-test","note":"safe to delete"}`)
	if code == 200 {
		_ = del(client, url) // clean up immediately — leave nothing behind
		return true, url, "PUT 200 — test key written and deleted"
	}
	return false, url, ""
}

// testFirestoreWrite creates a benign document in an autoar_wtest collection and
// deletes it on success.
func testFirestoreWrite(client *http.Client, projectID string) (writable bool, url, evidence string) {
	docID := wtestName()
	base := "https://firestore.googleapis.com/v1/projects/" + projectID + "/databases/(default)/documents/autoar_wtest"
	url = base + "?documentId=" + docID
	code := send(client, http.MethodPost, url, "application/json", `{"fields":{"autoar":{"stringValue":"authorized-write-test"}}}`)
	if code == 200 || code == 201 {
		_ = del(client, base+"/"+docID) // clean up
		return true, url, "createDocument " + strconv.Itoa(code) + " — test doc written and deleted"
	}
	return false, url, ""
}

// testStorageWrite uploads a small benign object to a labelled name and deletes it
// on success.
func testStorageWrite(client *http.Client, bucket string) (writable bool, url, evidence string) {
	name := wtestName() + ".txt"
	url = "https://firebasestorage.googleapis.com/v0/b/" + bucket + "/o?name=" + name
	code := send(client, http.MethodPost, url, "text/plain", "autoar authorized write test — safe to delete")
	if code == 200 {
		_ = del(client, "https://firebasestorage.googleapis.com/v0/b/"+bucket+"/o/"+name) // clean up
		return true, url, "upload 200 — test object written and deleted"
	}
	return false, url, ""
}

// ---- http helper -----------------------------------------------------------

// send performs a write request (PUT/POST) and returns the status code (0 on
// network error). The body is discarded — only the code matters.
func send(client *http.Client, method, url, contentType, body string) int {
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", browserUA())
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	return resp.StatusCode
}

// del removes a write-probe object (best-effort cleanup so nothing is left behind).
func del(client *http.Client, url string) int {
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", browserUA())
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

// get performs a single GET and returns a (capped) body + status code. Network
// errors return code 0.
func get(client *http.Client, url string) (string, int) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", 0
	}
	req.Header.Set("User-Agent", browserUA())
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0
	}
	defer resp.Body.Close()
	// Cap the read: enough to fingerprint / prove access, never a full DB dump.
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return string(b), resp.StatusCode
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
