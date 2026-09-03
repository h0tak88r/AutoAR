package apidocs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/utils"
	"github.com/sirupsen/logrus"
)

// apitester turns exposed API-documentation hits (swagger.json / openapi.json /
// api-docs — anything a nuclei template flagged) into an unauthenticated access
// audit: every documented endpoint × method is probed without credentials,
// 401/403s get a small auth-bypass header matrix, results are classified,
// persisted as a JSON artifact, and summarized to Discord. The AI automation
// cycles then do the adaptive depth work (FP filtering, parameterized retests,
// IDOR probing) on top of the artifact.

const (
	settingEnabled   = "API_DOCS_AUTOTEST"
	settingTrigger   = "API_DOCS_TRIGGER_REGEX"
	settingSeen      = "API_DOCS_SEEN"
	defaultTriggerRe = `(?i)(swagger|openapi|api-?docs?|graphql|exposed-?api)`

	maxDocBytes         = 4 << 20 // swagger docs can be large
	maxRespSampleBytes  = 256 << 10
	requestTimeout      = 12 * time.Second
	defaultMaxEndpoints = 300
	perDocDeadline      = 8 * time.Minute
	queueSize           = 256
	seenPruneDays       = 30
	seenCap             = 5000
)

var (
	once         sync.Once
	queue        chan docJob
	seenMu       sync.Mutex
	seenMap      map[string]time.Time
	failCooldown map[string]time.Time
	defaultRe    = regexp.MustCompile(defaultTriggerRe)
	interestRe   = regexp.MustCompile(`(?i)(admin|user|account|token|key|secret|config|internal|debug|private|customer|employee|export|dump|backup|password|credential|session|auth)`)
	// mask obvious credentials before anything reaches Discord
	redactRe = regexp.MustCompile(`(?i)((?:bearer|api[_-]?key|token|secret|password|authorization)"?\s*[:=]\s*"?)[A-Za-z0-9._\-+/=]{8,}`)
	uuidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

type docJob struct {
	TemplateID string
	DocURL     string
	SpecURL    string // discovered spec URL when the hit was an HTML doc page
}

func log() *logrus.Logger { return logger.GetLogger() }

// Enabled reports whether auto-testing is on (DB setting API_DOCS_AUTOTEST=off
// or env API_DOCS_AUTOTEST=off disables; default on).
func Enabled() bool {
	if v := strings.TrimSpace(os.Getenv("API_DOCS_AUTOTEST")); strings.EqualFold(v, "off") {
		return false
	}
	if v, _ := db.GetSetting(settingEnabled); strings.EqualFold(strings.TrimSpace(v), "off") {
		return false
	}
	return true
}

func triggerRegex() *regexp.Regexp {
	if v, _ := db.GetSetting(settingTrigger); strings.TrimSpace(v) != "" {
		if re, err := regexp.Compile(v); err == nil {
			return re
		}
	}
	return defaultRe
}

// MatchesTemplate reports whether a nuclei template-ID is an API-doc exposure.
func MatchesTemplate(templateID string) bool {
	return triggerRegex().MatchString(templateID)
}

// Offer queues a matched documentation URL for testing. Non-blocking: a full
// queue drops the job (the next hit on the same URL re-offers it) so the scan
// pipeline never stalls on us.
func Offer(templateID, matchedURL string) {
	if !Enabled() || !MatchesTemplate(templateID) {
		return
	}
	raw := strings.TrimSpace(matchedURL)
	if raw == "" || !strings.HasPrefix(raw, "http") {
		return
	}
	if err := utils.ValidatePublicHTTPURL(raw); err != nil {
		log().Infof("[API-TEST] skipping non-public doc URL %s: %v", raw, err)
		return
	}
	once.Do(startWorker)
	seenMu.Lock()
	if seenMap == nil {
		seenMap = loadSeen()
	}
	k := normalizeDocURL(raw)
	if t, ok := seenMap[k]; ok && time.Since(t) < 24*time.Hour {
		seenMu.Unlock()
		return // already tested within the dedupe window
	}
	if t, ok := failCooldown[k]; ok && time.Since(t) < 30*time.Minute {
		seenMu.Unlock()
		return // recent fetch/parse failure — let the cooldown expire
	}
	seenMap[k] = time.Now()
	seenMu.Unlock()

	select {
	case queue <- docJob{TemplateID: templateID, DocURL: raw}:
	default:
		log().Infof("[API-TEST] queue full, dropping %s", raw)
	}
}

// OfferFromFile scans a nuclei JSONL result file for API-doc template hits and
// queues each matched URL (used by the per-domain nuclei wrapper, which has no
// per-result callback).
func OfferFromFile(jsonPath string) {
	if !Enabled() {
		return
	}
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ev struct {
			TemplateID string `json:"template-id"`
			MatchedAt  string `json:"matched-at"`
			Host       string `json:"host"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.TemplateID == "" {
			continue
		}
		m := ev.MatchedAt
		if m == "" {
			m = ev.Host
		}
		if m != "" && strings.HasPrefix(m, "http") {
			Offer(ev.TemplateID, m)
		}
	}
}

func normalizeDocURL(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/")
	}
	return raw
}

func loadSeen() map[string]time.Time {
	m := map[string]time.Time{}
	if v, _ := db.GetSetting(settingSeen); v != "" {
		_ = json.Unmarshal([]byte(v), &m)
	}
	return m
}

func persistSeen() {
	seenMu.Lock()
	defer seenMu.Unlock()
	if len(seenMap) == 0 {
		return
	}
	cut := time.Now().AddDate(0, 0, -seenPruneDays)
	for k, t := range seenMap {
		if t.Before(cut) || len(seenMap) > seenCap {
			delete(seenMap, k)
		}
	}
	if b, err := json.Marshal(seenMap); err == nil {
		_ = db.SetSetting(settingSeen, string(b))
	}
}

func startWorker() {
	queue = make(chan docJob, queueSize)
	go func() {
		for job := range queue {
			if err := runTests(job); err != nil {
				// Failed fetch/parse: unmark so a later hit retries (a 24h dedupe
				// mark on failure would permanently swallow the doc), but cool the
				// URL down for 30 min so one scan's repeated hits don't hot-loop.
				seenMu.Lock()
				delete(seenMap, normalizeDocURL(job.DocURL))
				failCooldown[normalizeDocURL(job.DocURL)] = time.Now()
				seenMu.Unlock()
				log().Infof("[API-TEST] %s: %v (will retry on a later hit)", job.DocURL, err)
			}
			persistSeen()
		}
	}()
}

// ---- OpenAPI / Swagger parsing ----

type apiDoc struct {
	BaseURL string // origin + basePath/servers, no trailing slash
	Paths   []pathMethod
	Title   string
	Version string
}

type pathMethod struct {
	Method string
	Path   string // documented path, {params} intact
	Query  url.Values
	Params map[string]string // path param name -> substituted value
	OpID   string
}

type swaggerDoc struct {
	Swagger string `json:"swagger"`
	OpenAPI string `json:"openapi"`
	Info    struct {
		Title   string `json:"title"`
		Version string `json:"version"`
	} `json:"info"`
	Host     string   `json:"host"`
	BasePath string   `json:"basePath"`
	Schemes  []string `json:"schemes"`
	Servers  []struct {
		URL string `json:"url"`
	} `json:"servers"`
	Paths map[string]map[string]json.RawMessage `json:"paths"`
}

var httpMethods = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true,
	"patch": true, "options": true, "head": true,
}

func parseAPIDoc(body []byte, docURL string) (*apiDoc, error) {
	var d swaggerDoc
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("not valid JSON (HTML api-docs pages are not machine-testable): %w", err)
	}
	if len(d.Paths) == 0 {
		return nil, fmt.Errorf("no paths object in document")
	}
	u, err := url.Parse(docURL)
	if err != nil {
		return nil, err
	}
	origin := u.Scheme + "://" + u.Host

	doc := &apiDoc{Title: d.Info.Title, Version: d.Info.Version}
	switch {
	case d.Swagger != "": // Swagger 2.0
		host := d.Host
		if host == "" {
			host = u.Host
		}
		scheme := "https"
		if len(d.Schemes) > 0 {
			scheme = d.Schemes[0]
		}
		doc.BaseURL = strings.TrimRight(scheme+"://"+host+d.BasePath, "/")
		if d.BasePath == "" && d.Host == "" {
			doc.BaseURL = origin
		}
	case len(d.Servers) > 0 && strings.TrimSpace(d.Servers[0].URL) != "":
		s := d.Servers[0].URL
		if strings.HasPrefix(s, "http") {
			doc.BaseURL = strings.TrimRight(s, "/")
		} else {
			doc.BaseURL = strings.TrimRight(origin+"/"+strings.Trim(s, "/"), "/")
		}
	default:
		doc.BaseURL = origin
	}

	for p, ops := range d.Paths {
		// Path-level parameters (siblings of the method keys) apply to every
		// operation in the item — methods may omit them.
		pathParams := []struct {
			Name    string      `json:"name"`
			In      string      `json:"in"`
			Example interface{} `json:"example"`
			Default interface{} `json:"default"`
			Schema  struct {
				Example interface{} `json:"example"`
			} `json:"schema"`
		}{}
		if raw, ok := ops["parameters"]; ok {
			_ = json.Unmarshal(raw, &pathParams)
		}
		for m, raw := range ops {
			if !httpMethods[m] {
				continue
			}
			pm := pathMethod{Method: strings.ToUpper(m), Path: p, Params: map[string]string{}}
			var op struct {
				OperationID string `json:"operationId"`
				Parameters  []struct {
					Name    string      `json:"name"`
					In      string      `json:"in"`
					Example interface{} `json:"example"`
					Default interface{} `json:"default"`
					Schema  struct {
						Example interface{} `json:"example"`
					} `json:"schema"`
				} `json:"parameters"`
			}
			_ = json.Unmarshal(raw, &op)
			pm.OpID = op.OperationID
			// method-level params win over path-level
			for _, pr := range append(append([]struct {
				Name    string      `json:"name"`
				In      string      `json:"in"`
				Example interface{} `json:"example"`
				Default interface{} `json:"default"`
				Schema  struct {
					Example interface{} `json:"example"`
				} `json:"schema"`
			}{}, pathParams...), op.Parameters...) {
				val := ""
				for _, cand := range []interface{}{pr.Example, pr.Default, pr.Schema.Example} {
					if cand != nil {
						val = fmt.Sprintf("%v", cand)
						break
					}
				}
				if val == "" {
					val = guessParamValue(pr.Name)
				}
				switch pr.In {
				case "path":
					pm.Params[pr.Name] = val
				case "query":
					if pm.Query == nil {
						pm.Query = url.Values{}
					}
					pm.Query.Set(pr.Name, val)
				}
			}
			doc.Paths = append(doc.Paths, pm)
		}
	}
	return doc, nil
}

func guessParamValue(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "uuid"):
		return "00000000-0000-0000-0000-000000000000"
	case strings.Contains(n, "id"), strings.Contains(n, "page"), strings.Contains(n, "limit"), strings.Contains(n, "size"):
		return "1"
	case strings.Contains(n, "email"):
		return "probe@example.com"
	case strings.Contains(n, "date"):
		return "2026-01-01"
	default:
		return "test"
	}
}

func (pm pathMethod) BuildURL(base string) string {
	p := pm.Path
	for name, val := range pm.Params {
		p = strings.ReplaceAll(p, "{"+name+"}", url.PathEscape(val))
	}
	// leftover {placeholders} (param not documented) get a name-based guess
	p = regexp.MustCompile(`\{([^}]+)\}`).ReplaceAllStringFunc(p, func(m string) string {
		return url.PathEscape(guessParamValue(strings.Trim(m, "{}")))
	})
	u := base + p
	if len(pm.Query) > 0 {
		u += "?" + pm.Query.Encode()
	}
	return u
}

// ---- test execution ----

type endpointResult struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	Len         int    `json:"len"`
	ContentType string `json:"content_type,omitempty"`
	AuthError   bool   `json:"auth_error"`
	Bypassed    bool   `json:"bypassed,omitempty"`
	BypassVia   string `json:"bypass_via,omitempty"`
	Interesting bool   `json:"interesting,omitempty"`
	Sample      string `json:"sample,omitempty"`
}

type bypassHeaders struct {
	Name string
	H    map[string]string
}

var bypassMatrix = []bypassHeaders{
	{"xff", map[string]string{"X-Forwarded-For": "127.0.0.1"}},
	{"custom-ip", map[string]string{"X-Custom-IP-Authorization": "127.0.0.1"}},
	{"original-url", map[string]string{"X-Original-URL": "/", "X-Rewrite-URL": "/"}},
}

// ---- spec discovery for HTML doc pages ----

// specScrapeRes pull the machine-readable spec URL out of a rendered docs UI.
// swagger-ui init: url: "/v2/api-docs" · configUrl: ... · redoc/rapidoc:
// spec-url="..." · scalar: data-url="..." · plus a generic quoted-path catch.
var specScrapeRes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\burl\s*[:=]\s*["']([^"'\s]+\.(?:json|ya?ml))["']`),
	// spec endpoints frequently have no extension (e.g. /v3/api-docs) — accept
	// url: values that name a spec by keyword
	regexp.MustCompile(`(?i)\burl\s*[:=]\s*["']([^"'\s]*(?:api-docs|openapi|swagger|spec)[^"'\s]*)["']`),
	regexp.MustCompile(`(?i)\bspec-url\s*=\s*["']([^"'\s]+)["']`),
	regexp.MustCompile(`(?i)\bdata-url\s*=\s*["']([^"'\s]+\.(?:json|ya?ml))["']`),
	regexp.MustCompile(`(?i)\bconfigUrl\s*[:=]\s*["']([^"'\s]+\.(?:json|ya?ml))["']`),
	regexp.MustCompile(`(?i)["']([^"'\s]*(?:api-docs|openapi|swagger)[^"'\s]*\.(?:json|ya?ml))["']`),
}

// specProbePaths are the conventional spec locations, tried against the origin
// and against the doc page's own directory (FastAPI /docs → /openapi.json).
var specProbePaths = []string{
	"/v3/api-docs", "/v2/api-docs", "/api-docs", "/swagger.json", "/openapi.json",
	"/swagger/v1/swagger.json", "/api/swagger.json", "/api/openapi.json",
	"/api/v3/api-docs", "/api-docs/swagger.json",
}

// looksLikeSpec does a cheap shape check so probes stop at real specs.
func looksLikeSpec(body []byte) bool {
	t := strings.TrimSpace(string(body))
	if !strings.HasPrefix(t, "{") || len(t) < 16 {
		return false
	}
	return strings.Contains(t, "\"paths\"") ||
		strings.Contains(t, "\"openapi\"") || strings.Contains(t, "\"swagger\"")
}

// resolveRef absolutizes a scraped spec reference against the doc page URL.
func resolveRef(pageURL, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "#") {
		return ""
	}
	if strings.HasPrefix(ref, "//") {
		return "https:" + ref
	}
	b, err := url.Parse(pageURL)
	if err != nil {
		return ""
	}
	r, err := b.Parse(ref)
	if err != nil {
		return ""
	}
	return r.String()
}

// findSpecURL locates the JSON/YAML spec behind an HTML docs page: scrape the
// page's own references first (most reliable), then probe conventional paths.
func findSpecURL(client *http.Client, ctx context.Context, pageURL string, pageBody []byte) string {
	for _, re := range specScrapeRes {
		for _, m := range re.FindAllSubmatch(pageBody, 3) {
			if u := resolveRef(pageURL, string(m[1])); u != "" && strings.HasPrefix(u, "http") {
				if err := utils.ValidatePublicHTTPURL(u); err != nil {
					continue
				}
				resp, body, err := send(client, http.MethodGet, u, nil)
				if err == nil && resp.StatusCode == 200 && looksLikeSpec(body) {
					return u
				}
				time.Sleep(150 * time.Millisecond)
			}
		}
	}
	if ctx.Err() != nil {
		return ""
	}
	origin := ""
	pageDir := ""
	if b, err := url.Parse(pageURL); err == nil {
		origin = b.Scheme + "://" + b.Host
		pageDir = strings.TrimRight(origin+path.Dir(b.Path), "/")
	}
	tried := map[string]bool{}
	for _, rel := range append([]string{}, specProbePaths...) {
		for _, base := range []string{origin, pageDir} {
			if base == "" {
				continue
			}
			u := base + rel
			if tried[u] {
				continue
			}
			tried[u] = true
			if err := utils.ValidatePublicHTTPURL(u); err != nil {
				continue
			}
			resp, body, err := send(client, http.MethodGet, u, nil)
			if err == nil && resp.StatusCode == 200 && looksLikeSpec(body) {
				return u
			}
			time.Sleep(150 * time.Millisecond)
			if ctx.Err() != nil {
				return ""
			}
		}
	}
	return ""
}

func send(client *http.Client, method, u string, hdr map[string]string) (*http.Response, []byte, error) {
	var body io.Reader
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		body = strings.NewReader("{}")
	}
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; AutoAR-APITest/1.0)")
	req.Header.Set("Accept", "application/json, */*")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespSampleBytes))
	return resp, data, nil
}

func isAuthError(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return true
	}
	return resp.Header.Get("WWW-Authenticate") != "" && resp.StatusCode >= 400
}

func redact(s string) string {
	return redactRe.ReplaceAllString(s, "$1[REDACTED]")
}

func runTests(job docJob) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			log().Errorf("[API-TEST] panic testing %s: %v", job.DocURL, r)
			retErr = fmt.Errorf("panic: %v", r)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), perDocDeadline)
	defer cancel()

	log().Infof("[API-TEST] testing %s (via %s)", job.DocURL, job.TemplateID)
	client := utils.NewPublicHTTPClient(requestTimeout)
	resp, data, err := send(client, http.MethodGet, job.DocURL, nil)
	if err != nil || resp.StatusCode != 200 {
		return fmt.Errorf("doc fetch failed: status=%v err=%v", statusOf(resp), err)
	}
	doc, parseErr := parseAPIDoc(data, job.DocURL)
	if parseErr != nil {
		// HTML doc page (swagger-ui / redoc / rapidoc / scalar UIs) — find the
		// machine-readable spec it renders: scrape the page for spec references
		// first, then probe the conventional spec paths.
		specURL := findSpecURL(client, ctx, job.DocURL, data)
		if specURL == "" {
			return fmt.Errorf("no parseable spec (HTML page, no discoverable spec URL): %v", parseErr)
		}
		sresp, sdata, serr := send(client, http.MethodGet, specURL, nil)
		if serr != nil || sresp.StatusCode != 200 {
			return fmt.Errorf("discovered spec %s not fetchable: status=%v err=%v", specURL, statusOf(sresp), serr)
		}
		doc, parseErr = parseAPIDoc(sdata, specURL)
		if parseErr != nil {
			return fmt.Errorf("discovered spec %s unparseable: %v", specURL, parseErr)
		}
		job.SpecURL = specURL
		log().Infof("[API-TEST] %s: using discovered spec %s", job.DocURL, specURL)
	}

	maxEndpoints := db.GetSettingInt("API_DOCS_MAX_ENDPOINTS", defaultMaxEndpoints)
	paths := doc.Paths
	if len(paths) > maxEndpoints {
		paths = paths[:maxEndpoints]
	}
	host := job.DocURL
	if u, err := url.Parse(job.DocURL); err == nil {
		host = u.Host
	}

	// soft-404 canary: a random nonexistent path; endpoints whose status+length
	// match it are discounted (catch-all routes / SPA fallbacks).
	_, canaryBody, _ := send(client, http.MethodGet, doc.BaseURL+"/api-probe-canary-"+fmt.Sprintf("%d", time.Now().UnixNano()%1e6), nil)
	canaryLen := len(canaryBody)

	results := make([]endpointResult, 0, len(paths))
	accessible, bypassed, interesting := 0, 0, 0
	for _, pm := range paths {
		if ctx.Err() != nil {
			break
		}
		u := pm.BuildURL(doc.BaseURL)
		if err := utils.ValidatePublicHTTPURL(u); err != nil {
			continue
		}
		r, rdata, err := send(client, pm.Method, u, nil)
		time.Sleep(200 * time.Millisecond) // politeness
		if err != nil {
			continue
		}
		res := endpointResult{
			Method:      pm.Method,
			Path:        pm.Path,
			URL:         u,
			Status:      r.StatusCode,
			Len:         len(rdata),
			ContentType: r.Header.Get("Content-Type"),
			AuthError:   isAuthError(r),
			Interesting: interestRe.MatchString(pm.Path),
		}
		sample := string(rdata)
		if len(sample) > 160 {
			sample = sample[:160] + "…"
		}
		res.Sample = redact(strings.TrimSpace(sample))

		if res.AuthError {
			// auth-bypass retries: if any header set flips 401/403 → 2xx, flag it
			for _, bh := range bypassMatrix {
				br, bdata, berr := send(client, pm.Method, u, bh.H)
				time.Sleep(200 * time.Millisecond)
				if berr == nil && br != nil && br.StatusCode >= 200 && br.StatusCode < 300 {
					res.Bypassed = true
					res.BypassVia = bh.Name
					bs := string(bdata)
					if len(bs) > 160 {
						bs = bs[:160] + "…"
					}
					res.Sample = redact(strings.TrimSpace(bs))
					break
				}
			}
		}

		soft404 := r.StatusCode == 200 && canaryLen > 0 && len(data) == canaryLen
		if (r.StatusCode >= 200 && r.StatusCode < 300 && !soft404) || res.Bypassed {
			if len(data) > 0 {
				accessible++
			}
			if res.Interesting {
				interesting++
			}
			if res.Bypassed {
				bypassed++
			}
		}
		results = append(results, res)
	}

	if len(results) == 0 {
		return
	}

	// persist artifact for AI triage
	outDir := filepath.Join(utils.GetResultsDir(), "global-subdomains", "api-tests")
	_ = os.MkdirAll(outDir, 0o755)
	fname := fmt.Sprintf("%s-%d.json", sanitize(host), time.Now().Unix())
	artifact := map[string]interface{}{
		"doc_url": job.DocURL, "spec_url": job.SpecURL, "template_id": job.TemplateID,
		"title": doc.Title, "version": doc.Version, "base_url": doc.BaseURL,
		"endpoints_in_doc": len(doc.Paths), "tested": len(results),
		"accessible": accessible, "bypassed": bypassed, "interesting": interesting,
		"results": results, "tested_at": time.Now().UTC().Format(time.RFC3339),
	}
	b, _ := json.MarshalIndent(artifact, "", "  ")
	_ = os.WriteFile(filepath.Join(outDir, fname), b, 0o644)

	if accessible == 0 {
		log().Infof("[API-TEST] %s: %d endpoints tested, none accessible unauth — artifact only", host, len(results))
		return nil
	}
	notifyDiscord(host, job, len(doc.Paths), len(results), accessible, bypassed, interesting, results, fname)
	return nil
}

func statusOf(r *http.Response) int {
	if r == nil {
		return 0
	}
	return r.StatusCode
}

func sanitize(s string) string {
	s = strings.ToLower(s)
	s = regexp.MustCompile(`[^a-z0-9.-]+`).ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

func notifyDiscord(host string, job docJob, total, tested, accessible, bypassed, interesting int, results []endpointResult, fname string) {
	var b strings.Builder
	fmt.Fprintf(&b, "🔌 **Unauth API access audit: `%s`**\n", host)
	fmt.Fprintf(&b, "Doc: <%s> (via `%s`, %d endpoints in doc, %d tested)\n", job.DocURL, job.TemplateID, total, tested)
	fmt.Fprintf(&b, "**2xx without auth: %d** • bypass-success: %d • interesting paths: %d\n", accessible, bypassed, interesting)

	// prioritize: bypass successes first, then interesting paths, then any 2xx
	pick := func(f func(endpointResult) bool, n int) []endpointResult {
		out := []endpointResult{}
		for _, r := range results {
			if f(r) && len(out) < n {
				out = append(out, r)
			}
		}
		return out
	}
	samples := append(
		pick(func(r endpointResult) bool { return r.Bypassed }, 3),
		pick(func(r endpointResult) bool { return !r.Bypassed && r.Interesting && r.Status >= 200 && r.Status < 300 }, 5)...,
	)
	if len(samples) < 8 {
		samples = append(samples, pick(func(r endpointResult) bool {
			return !r.Bypassed && !r.Interesting && r.Status >= 200 && r.Status < 300 && r.Len > 0
		}, 8-len(samples))...)
	}
	for _, s := range samples {
		tag := ""
		if s.Bypassed {
			tag = " 🔓bypass:" + s.BypassVia
		}
		if s.Interesting {
			tag += " ⭐"
		}
		fmt.Fprintf(&b, "• `%s %s` → %d (%dB)%s `%s`\n", s.Method, s.Path, s.Status, s.Len, tag, s.Sample)
	}
	fmt.Fprintf(&b, "Full results: `new-results/global-subdomains/api-tests/%s` (AI triage pending)", fname)
	utils.SendMonitorWebhook(b.String())
}
