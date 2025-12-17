package misconfigmapper

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// --- Types mirrored from misconfig-mapper ---

// Service represents a service configuration from the template file.
type Service struct {
	ID      int64 `json:"id"`
	Request struct {
		Method  string              `json:"method"`
		BaseURL string              `json:"baseURL"`
		Path    []string            `json:"path"`
		Headers []map[string]string `json:"headers"`
		Body    any                 `json:"body"`
	} `json:"request"`
	Response struct {
		StatusCode            interface{} `json:"statusCode"`
		DetectionFingerprints []string    `json:"detectionFingerprints"`
		Fingerprints          []string    `json:"fingerprints"`
		ExclusionPatterns     []string    `json:"exclusionPatterns,omitempty"`
	} `json:"response"`
	Metadata struct {
		Service           string   `json:"service"`
		ServiceName       string   `json:"serviceName"`
		Description       string   `json:"description"`
		ReproductionSteps []string `json:"reproductionSteps"`
		References        []string `json:"references"`
	} `json:"metadata"`
}

// Result represents a scan result.
type Result struct {
	URL        string  `json:"url"`
	Exists     bool    `json:"exists"`
	Vulnerable bool    `json:"vulnerable"`
	ServiceID  string  `json:"serviceid"`
	Service    Service `json:"service"`
}

// --- Template management ---

const templatesURL = "https://raw.githubusercontent.com/intigriti/misconfig-mapper/main/templates/services.json"

// Manager handles loading and updating service templates.
type Manager struct {
	TemplatesDir string
	ServicesPath string
}

func NewManager(templatesDir string) *Manager {
	return &Manager{
		TemplatesDir: templatesDir,
		ServicesPath: filepath.Join(templatesDir, "services.json"),
	}
}

func (m *Manager) LoadTemplates() ([]Service, error) {
	var services []Service

	file, err := os.Open(m.ServicesPath)
	if err != nil {
		return services, fmt.Errorf("failed opening file '%s': %w", m.ServicesPath, err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&services); err != nil {
		return services, fmt.Errorf("failed decoding JSON file: %w", err)
	}

	return services, nil
}

// UpdateTemplates fetches services.json from GitHub and writes it to TemplatesDir.
// If update == true, it truncates the existing file; otherwise it creates the
// directory and file if needed.
func (m *Manager) UpdateTemplates(update bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, templatesURL, nil)
	if err != nil {
		return err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if res == nil {
		return fmt.Errorf("empty response received")
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	var f *os.File
	if update {
		f, err = os.OpenFile(m.ServicesPath, os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return fmt.Errorf("failed to open services file: %w", err)
		}
		defer f.Close()
	} else {
		if err := os.MkdirAll(m.TemplatesDir, 0o755); err != nil {
			return fmt.Errorf("failed to create templates directory: %w", err)
		}
		f, err = os.Create(m.ServicesPath)
		if err != nil {
			return fmt.Errorf("failed to create services file: %w", err)
		}
		defer f.Close()
	}

	if _, err := f.Write(body); err != nil {
		return fmt.Errorf("failed to write services file: %w", err)
	}

	return nil
}

// GetService filters services by comma-separated IDs or service names. "*" returns all.
func (m *Manager) GetService(ids string, services []Service) []Service {
	if ids == "*" {
		return services
	}

	var result []Service
	parsed := strings.Split(ids, ",")

	for _, service := range services {
		for _, id := range parsed {
			id = strings.TrimSpace(id)
			if fmt.Sprintf("%v", service.ID) == id || strings.EqualFold(service.Metadata.Service, id) {
				result = append(result, service)
				break
			}
		}
	}

	return result
}

// ParseRegex transforms an array of patterns into a regex string.
func ParseRegex(v []string) string {
	x := strings.Join(v, "|")
	x = strings.ReplaceAll(x, ".", `\.`)
	return x
}

// --- HTTP client and response evaluation ---

// HTTPClient handles HTTP requests to services.
type HTTPClient struct {
	Client     *http.Client
	Timeout    int
	Headers    map[string]string
	SkipChecks bool
}

// NewHTTPClient creates a new HTTP client.
func NewHTTPClient(timeout, maxRedirects int, headers map[string]string, skipChecks bool, skipSSL bool) *HTTPClient {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("too many redirects encountered")
			}
			return nil
		},
		Timeout: time.Duration(timeout) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipSSL},
		},
	}

	return &HTTPClient{
		Client:     client,
		Timeout:    timeout,
		Headers:    headers,
		SkipChecks: skipChecks,
	}
}

// CheckResponse checks if a service is present / vulnerable and updates result.
func (c *HTTPClient) CheckResponse(result *Result, service *Service) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.Timeout)*time.Millisecond)
	defer cancel()

	var requestBody io.Reader
	if service.Request.Body != nil {
		requestBody = bytes.NewBuffer([]byte(fmt.Sprintf("%v", service.Request.Body)))
	}

	req, err := http.NewRequestWithContext(ctx, service.Request.Method, result.URL, requestBody)
	if err != nil {
		result.Vulnerable = false
		result.Exists = false
		return
	}

	// Headers from service template
	for _, header := range service.Request.Headers {
		for key, value := range header {
			req.Header.Set(key, value)
		}
	}

	// Custom headers override
	for key, value := range c.Headers {
		req.Header.Set(key, value)
	}

	req.Header.Set("Connection", "close")

	res, err := c.Client.Do(req)
	if err != nil || res == nil {
		result.Exists = false
		result.Vulnerable = false
		return
	}
	defer res.Body.Close()

	// Status code matching
	statusCodeMatched := false
	switch v := service.Response.StatusCode.(type) {
	case []interface{}:
		for _, ccode := range v {
			if int(ccode.(float64)) == res.StatusCode {
				statusCodeMatched = true
				break
			}
		}
	case float64:
		if res.StatusCode == int(v) {
			statusCodeMatched = true
		}
	}

	// Headers
	var responseHeaders string
	for key, values := range res.Header {
		for _, value := range values {
			responseHeaders += fmt.Sprintf("%v: %v\n", key, value)
		}
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return
	}

	// Exclusion patterns first
	if len(service.Response.ExclusionPatterns) > 0 {
		exclusionExpr := ParseRegex(service.Response.ExclusionPatterns)
		exclusionRe, err := regexp.Compile(exclusionExpr)
		if err == nil && exclusionRe.Match(body) {
			result.Exists = false
			result.Vulnerable = false
			return
		}
	}

	fullResponse := append([]byte(responseHeaders), body...)

	if c.SkipChecks {
		// Detection-only mode
		expr := ParseRegex(service.Response.DetectionFingerprints)
		re, err := regexp.Compile(expr)
		if err != nil {
			return
		}
		result.Exists = re.Match(fullResponse)
		return
	}

	// Vulnerability fingerprints
	expr := ParseRegex(service.Response.Fingerprints)
	re, err := regexp.Compile(expr)
	if err != nil {
		return
	}

	result.Vulnerable = re.Match(fullResponse) && statusCodeMatched
	result.Exists = result.Vulnerable
}

// --- Scanner ---

// Common domain suffixes for permutation generation.
var suffixes = []string{
	"com", "net", "org", "io", "fr", "ltd", "app", "prod", "internal",
	"dev", "development", "devops", "logs", "logging", "admin", "log",
	"stage", "staging", "stg", "production", "dev-only", "cicd",
	"employee-only", "testing", "secret", "kibana", "employees",
	"partners", "sso", "saml", "tickets", "issues", "oauth2",
}

// Scanner manages the scanning process.
type Scanner struct {
	Target           string
	AsDomain         bool
	EnablePerms      bool
	SkipChecks       bool
	Client           *HTTPClient
	RateLimiter      *rate.Limiter
	SelectedServices []Service
	OnResult         func(*Result)
}

func NewScanner(target string, asDomain, enablePerms, skipChecks bool, httpClient *HTTPClient, delay int) *Scanner {
	var limiter *rate.Limiter
	if delay > 0 {
		limiter = rate.NewLimiter(rate.Every(time.Duration(delay)*time.Millisecond), 1)
	}

	return &Scanner{
		Target:      target,
		AsDomain:    asDomain,
		EnablePerms: enablePerms,
		SkipChecks:  skipChecks,
		Client:      httpClient,
		RateLimiter: limiter,
	}
}

func (s *Scanner) SetSelectedServices(services []Service) {
	s.SelectedServices = services
}

// GenerateTargets generates potential target domains based on the input.
func (s *Scanner) GenerateTargets() ([]string, error) {
	var possibleTargets []string

	// If Target is a file path, treat lines as targets
	if isFile(s.Target) {
		targets, err := s.loadTargetsFromFile(s.Target)
		if err != nil {
			return nil, err
		}
		if s.EnablePerms {
			for _, t := range targets {
				possibleTargets = append(possibleTargets, s.generatePermutations(t)...)
			}
		} else {
			possibleTargets = targets
		}
	} else {
		if s.EnablePerms {
			possibleTargets = s.generatePermutations(s.Target)
		} else {
			possibleTargets = []string{s.Target}
		}
	}

	return possibleTargets, nil
}

func (s *Scanner) loadTargetsFromFile(filePath string) ([]string, error) {
	var targets []string

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			targets = append(targets, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return targets, nil
}

func (s *Scanner) generatePermutations(target string) []string {
	var permutations []string
	permutations = append(permutations, target)
	target = strings.TrimSpace(strings.ToLower(target))

	for _, suffix := range suffixes {
		for _, connector := range []string{".", "-", ""} {
			permutations = append(permutations, fmt.Sprintf("%s%s%s", target, connector, suffix))
		}
	}
	return permutations
}

func (s *Scanner) craftTargetURL(baseURL, path, domain string) (string, error) {
	var targetURL string

	if s.EnablePerms || !s.AsDomain {
		// Normalize domain (remove protocol)
		domain = regexp.MustCompile(`^https?://`).ReplaceAllString(domain, "")
		targetURL = strings.Replace(fmt.Sprintf("%v%v", baseURL, path), "{TARGET}", domain, -1)
	} else {
		if !strings.HasPrefix(domain, "http") {
			domain = fmt.Sprintf("https://%v", domain)
		}
		u, err := url.Parse(domain)
		if err != nil {
			return "", fmt.Errorf("invalid URL: %w", err)
		}
		u.Path = path
		targetURL = u.String()
	}

	return targetURL, nil
}

// ScanTargets performs the scan operation across all services and targets.
func (s *Scanner) ScanTargets() error {
	targets, err := s.GenerateTargets()
	if err != nil {
		return fmt.Errorf("failed to generate targets: %w", err)
	}

	for _, service := range s.SelectedServices {
		for _, target := range targets {
			for _, path := range service.Request.Path {
				if s.RateLimiter != nil {
					_ = s.RateLimiter.Wait(context.Background())
				}

				if s.SkipChecks {
					path = "/"
				}

				targetURL, err := s.craftTargetURL(service.Request.BaseURL, path, target)
				if err != nil {
					continue
				}

				parsedURL, err := url.Parse(targetURL)
				if err != nil {
					continue
				}

				res := Result{
					URL:       parsedURL.String(),
					ServiceID: fmt.Sprintf("%d", service.ID),
					Service:   service,
				}

				s.Client.CheckResponse(&res, &service)

				if res.Exists || res.Vulnerable {
					if s.OnResult != nil {
						s.OnResult(&res)
					}
					break
				}
			}
		}
	}

	return nil
}

// --- Public API wrappers used by AutoAR ---

// ScanOptions contains a minimal set of options for running a scan.
type ScanOptions struct {
	Target        string
	ServiceID     string
	Delay         int
	TemplatesPath string
	AsDomain      bool
	EnablePerms   bool
	SkipChecks    bool
	Timeout       int
	MaxRedirects  int
	SkipSSL       bool
}

// ScanResult is a simplified representation of a misconfig finding.
type ScanResult struct {
	URL         string
	Exists      bool
	Vulnerable  bool
	ServiceID   string
	ServiceName string
	Description string
	References  []string
}

// Scan runs a misconfig scan and returns all positive results.
func Scan(opts ScanOptions) ([]ScanResult, error) {
	if strings.TrimSpace(opts.Target) == "" {
		return nil, fmt.Errorf("target is required")
	}
	if opts.TemplatesPath == "" {
		opts.TemplatesPath = "./templates"
	}
	if opts.Timeout == 0 {
		opts.Timeout = 7000
	}
	if opts.MaxRedirects == 0 {
		opts.MaxRedirects = 5
	}

	mgr := NewManager(opts.TemplatesPath)
	services, err := mgr.LoadTemplates()
	if err != nil {
		// Try to pull latest templates once
		if err := mgr.UpdateTemplates(false); err != nil {
			return nil, fmt.Errorf("failed to pull latest services: %w", err)
		}
		services, err = mgr.LoadTemplates()
		if err != nil {
			return nil, fmt.Errorf("failed to load services: %w", err)
		}
	}

	if opts.ServiceID == "" {
		opts.ServiceID = "*"
	}
	selected := mgr.GetService(opts.ServiceID, services)
	if len(selected) == 0 {
		return nil, fmt.Errorf("no services selected for id %q", opts.ServiceID)
	}

	httpClient := NewHTTPClient(opts.Timeout, opts.MaxRedirects, map[string]string{}, opts.SkipChecks, opts.SkipSSL)

	scn := NewScanner(opts.Target, opts.AsDomain, opts.EnablePerms, opts.SkipChecks, httpClient, opts.Delay)
	scn.SetSelectedServices(selected)

	var out []ScanResult
	scn.OnResult = func(r *Result) {
		out = append(out, ScanResult{
			URL:         r.URL,
			Exists:      r.Exists,
			Vulnerable:  r.Vulnerable,
			ServiceID:   r.ServiceID,
			ServiceName: r.Service.Metadata.ServiceName,
			Description: r.Service.Metadata.Description,
			References:  append([]string{}, r.Service.Metadata.References...),
		})
	}

	if err := scn.ScanTargets(); err != nil {
		return out, err
	}
	return out, nil
}

// UpdateTemplates ensures the services.json file exists and is up to date.
func UpdateTemplates(templatesPath string) error {
	if templatesPath == "" {
		templatesPath = "./templates"
	}
	mgr := NewManager(templatesPath)
	serviceFilePath := filepath.Join(templatesPath, "services.json")
	fileExists := isFile(serviceFilePath)
	return mgr.UpdateTemplates(fileExists)
}

// ServiceInfo is a lightweight descriptor of a service.
type ServiceInfo struct {
	ID          int64
	Service     string
	ServiceName string
}

// ListServices returns basic information about all available services.
func ListServices(templatesPath string) ([]ServiceInfo, error) {
	if templatesPath == "" {
		templatesPath = "./templates"
	}
	mgr := NewManager(templatesPath)
	services, err := mgr.LoadTemplates()
	if err != nil {
		return nil, err
	}

	infos := make([]ServiceInfo, 0, len(services))
	for _, s := range services {
		infos = append(infos, ServiceInfo{
			ID:          s.ID,
			Service:     s.Metadata.Service,
			ServiceName: s.Metadata.ServiceName,
		})
	}
	return infos, nil
}

// --- small helpers ---

func isFile(path string) bool {
	if filepath.Ext(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
