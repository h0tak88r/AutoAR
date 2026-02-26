package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ExtractSubdomains extracts subdomains matching the target domain from a string
func ExtractSubdomains(text, domain string) []string {
	re := regexp.MustCompile(fmt.Sprintf(`[a-zA-Z0-9._-]+\.%s`, regexp.QuoteMeta(domain)))
	matches := re.FindAllString(text, -1)
	
	unique := make(map[string]bool)
	var results []string
	for _, m := range matches {
		m = strings.ToLower(strings.TrimSpace(m))
		if !unique[m] {
			unique[m] = true
			results = append(results, m)
		}
	}
	return results
}

// SecurityTrailsSource implements a custom source for SecurityTrails
type SecurityTrailsSource struct {
	apiKey string
	client *http.Client
}

func NewSecurityTrailsSource(apiKey string) *SecurityTrailsSource {
	return &SecurityTrailsSource{
		apiKey: apiKey,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

type securityTrailsResponse struct {
	Subdomains []string `json:"subdomains"`
}

func (s *SecurityTrailsSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains?children_only=false", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("accept", "application/json")
	req.Header.Set("apikey", s.apiKey)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("securitytrails returned status %d", resp.StatusCode)
	}

	var stResp securityTrailsResponse
	if err := json.NewDecoder(resp.Body).Decode(&stResp); err != nil {
		return nil, err
	}

	var results []string
	for _, sub := range stResp.Subdomains {
		results = append(results, fmt.Sprintf("%s.%s", sub, domain))
	}

	return results, nil
}

// AlienVaultSource implements a custom source for AlienVault OTX
type AlienVaultSource struct {
	client *http.Client
}

func NewAlienVaultSource() *AlienVaultSource {
	return &AlienVaultSource{client: &http.Client{Timeout: 30 * time.Second}}
}

func (s *AlienVaultSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return ExtractSubdomains(string(body), domain), nil
}

// AnubisSource implements a custom source for Anubis (jldc.me)
type AnubisSource struct {
	client *http.Client
}

func NewAnubisSource() *AnubisSource {
	return &AnubisSource{client: &http.Client{Timeout: 30 * time.Second}}
}

func (s *AnubisSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return ExtractSubdomains(string(body), domain), nil
}

// HackerTargetSource implements a custom source for HackerTarget
type HackerTargetSource struct {
	client *http.Client
}

func NewHackerTargetSource() *HackerTargetSource {
	return &HackerTargetSource{client: &http.Client{Timeout: 30 * time.Second}}
}

func (s *HackerTargetSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return ExtractSubdomains(string(body), domain), nil
}

// WaybackSource implements a custom source for Wayback Machine
type WaybackSource struct {
	client *http.Client
}

func NewWaybackSource() *WaybackSource {
	return &WaybackSource{client: &http.Client{Timeout: 30 * time.Second}}
}

func (s *WaybackSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return ExtractSubdomains(string(body), domain), nil
}

// RapidDNSSource implements a custom source for RapidDNS
type RapidDNSSource struct {
	client *http.Client
}

func NewRapidDNSSource() *RapidDNSSource {
	return &RapidDNSSource{client: &http.Client{Timeout: 30 * time.Second}}
}

func (s *RapidDNSSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1#result", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return ExtractSubdomains(string(body), domain), nil
}
