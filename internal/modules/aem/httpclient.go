package aem

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPClient wraps HTTP client functionality for AEM scanning
type HTTPClient struct {
	client      *http.Client
	proxyURL    *url.URL
	extraHeaders map[string]string
	debug       bool
}

// NewHTTPClient creates a new HTTP client for AEM scanning
func NewHTTPClient(proxy string, debug bool) (*HTTPClient, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: false,
	}

	var proxyURL *url.URL
	if proxy != "" {
		var err error
		proxyURL, err = url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   40 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	return &HTTPClient{
		client:      client,
		proxyURL:    proxyURL,
		extraHeaders: make(map[string]string),
		debug:       debug,
	}, nil
}

// SetExtraHeaders sets additional headers to include in requests
func (c *HTTPClient) SetExtraHeaders(headers map[string]string) {
	c.extraHeaders = headers
}

// Request performs an HTTP request
func (c *HTTPClient) Request(method, targetURL string, body io.Reader, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, targetURL, body)
	if err != nil {
		return nil, err
	}

	// Set default User-Agent
	req.Header.Set("User-Agent", "curl/7.30.0")

	// Set extra headers
	for k, v := range c.extraHeaders {
		if _, exists := headers[k]; !exists {
			req.Header.Set(k, v)
		}
	}

	// Set request-specific headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	if c.debug {
		fmt.Printf(">> Sending %s %s\n", method, targetURL)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	if c.debug {
		fmt.Printf("<< Received HTTP-%d\n", resp.StatusCode)
	}

	return resp, nil
}

// Get performs a GET request
func (c *HTTPClient) Get(targetURL string, headers map[string]string) (*http.Response, error) {
	return c.Request("GET", targetURL, nil, headers)
}

// Post performs a POST request
func (c *HTTPClient) Post(targetURL string, body io.Reader, headers map[string]string) (*http.Response, error) {
	return c.Request("POST", targetURL, body, headers)
}

// PostForm performs a POST request with form data
func (c *HTTPClient) PostForm(targetURL string, data map[string]string, headers map[string]string) (*http.Response, error) {
	values := url.Values{}
	for k, v := range data {
		values.Set(k, v)
	}
	body := strings.NewReader(values.Encode())
	
	if headers == nil {
		headers = make(map[string]string)
	}
	headers["Content-Type"] = "application/x-www-form-urlencoded"
	
	return c.Post(targetURL, body, headers)
}

// NormalizeURL normalizes a base URL and path
func NormalizeURL(baseURL, path string) string {
	if strings.HasSuffix(baseURL, "/") && (strings.HasPrefix(path, "/") || strings.HasPrefix(path, "\\")) {
		return baseURL[:len(baseURL)-1] + path
	}
	return baseURL + path
}

// ContentType extracts the content type from a Content-Type header
func ContentType(ct string) string {
	parts := strings.Split(ct, ";")
	if len(parts) > 0 {
		return strings.ToLower(strings.TrimSpace(parts[0]))
	}
	return ""
}

// BasicAuth creates a Basic Auth header value
func BasicAuth(username, password string) string {
	auth := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

// RandomString generates a random string of given length
func RandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[i%len(charset)]
	}
	return string(b)
}


