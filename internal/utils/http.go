package utils

import (
	"net/http"
	"time"
)

// GlobalHTTPClient is a shared HTTP client with connection pooling
// This improves performance by reusing connections instead of creating new ones
var GlobalHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,              // Maximum idle connections across all hosts
		MaxIdleConnsPerHost: 10,               // Maximum idle connections per host
		IdleConnTimeout:     90 * time.Second, // How long idle connections stay open
		DisableCompression:  false,            // Enable compression
		DisableKeepAlives:   false,            // Enable keep-alives for connection reuse
		MaxConnsPerHost:     0,                // No limit on connections per host
	},
}

// GetHTTPClient returns the global HTTP client with connection pooling
func GetHTTPClient() *http.Client {
	return GlobalHTTPClient
}

// CreateCustomHTTPClient creates an HTTP client with custom timeout
func CreateCustomHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  false,
			DisableKeepAlives:   false,
		},
	}
}
