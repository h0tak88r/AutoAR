package utils

import (
	"crypto/tls"
	"net"
	"net/http"
	"runtime"
	"time"
)

// defaultTransport returns a tuned *http.Transport suitable for the shared
// global client.  Key design choices:
//
//   - MaxIdleConns / MaxIdleConnsPerHost are sized relative to GOMAXPROCS so
//     the pool scales naturally on multi-core hosts without wasting file
//     descriptors on single-core containers.
//   - TLSHandshakeTimeout / ExpectContinueTimeout bound the slow-path SSL and
//     "100 Continue" interactions that are not covered by the top-level client
//     Timeout.
//   - ForceAttemptHTTP2 lets the transport negotiate h2 when the server
//     supports it, reducing connection overhead.
//   - KeepAlive in the dialer matches the IdleConnTimeout so lingering OS
//     sockets are cleaned up on the same schedule as the pool entries.
func defaultTransport() *http.Transport {
	maxIdle := 16 * runtime.GOMAXPROCS(0) // scale with CPU count
	if maxIdle < 64 {
		maxIdle = 64
	}

	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second, // TCP connect timeout
			KeepAlive: 90 * time.Second, // matches IdleConnTimeout
		}).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		TLSHandshakeTimeout:   10 * time.Second,
		MaxIdleConns:          maxIdle,
		MaxIdleConnsPerHost:   maxIdle / 4, // ≥1 host gets a fair share
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    false, // gzip/br accepted by default
		DisableKeepAlives:     false, // connection reuse enabled
		ForceAttemptHTTP2:     true,  // prefer h2 when negotiable
	}
}

// GlobalHTTPClient is the process-wide shared HTTP client.
// It uses a connection-pooled transport tuned for concurrent scan workloads.
// Callers should not mutate the client or its transport after initialisation.
// Use CreateCustomHTTPClient when a non-default timeout or transport is needed.
var GlobalHTTPClient = &http.Client{
	Timeout:   30 * time.Second,
	Transport: defaultTransport(),
}

// GetHTTPClient returns the process-wide shared HTTP client.
// The returned client must not be mutated by callers.
func GetHTTPClient() *http.Client {
	return GlobalHTTPClient
}

// CreateCustomHTTPClient creates an independent HTTP client with the given
// timeout and a fresh, tuned transport.  Use this when you need a different
// timeout for a specific subsystem (e.g., a long-running nuclei scan) while
// still benefiting from connection pooling and the optimised dialer settings.
func CreateCustomHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: defaultTransport(),
	}
}
