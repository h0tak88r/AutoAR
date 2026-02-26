package tls

import (
	"context"
	"strings"

	"github.com/projectdiscovery/tlsx/pkg/tlsx"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

// Client is a wrapper around tlsx's service
type Client struct {
	tlsx *tlsx.Service
}

// NewClient creates a new tlsx client
func NewClient(threads int) (*Client, error) {
	options := &clients.Options{
		SAN:         true,
		CN:          true,
		DisplayDns:  true,
		Timeout:     10,
		Concurrency: threads,
	}

	tlsxService, err := tlsx.New(options)
	if err != nil {
		return nil, err
	}

	return &Client{
		tlsx: tlsxService,
	}, nil
}

// Probe probes a domain for TLS certificate info and returns discovered subdomains
func (c *Client) Probe(ctx context.Context, domain string) ([]string, error) {
	resp, err := c.tlsx.Connect(domain, "", "443")
	if err != nil {
		return nil, err
	}

	subdomains := make(map[string]bool)
	
	// Extract from Subject Common Name
	if resp.SubjectCN != "" && strings.HasSuffix(resp.SubjectCN, "."+domain) {
		subdomains[resp.SubjectCN] = true
	}

	// Extract from Subject Alternative Names
	for _, san := range resp.SubjectAN {
		if strings.HasSuffix(san, "."+domain) {
			subdomains[san] = true
		}
	}

	var results []string
	for s := range subdomains {
		results = append(results, s)
	}

	return results, nil
}
