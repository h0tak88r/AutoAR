package http_asr

import (
	"context"
	"sync"

	"github.com/projectdiscovery/httpx/common/httpx"
)

// Client is a wrapper around httpx's client
type Client struct {
	httpx *httpx.HTTPX
}

// NewClient creates a new httpx client
func NewClient(threads int) (*Client, error) {
	options := httpx.DefaultOptions
	options.Threads = threads
	options.Timeout = 10

	httpxClient, err := httpx.New(&options)
	if err != nil {
		return nil, err
	}

	return &Client{
		httpx: httpxClient,
	}, nil
}

// CheckLive checks which of the provided domains are live web hosts in parallel
func (c *Client) CheckLive(ctx context.Context, domains []string, threads int) ([]string, error) {
	if threads <= 0 {
		threads = 20
	}

	results := make(chan string)
	jobs := make(chan string, len(domains))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					// Try both http and https
					for _, protocol := range []string{"https", "http"} { // Try https first
						url := protocol + "://" + domain
						req, err := c.httpx.NewRequest("GET", url)
						if err != nil {
							continue
						}
						result, err := c.httpx.Do(req, httpx.UnsafeOptions{})
						if err == nil && result != nil {
							results <- url
							break
						}
					}
				}
			}
		}()
	}

	// Send jobs
	go func() {
		for _, domain := range domains {
			jobs <- domain
		}
		close(jobs)
	}()

	// Wait and close results
	go func() {
		wg.Wait()
		close(results)
	}()

	var live []string
	for url := range results {
		live = append(live, url)
	}

	return live, nil
}

