package dns_asr

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// Client is a wrapper around dnsx's client
type Client struct {
	dnsx      *dnsx.DNSX
	resolvers string // path to resolvers file
}

// NewClient creates a new dnsx client
func NewClient(resolvers []string, threads int) (*Client, error) {
	options := dnsx.DefaultOptions
	if len(resolvers) > 0 {
		options.BaseResolvers = resolvers
	}

	dnsxClient, err := dnsx.New(options)
	if err != nil {
		return nil, err
	}

	return &Client{
		dnsx: dnsxClient,
	}, nil
}

// NewClientWithResolverFile creates a new client with a resolvers file path for puredns
func NewClientWithResolverFile(resolverFile string, threads int) (*Client, error) {
	client, err := NewClient(nil, threads)
	if err != nil {
		return nil, err
	}
	client.resolvers = resolverFile
	return client, nil
}

// Resolve resolves a list of domains using puredns (fast) or dnsx (fallback)
func (c *Client) Resolve(ctx context.Context, domains []string, threads int) ([]string, error) {
	if len(domains) == 0 {
		return nil, nil
	}

	// Try puredns first (much faster for large lists)
	if _, err := exec.LookPath("puredns"); err == nil {
		return c.resolveWithPuredns(ctx, domains, threads)
	}

	// Fallback to concurrent dnsx
	return c.resolveWithDnsx(ctx, domains, threads)
}

// Bruteforce performs DNS bruteforcing using puredns (fast) or dnsx (fallback)
func (c *Client) Bruteforce(ctx context.Context, domain string, wordlist []string, threads int) ([]string, error) {
	if len(wordlist) == 0 {
		return nil, nil
	}

	// Try puredns first (much faster for large wordlists)
	if _, err := exec.LookPath("puredns"); err == nil {
		return c.bruteforceWithPuredns(ctx, domain, wordlist, threads)
	}

	// Fallback to concurrent dnsx
	return c.bruteforceWithDnsx(ctx, domain, wordlist, threads)
}

// BruteforceWithWordlistFile performs DNS bruteforcing using a wordlist file path directly
// This avoids loading the entire wordlist into memory
func (c *Client) BruteforceWithWordlistFile(ctx context.Context, domain, wordlistPath string, threads int) ([]string, error) {
	if _, err := exec.LookPath("puredns"); err == nil {
		return c.bruteforceFileWithPuredns(ctx, domain, wordlistPath, threads)
	}

	// Fallback: load file and use dnsx
	data, err := os.ReadFile(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read wordlist: %w", err)
	}
	words := strings.Split(string(data), "\n")
	return c.bruteforceWithDnsx(ctx, domain, words, threads)
}

// ---- puredns implementations (fast, for large lists) ----

func (c *Client) resolveWithPuredns(ctx context.Context, domains []string, threads int) ([]string, error) {
	tmpDir := os.TempDir()
	inputFile := filepath.Join(tmpDir, "asr_resolve_input.txt")
	outputFile := filepath.Join(tmpDir, "asr_resolve_output.txt")
	defer os.Remove(inputFile)
	defer os.Remove(outputFile)

	// Write domains to temp file
	if err := writeLines(inputFile, domains); err != nil {
		return nil, fmt.Errorf("failed to write input file: %w", err)
	}

	args := []string{"resolve", inputFile, "-w", outputFile}
	if c.resolvers != "" {
		args = append(args, "-r", c.resolvers)
	}

	log.Printf("[ASR] Running puredns resolve on %d domains", len(domains))
	cmd := exec.CommandContext(ctx, "puredns", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("[WARN] puredns resolve failed: %v, falling back to dnsx", err)
		return c.resolveWithDnsx(ctx, domains, threads)
	}

	return readLines(outputFile)
}

func (c *Client) bruteforceWithPuredns(ctx context.Context, domain string, wordlist []string, threads int) ([]string, error) {
	tmpDir := os.TempDir()
	wordlistFile := filepath.Join(tmpDir, "asr_bruteforce_wordlist.txt")
	defer os.Remove(wordlistFile)

	if err := writeLines(wordlistFile, wordlist); err != nil {
		return nil, fmt.Errorf("failed to write wordlist file: %w", err)
	}

	return c.bruteforceFileWithPuredns(ctx, domain, wordlistFile, threads)
}

func (c *Client) bruteforceFileWithPuredns(ctx context.Context, domain, wordlistPath string, threads int) ([]string, error) {
	tmpDir := os.TempDir()
	outputFile := filepath.Join(tmpDir, "asr_bruteforce_output.txt")
	defer os.Remove(outputFile)

	args := []string{"bruteforce", wordlistPath, domain, "-w", outputFile}
	if c.resolvers != "" {
		args = append(args, "-r", c.resolvers)
	}

	log.Printf("[ASR] Running puredns bruteforce for %s", domain)
	cmd := exec.CommandContext(ctx, "puredns", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("[WARN] puredns bruteforce failed: %v", err)
		return nil, err
	}

	return readLines(outputFile)
}

// ---- dnsx fallback implementations (slower, but no external dependency) ----

func (c *Client) resolveWithDnsx(ctx context.Context, domains []string, threads int) ([]string, error) {
	if threads <= 0 {
		threads = 50
	}

	results := make(chan string, len(domains))
	jobs := make(chan string, threads*2)
	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					result, err := c.dnsx.QueryOne(domain)
					if err == nil && result != nil && (len(result.A) > 0 || len(result.AAAA) > 0 || len(result.CNAME) > 0) {
						results <- domain
					}
				}
			}
		}()
	}

	go func() {
		for _, domain := range domains {
			jobs <- domain
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var resolved []string
	for domain := range results {
		resolved = append(resolved, domain)
	}

	return resolved, nil
}

func (c *Client) bruteforceWithDnsx(ctx context.Context, domain string, wordlist []string, threads int) ([]string, error) {
	if threads <= 0 {
		threads = 50
	}

	results := make(chan string, threads*2)
	jobs := make(chan string, threads*2) // Small buffer to avoid huge memory allocation
	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					subdomain := fmt.Sprintf("%s.%s", strings.TrimSpace(word), domain)
					result, err := c.dnsx.QueryOne(subdomain)
					if err == nil && result != nil && (len(result.A) > 0 || len(result.AAAA) > 0 || len(result.CNAME) > 0) {
						results <- subdomain
					}
				}
			}
		}()
	}

	go func() {
		for _, word := range wordlist {
			jobs <- word
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var discovered []string
	for sub := range results {
		discovered = append(discovered, sub)
	}

	return discovered, nil
}

// ---- File helpers ----

func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			fmt.Fprintln(w, line)
		}
	}
	return w.Flush()
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}
