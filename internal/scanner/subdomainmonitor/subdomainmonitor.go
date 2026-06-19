package subdomainmonitor

import (
	"fmt"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"strings"
	"sync"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/scanner/jsendpoints"
	"github.com/h0tak88r/AutoAR/internal/scanner/subdomains"
	"github.com/projectdiscovery/httpx/runner"
)

// ChangeType represents the type of change detected
type ChangeType string

const (
	ChangeTypeNewSubdomain  ChangeType = "new_subdomain"
	ChangeTypeStatusChanged ChangeType = "status_changed"
	ChangeTypeBecameLive    ChangeType = "became_live"
	ChangeTypeBecameDead    ChangeType = "became_dead"
	ChangeTypeNewJSEndpoint ChangeType = "new_js_endpoint"
)

// EndpointChange represents a newly-discovered JS endpoint for a domain.
type EndpointChange struct {
	Endpoint string
	SourceJS string
}

// SubdomainChange represents a detected change in a subdomain
type SubdomainChange struct {
	Subdomain      string
	ChangeType     ChangeType
	OldHTTPStatus  int
	NewHTTPStatus  int
	OldHTTPSStatus int
	NewHTTPSStatus int
	HTTPURL        string
	HTTPSURL       string
	Message        string
}

// MonitorResult contains the results of a monitoring run
type MonitorResult struct {
	Domain        string
	TotalChecked  int
	NewSubdomains []SubdomainChange
	StatusChanges []SubdomainChange
	BecameLive    []SubdomainChange
	BecameDead    []SubdomainChange
	NewEndpoints  []EndpointChange
	Errors        []string
}

// MonitorOptions contains options for monitoring
type MonitorOptions struct {
	Domain      string
	Threads     int
	CheckNew    bool // Check for new subdomains (known host 404 -> 200)
	Reenumerate bool // Re-run passive enumeration to find brand-new hostnames
	MonitorJS   bool // Diff JS endpoints across the domain's live hosts (heavier)
	// SuppressBaseline silences new_subdomain/new_js_endpoint alerts on a target's
	// first run so the initial discovery establishes a baseline instead of spamming.
	SuppressBaseline bool
	Notify           bool // Send webhook notifications on change
}

// MonitorSubdomains monitors subdomains for a domain and detects changes
func MonitorSubdomains(opts MonitorOptions) (*MonitorResult, error) {
	if opts.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	if opts.Threads <= 0 {
		opts.Threads = 100
	}

	// Initialize database
	if err := db.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}
	if err := db.InitSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	// Get existing subdomains with status from database (the baseline for diffing).
	existingSubs, err := db.ListSubdomainsWithStatus(opts.Domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get subdomains from database: %w", err)
	}

	result := &MonitorResult{
		Domain:        opts.Domain,
		TotalChecked:  len(existingSubs),
		NewSubdomains: []SubdomainChange{},
		StatusChanges: []SubdomainChange{},
		BecameLive:    []SubdomainChange{},
		BecameDead:    []SubdomainChange{},
		NewEndpoints:  []EndpointChange{},
		Errors:        []string{},
	}

	knownSet := make(map[string]bool, len(existingSubs))
	for _, s := range existingSubs {
		knownSet[strings.ToLower(s.Subdomain)] = true
	}

	// ── Re-enumeration: discover brand-new hostnames not yet in the DB ──────────────
	// This is what turns the monitor from "liveness of known hosts" into "new asset
	// discovery". New rows are persisted (is_live=false) so the next cycle's liveness
	// pass picks them up; the new_subdomain alert is suppressed on the baseline run.
	if opts.Reenumerate {
		discovered, derr := subdomains.EnumerateFresh(opts.Domain, opts.Threads)
		if derr != nil {
			logger.GetLogger().Infof("[WARN] Monitor re-enumeration failed for %s: %v", opts.Domain, derr)
		} else {
			var newNames []string
			for _, d := range discovered {
				dn := strings.ToLower(strings.TrimSpace(d))
				if dn == "" || knownSet[dn] {
					continue
				}
				knownSet[dn] = true
				newNames = append(newNames, dn)
			}
			if len(newNames) > 0 {
				if ierr := db.BatchInsertSubdomains(opts.Domain, newNames, false); ierr != nil {
					logger.GetLogger().Infof("[WARN] Failed to persist %d newly-enumerated subdomains for %s: %v", len(newNames), opts.Domain, ierr)
				}
				if opts.SuppressBaseline {
					logger.GetLogger().Infof("[INFO] Monitor baseline for %s: recorded %d subdomains (alerts suppressed)", opts.Domain, len(newNames))
				} else {
					for _, n := range newNames {
						result.NewSubdomains = append(result.NewSubdomains, SubdomainChange{
							Subdomain:  n,
							ChangeType: ChangeTypeNewSubdomain,
							Message:    "New subdomain discovered via passive enumeration",
						})
					}
				}
			}
		}
	}

	// ── JS endpoint diff: surface NEW endpoints shipped in the live hosts' bundles ──
	if opts.MonitorJS {
		diffJSEndpoints(opts.Domain, opts.Threads, opts.SuppressBaseline, result)
	}

	if len(existingSubs) == 0 {
		// Nothing known yet to liveness-check (e.g. brand-new domain). Re-enumeration
		// above may still have populated the DB and produced new_subdomain changes.
		return result, nil
	}

	logger.GetLogger().Infof("[INFO] Monitoring %d subdomains for %s", len(existingSubs), opts.Domain)

	// Create a map of existing subdomains for quick lookup
	existingMap := make(map[string]db.SubdomainStatus)
	for _, sub := range existingSubs {
		existingMap[sub.Subdomain] = sub
	}

	// Prepare targets for httpx (check both http and https)
	var targets []string
	for _, sub := range existingSubs {
		targets = append(targets, "http://"+sub.Subdomain)
		targets = append(targets, "https://"+sub.Subdomain)
	}

	// Run httpx to check current status
	currentStatus := make(map[string]SubdomainStatus)
	var mu sync.Mutex
	var errors []string

	httpxOptions := runner.Options{
		InputTargetHost: targets,
		Threads:        opts.Threads,
		Silent:         true,
		NoColor:        true,
		FollowRedirects: true,
		FollowHostRedirects: true,
		HTTPProxy:      "",
		SocksProxy:     "",
		OnResult: func(result runner.Result) {
			mu.Lock()
			defer mu.Unlock()

			// Extract subdomain from URL
			url := result.URL
			if url == "" {
				return
			}

			var subdomain string
			var isHTTPS bool
			if strings.HasPrefix(url, "https://") {
				subdomain = strings.TrimPrefix(url, "https://")
				isHTTPS = true
			} else if strings.HasPrefix(url, "http://") {
				subdomain = strings.TrimPrefix(url, "http://")
				isHTTPS = false
			} else {
				return
			}

			// Remove path
			if idx := strings.Index(subdomain, "/"); idx != -1 {
				subdomain = subdomain[:idx]
			}

			status, exists := currentStatus[subdomain]
			if !exists {
				status = SubdomainStatus{
					Subdomain:   subdomain,
					HTTPURL:     "http://" + subdomain,
					HTTPSURL:    "https://" + subdomain,
					HTTPStatus:  0,
					HTTPSStatus: 0,
				}
			}

			if isHTTPS {
				status.HTTPSStatus = result.StatusCode
				status.HTTPSURL = url
			} else {
				status.HTTPStatus = result.StatusCode
				status.HTTPURL = url
			}

			// Determine if live (either http or https is 200-399)
			status.IsLive = (status.HTTPStatus >= 200 && status.HTTPStatus < 400) ||
				(status.HTTPSStatus >= 200 && status.HTTPSStatus < 400)

			currentStatus[subdomain] = status
		},
	}

	if err := httpxOptions.ValidateOptions(); err != nil {
		return nil, fmt.Errorf("failed to validate httpx options: %w", err)
	}

	httpxRunner, err := runner.New(&httpxOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create httpx runner: %w", err)
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()

	// Compare current status with existing status and detect changes.
	// `result` was already created above (it may already hold new_subdomain /
	// new_js_endpoint changes from re-enumeration and the JS diff) — only merge in
	// any httpx errors here, do not overwrite the accumulated changes.
	result.TotalChecked = len(existingSubs)
	result.Errors = append(result.Errors, errors...)

	// Check each existing subdomain for changes
	for _, existing := range existingSubs {
		current, exists := currentStatus[existing.Subdomain]
		if !exists {
			// Subdomain not found in current check (might be dead now)
			// Check if it was previously live
			if existing.IsLive {
				change := SubdomainChange{
					Subdomain:      existing.Subdomain,
					ChangeType:      ChangeTypeBecameDead,
					OldHTTPStatus:   existing.HTTPStatus,
					NewHTTPStatus:   0,
					OldHTTPSStatus:  existing.HTTPSStatus,
					NewHTTPSStatus:  0,
					HTTPURL:         existing.HTTPURL,
					HTTPSURL:        existing.HTTPSURL,
					Message:         fmt.Sprintf("Subdomain became unreachable (was %d/%d)", existing.HTTPStatus, existing.HTTPSStatus),
				}
				result.BecameDead = append(result.BecameDead, change)
			}
			continue
		}

		// Check for status changes
		httpChanged := current.HTTPStatus != existing.HTTPStatus
		httpsChanged := current.HTTPSStatus != existing.HTTPSStatus
		becameLive := !existing.IsLive && current.IsLive
		becameDead := existing.IsLive && !current.IsLive

		// Legacy "new subdomain" heuristic: a known host that was 404/0 now serves 200.
		// Skipped when Reenumerate is on — there, brand-new hosts are reported once at
		// discovery (above), and a 0→200 transition is just the host coming online
		// (became_live), so running this heuristic too would double-report the event.
		reportedNew := false
		if opts.CheckNew && !opts.Reenumerate {
			wasDead := (existing.HTTPStatus == 0 || existing.HTTPStatus == 404) &&
				(existing.HTTPSStatus == 0 || existing.HTTPSStatus == 404)
			isNowLive := current.HTTPStatus == 200 || current.HTTPSStatus == 200

			if wasDead && isNowLive {
				change := SubdomainChange{
					Subdomain:      current.Subdomain,
					ChangeType:     ChangeTypeNewSubdomain,
					OldHTTPStatus:  existing.HTTPStatus,
					NewHTTPStatus:  current.HTTPStatus,
					OldHTTPSStatus: existing.HTTPSStatus,
					NewHTTPSStatus: current.HTTPSStatus,
					HTTPURL:        current.HTTPURL,
					HTTPSURL:       current.HTTPSURL,
					Message:        fmt.Sprintf("New subdomain appeared! Status: %d/%d", current.HTTPStatus, current.HTTPSStatus),
				}
				result.NewSubdomains = append(result.NewSubdomains, change)
				reportedNew = true
			}
		}

		// Check if became live (suppressed if already reported as new this cycle, so a
		// single dead→live transition never emits both new_subdomain and became_live).
		if becameLive && !reportedNew {
			change := SubdomainChange{
				Subdomain:      current.Subdomain,
				ChangeType:      ChangeTypeBecameLive,
				OldHTTPStatus:   existing.HTTPStatus,
				NewHTTPStatus:   current.HTTPStatus,
				OldHTTPSStatus:  existing.HTTPSStatus,
				NewHTTPSStatus:  current.HTTPSStatus,
				HTTPURL:         current.HTTPURL,
				HTTPSURL:        current.HTTPSURL,
				Message:         fmt.Sprintf("Subdomain became live! Status: %d/%d (was %d/%d)", current.HTTPStatus, current.HTTPSStatus, existing.HTTPStatus, existing.HTTPSStatus),
			}
			result.BecameLive = append(result.BecameLive, change)
		}

		// Check if became dead
		if becameDead {
			change := SubdomainChange{
				Subdomain:      current.Subdomain,
				ChangeType:      ChangeTypeBecameDead,
				OldHTTPStatus:   existing.HTTPStatus,
				NewHTTPStatus:   current.HTTPStatus,
				OldHTTPSStatus:  existing.HTTPSStatus,
				NewHTTPSStatus:  current.HTTPSStatus,
				HTTPURL:         current.HTTPURL,
				HTTPSURL:        current.HTTPSURL,
				Message:         fmt.Sprintf("Subdomain became dead! Status: %d/%d (was %d/%d)", current.HTTPStatus, current.HTTPSStatus, existing.HTTPStatus, existing.HTTPSStatus),
			}
			result.BecameDead = append(result.BecameDead, change)
		}

		// Check for status code changes (but not new subdomain or live/dead changes)
		if (httpChanged || httpsChanged) && !becameLive && !becameDead {
			change := SubdomainChange{
				Subdomain:      current.Subdomain,
				ChangeType:      ChangeTypeStatusChanged,
				OldHTTPStatus:   existing.HTTPStatus,
				NewHTTPStatus:   current.HTTPStatus,
				OldHTTPSStatus:  existing.HTTPSStatus,
				NewHTTPSStatus:  current.HTTPSStatus,
				HTTPURL:         current.HTTPURL,
				HTTPSURL:        current.HTTPSURL,
				Message:         fmt.Sprintf("Status changed: %d/%d -> %d/%d", existing.HTTPStatus, existing.HTTPSStatus, current.HTTPStatus, current.HTTPSStatus),
			}
			result.StatusChanges = append(result.StatusChanges, change)
		}

		// Update database with current status
		isLive := current.HTTPStatus >= 200 && current.HTTPStatus < 400 ||
			current.HTTPSStatus >= 200 && current.HTTPSStatus < 400

		httpURL := current.HTTPURL
		if httpURL == "" {
			httpURL = "http://" + current.Subdomain
		}
		httpsURL := current.HTTPSURL
		if httpsURL == "" {
			httpsURL = "https://" + current.Subdomain
		}

		if err := db.InsertSubdomain(opts.Domain, current.Subdomain, isLive, httpURL, httpsURL, current.HTTPStatus, current.HTTPSStatus); err != nil {
			logger.GetLogger().Infof("[WARN] Failed to update subdomain %s in database: %v", current.Subdomain, err)
		}
	}

	// Check for completely new subdomains (not in database at all)
	// This would require re-enumeration, which we'll skip for now to keep it focused on status monitoring

	logger.GetLogger().Infof("[OK] Monitoring complete: %d checked, %d new, %d status changes, %d became live, %d became dead",
		result.TotalChecked, len(result.NewSubdomains), len(result.StatusChanges), len(result.BecameLive), len(result.BecameDead))

	return result, nil
}

// diffJSEndpoints crawls the domain's live hosts' current JS bundles, extracts API
// endpoints, and diffs them against the js_endpoints table. Newly-appearing endpoints
// (e.g. shipped in a fresh deploy) are persisted and appended to result.NewEndpoints —
// unless this is the target's baseline run, where they are only recorded silently.
func diffJSEndpoints(domain string, threads int, suppressBaseline bool, result *MonitorResult) {
	liveSubs, err := db.ListLiveSubdomains(domain)
	if err != nil {
		logger.GetLogger().Infof("[WARN] JS diff: failed to list live subdomains for %s: %v", domain, err)
		return
	}
	if len(liveSubs) == 0 {
		return
	}

	hosts := make([]string, 0, len(liveSubs))
	for _, s := range liveSubs {
		switch {
		case s.HTTPSURL != "":
			hosts = append(hosts, s.HTTPSURL)
		case s.HTTPURL != "":
			hosts = append(hosts, s.HTTPURL)
		default:
			hosts = append(hosts, s.Subdomain)
		}
	}

	eps, err := jsendpoints.CollectEndpointsForHosts(hosts, threads)
	if err != nil {
		logger.GetLogger().Infof("[WARN] JS diff: endpoint extraction failed for %s: %v", domain, err)
		return
	}
	if len(eps) == 0 {
		return
	}

	existing, err := db.ListJSEndpoints(domain)
	if err != nil {
		logger.GetLogger().Infof("[WARN] JS diff: failed to list stored endpoints for %s: %v", domain, err)
		return
	}
	seen := make(map[string]bool, len(existing))
	for _, e := range existing {
		seen[e] = true
	}

	toStore := make([]db.JSEndpoint, 0, len(eps))
	var fresh []EndpointChange
	for _, ep := range eps {
		toStore = append(toStore, db.JSEndpoint{Endpoint: ep.Path, SourceJS: ep.Source})
		if !seen[ep.Path] {
			seen[ep.Path] = true // de-dupe within this batch too
			fresh = append(fresh, EndpointChange{Endpoint: ep.Path, SourceJS: ep.Source})
		}
	}

	if err := db.InsertJSEndpoints(domain, toStore); err != nil {
		logger.GetLogger().Infof("[WARN] JS diff: failed to persist endpoints for %s: %v", domain, err)
	}

	if suppressBaseline {
		logger.GetLogger().Infof("[INFO] Monitor baseline for %s: recorded %d JS endpoints (alerts suppressed)", domain, len(toStore))
		return
	}
	result.NewEndpoints = append(result.NewEndpoints, fresh...)
}

// SubdomainStatus is a helper struct for tracking current status during monitoring
type SubdomainStatus struct {
	Subdomain   string
	HTTPURL     string
	HTTPSURL    string
	HTTPStatus  int
	HTTPSStatus int
	IsLive      bool
}

// PrintResults prints monitoring results to stdout
func PrintResults(result *MonitorResult) {
	fmt.Printf("\n=== Subdomain Monitoring Results for %s ===\n", result.Domain)
	fmt.Printf("Total Checked: %d\n", result.TotalChecked)

	if len(result.NewSubdomains) > 0 {
		fmt.Printf("\n New Subdomains (%d):\n", len(result.NewSubdomains))
		for _, change := range result.NewSubdomains {
			fmt.Printf("  - %s: %s\n", change.Subdomain, change.Message)
		}
	}

	if len(result.BecameLive) > 0 {
		fmt.Printf("\n[ + ]Became Live (%d):\n", len(result.BecameLive))
		for _, change := range result.BecameLive {
			fmt.Printf("  - %s: %s\n", change.Subdomain, change.Message)
		}
	}

	if len(result.StatusChanges) > 0 {
		fmt.Printf("\n Status Changes (%d):\n", len(result.StatusChanges))
		for _, change := range result.StatusChanges {
			fmt.Printf("  - %s: %s\n", change.Subdomain, change.Message)
		}
	}

	if len(result.BecameDead) > 0 {
		fmt.Printf("\n Became Dead (%d):\n", len(result.BecameDead))
		for _, change := range result.BecameDead {
			fmt.Printf("  - %s: %s\n", change.Subdomain, change.Message)
		}
	}

	if len(result.NewSubdomains) == 0 && len(result.StatusChanges) == 0 && len(result.BecameLive) == 0 && len(result.BecameDead) == 0 {
		fmt.Printf("\n[ + ]No changes detected\n")
	}
}

