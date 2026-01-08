package subdomainmonitor

import (
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/h0tak88r/AutoAR/v3/internal/modules/db"
	"github.com/projectdiscovery/httpx/runner"
)

// ChangeType represents the type of change detected
type ChangeType string

const (
	ChangeTypeNewSubdomain    ChangeType = "new_subdomain"
	ChangeTypeStatusChanged   ChangeType = "status_changed"
	ChangeTypeBecameLive      ChangeType = "became_live"
	ChangeTypeBecameDead      ChangeType = "became_dead"
)

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
	Domain          string
	TotalChecked    int
	NewSubdomains   []SubdomainChange
	StatusChanges   []SubdomainChange
	BecameLive      []SubdomainChange
	BecameDead      []SubdomainChange
	Errors          []string
}

// MonitorOptions contains options for monitoring
type MonitorOptions struct {
	Domain      string
	Threads     int
	CheckNew    bool // Check for new subdomains (404 -> 200)
	Notify      bool // Send notifications (for future webhook/Discord integration)
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

	// Get existing subdomains with status from database
	existingSubs, err := db.ListSubdomainsWithStatus(opts.Domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get subdomains from database: %w", err)
	}

	if len(existingSubs) == 0 {
		return &MonitorResult{
			Domain:        opts.Domain,
			TotalChecked:  0,
			NewSubdomains: []SubdomainChange{},
			StatusChanges: []SubdomainChange{},
			BecameLive:    []SubdomainChange{},
			BecameDead:    []SubdomainChange{},
			Errors:        []string{"No subdomains found in database for this domain"},
		}, nil
	}

	log.Printf("[INFO] Monitoring %d subdomains for %s", len(existingSubs), opts.Domain)

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

	// Compare current status with existing status and detect changes
	result := &MonitorResult{
		Domain:        opts.Domain,
		TotalChecked:   len(existingSubs),
		NewSubdomains: []SubdomainChange{},
		StatusChanges: []SubdomainChange{},
		BecameLive:    []SubdomainChange{},
		BecameDead:    []SubdomainChange{},
		Errors:        errors,
	}

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

		// Check for new subdomain (was 404/0, now 200)
		if opts.CheckNew {
			wasDead := (existing.HTTPStatus == 0 || existing.HTTPStatus == 404) &&
				(existing.HTTPSStatus == 0 || existing.HTTPSStatus == 404)
			isNowLive := current.HTTPStatus == 200 || current.HTTPSStatus == 200

			if wasDead && isNowLive {
				change := SubdomainChange{
					Subdomain:      current.Subdomain,
					ChangeType:      ChangeTypeNewSubdomain,
					OldHTTPStatus:   existing.HTTPStatus,
					NewHTTPStatus:   current.HTTPStatus,
					OldHTTPSStatus:  existing.HTTPSStatus,
					NewHTTPSStatus:  current.HTTPSStatus,
					HTTPURL:         current.HTTPURL,
					HTTPSURL:        current.HTTPSURL,
					Message:         fmt.Sprintf("New subdomain appeared! Status: %d/%d", current.HTTPStatus, current.HTTPSStatus),
				}
				result.NewSubdomains = append(result.NewSubdomains, change)
			}
		}

		// Check if became live
		if becameLive {
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
			log.Printf("[WARN] Failed to update subdomain %s in database: %v", current.Subdomain, err)
		}
	}

	// Check for completely new subdomains (not in database at all)
	// This would require re-enumeration, which we'll skip for now to keep it focused on status monitoring

	log.Printf("[OK] Monitoring complete: %d checked, %d new, %d status changes, %d became live, %d became dead",
		result.TotalChecked, len(result.NewSubdomains), len(result.StatusChanges), len(result.BecameLive), len(result.BecameDead))

	return result, nil
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
		fmt.Printf("\n🆕 New Subdomains (%d):\n", len(result.NewSubdomains))
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
		fmt.Printf("\n🔄 Status Changes (%d):\n", len(result.StatusChanges))
		for _, change := range result.StatusChanges {
			fmt.Printf("  - %s: %s\n", change.Subdomain, change.Message)
		}
	}

	if len(result.BecameDead) > 0 {
		fmt.Printf("\n❌ Became Dead (%d):\n", len(result.BecameDead))
		for _, change := range result.BecameDead {
			fmt.Printf("  - %s: %s\n", change.Subdomain, change.Message)
		}
	}

	if len(result.NewSubdomains) == 0 && len(result.StatusChanges) == 0 && len(result.BecameLive) == 0 && len(result.BecameDead) == 0 {
		fmt.Printf("\n[ + ]No changes detected\n")
	}
}

