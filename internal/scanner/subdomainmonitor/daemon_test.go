package subdomainmonitor

import (
	"strings"
	"testing"
)

// TestChangeSection covers the pure alert-list renderer: empty input yields no
// section, and the per-category cap (maxAlertItemsPerCategory) truncates with an
// "…and N more" line rather than dumping an unbounded list into a Discord message.
func TestChangeSection(t *testing.T) {
	if got := changeSection("**%d** changed", nil); got != "" {
		t.Errorf("empty changes should render nothing, got %q", got)
	}

	one := []SubdomainChange{{Subdomain: "a.example.com", Message: "became live"}}
	got := changeSection("**%d** became **live**", one)
	if !strings.Contains(got, "a.example.com") || !strings.Contains(got, "became live") {
		t.Errorf("section missing subdomain/message: %q", got)
	}
	if !strings.Contains(got, "1") {
		t.Errorf("section header should include the count: %q", got)
	}

	// One over the cap: exactly maxAlertItemsPerCategory bullets, then a summary.
	n := maxAlertItemsPerCategory + 5
	many := make([]SubdomainChange, n)
	for i := range many {
		many[i] = SubdomainChange{Subdomain: "h", Message: "m"}
	}
	got = changeSection("**%d** status change(s)", many)
	if bullets := strings.Count(got, "•"); bullets != maxAlertItemsPerCategory {
		t.Errorf("expected %d bullets at cap, got %d", maxAlertItemsPerCategory, bullets)
	}
	if !strings.Contains(got, "…and 5 more") {
		t.Errorf("expected overflow summary '…and 5 more', got %q", got)
	}
}

// TestFormatChangeAlert covers the top-level alert assembler: it names the domain,
// includes only the non-empty categories, and renders new JS endpoints.
func TestFormatChangeAlert(t *testing.T) {
	r := &MonitorResult{
		Domain:        "example.com",
		NewSubdomains: []SubdomainChange{{Subdomain: "new.example.com", Message: "new"}},
		NewEndpoints:  []EndpointChange{{Endpoint: "/api/secret"}},
	}
	got := formatChangeAlert("example.com", r)
	if !strings.Contains(got, "example.com") {
		t.Errorf("alert should name the domain: %q", got)
	}
	if !strings.Contains(got, "new.example.com") {
		t.Errorf("alert should list the new subdomain: %q", got)
	}
	if !strings.Contains(got, "/api/secret") {
		t.Errorf("alert should list the new JS endpoint: %q", got)
	}
	// Categories with no changes must not appear.
	if strings.Contains(got, "became **dead**") {
		t.Errorf("empty category should be omitted: %q", got)
	}
}
