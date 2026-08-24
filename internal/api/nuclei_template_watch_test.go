package api

import (
	"testing"
	"time"
)

func TestNucleiTemplateWatchToggles(t *testing.T) {
	// Defaults: watcher on (when a key exists), autorun on, 30-minute interval.
	t.Setenv("PDCP_API_KEY", "test-key")
	t.Setenv("CHAOS_API_KEY", "")
	t.Setenv("NUCLEI_TEMPLATE_WATCH", "")
	t.Setenv("NUCLEI_TEMPLATE_AUTORUN", "")
	t.Setenv("NUCLEI_TEMPLATE_WATCH_INTERVAL_MINUTES", "")
	if !nucleiTemplateWatchEnabled() {
		t.Error("watch should default to enabled when a PDCP key is set")
	}
	if !nucleiTemplateAutoRunEnabled() {
		t.Error("autorun should default to enabled")
	}
	if got := nucleiTemplateWatchInterval(); got != 30*time.Minute {
		t.Errorf("default interval = %s, want 30m", got)
	}

	t.Setenv("NUCLEI_TEMPLATE_WATCH", "off")
	if nucleiTemplateWatchEnabled() {
		t.Error("NUCLEI_TEMPLATE_WATCH=off should disable the watch")
	}
	t.Setenv("NUCLEI_TEMPLATE_WATCH", "")
	t.Setenv("NUCLEI_TEMPLATE_AUTORUN", "off")
	if nucleiTemplateAutoRunEnabled() {
		t.Error("NUCLEI_TEMPLATE_AUTORUN=off should disable autorun")
	}

	// Interval: valid override, plus the floor at 5 minutes.
	t.Setenv("NUCLEI_TEMPLATE_WATCH_INTERVAL_MINUTES", "60")
	if got := nucleiTemplateWatchInterval(); got != time.Hour {
		t.Errorf("interval override = %s, want 1h", got)
	}
	t.Setenv("NUCLEI_TEMPLATE_WATCH_INTERVAL_MINUTES", "1")
	if got := nucleiTemplateWatchInterval(); got != 30*time.Minute {
		t.Errorf("below-floor interval = %s, want fallback 30m", got)
	}
	t.Setenv("NUCLEI_TEMPLATE_WATCH_INTERVAL_MINUTES", "not-a-number")
	if got := nucleiTemplateWatchInterval(); got != 30*time.Minute {
		t.Errorf("garbage interval = %s, want fallback 30m", got)
	}
}

func TestNucleiTemplateAPIKeyFallback(t *testing.T) {
	// PDCP_API_KEY wins; CHAOS_API_KEY (the same PDCP key) is the fallback.
	t.Setenv("PDCP_API_KEY", "pdcp-key")
	t.Setenv("CHAOS_API_KEY", "chaos-key")
	if got := nucleiTemplateAPIKey(); got != "pdcp-key" {
		t.Errorf("nucleiTemplateAPIKey() = %q, want PDCP_API_KEY", got)
	}

	t.Setenv("PDCP_API_KEY", "")
	if got := nucleiTemplateAPIKey(); got != "chaos-key" {
		t.Errorf("nucleiTemplateAPIKey() = %q, want CHAOS_API_KEY fallback", got)
	}

	// No key at all: watch stays off even without an explicit =off.
	t.Setenv("CHAOS_API_KEY", "")
	t.Setenv("NUCLEI_TEMPLATE_WATCH", "")
	if nucleiTemplateWatchEnabled() {
		t.Error("watch should be disabled when no PDCP/CHAOS key is set")
	}
}
