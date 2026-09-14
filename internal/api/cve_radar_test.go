package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCVERadarPasses(t *testing.T) {
	re := cveRadarKeywordRE()
	if re == nil {
		t.Fatal("keyword matcher failed to compile")
	}
	cases := []struct {
		name  string
		desc  string
		score float64
		want  bool
	}{
		{"critical any product", "some obscure library heap overflow", 9.8, true},
		{"at threshold any product", "some obscure library heap overflow", 9.0, true},
		{"high on watched product", "GitLab CE/EE arbitrary file read via workhorse", 7.5, true},
		{"high on unknown product", "some obscure library heap overflow", 7.5, false},
		{"below bar", "some obscure library reflected xss", 6.9, false},
		{"medium on watched product", "wordpress plugin stored xss", 5.5, false},
		{"keyword case-insensitive", "AFFECTED: GitLab.com deployments", 7.0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cveRadarPasses(tc.desc, tc.score, re); got != tc.want {
				t.Fatalf("cveRadarPasses(%q, %.1f) = %v, want %v", tc.desc, tc.score, got, tc.want)
			}
		})
	}
}

func TestCVERadarToggles(t *testing.T) {
	// Defaults: radar on, 15-minute interval with a 5-minute floor.
	t.Setenv("CVE_RADAR", "")
	t.Setenv("CVE_RADAR_INTERVAL_MINUTES", "")
	if !cveRadarEnabled() {
		t.Error("radar should default to enabled")
	}
	if got := cveRadarInterval(); got != 15*time.Minute {
		t.Errorf("default interval = %s, want 15m", got)
	}
	t.Setenv("CVE_RADAR", "off")
	if cveRadarEnabled() {
		t.Error("CVE_RADAR=off should disable the radar")
	}
	t.Setenv("CVE_RADAR", "")
	t.Setenv("CVE_RADAR_INTERVAL_MINUTES", "5")
	if got := cveRadarInterval(); got != 5*time.Minute {
		t.Errorf("floor interval = %s, want 5m", got)
	}
	t.Setenv("CVE_RADAR_INTERVAL_MINUTES", "not-a-number")
	if got := cveRadarInterval(); got != 15*time.Minute {
		t.Errorf("garbage interval = %s, want fallback 15m", got)
	}
}

func TestCVERadarScoreThresholds(t *testing.T) {
	t.Setenv("CVE_RADAR_CRITICAL_MIN", "")
	t.Setenv("CVE_RADAR_HIGH_MIN", "")
	if got := cveRadarCriticalMin(); got != 9.0 {
		t.Errorf("critical min = %.1f, want 9.0", got)
	}
	if got := cveRadarHighMin(); got != 7.0 {
		t.Errorf("high min = %.1f, want 7.0", got)
	}
	t.Setenv("CVE_RADAR_CRITICAL_MIN", "8.5")
	t.Setenv("CVE_RADAR_HIGH_MIN", "6.5")
	if got := cveRadarCriticalMin(); got != 8.5 {
		t.Errorf("critical override = %.1f, want 8.5", got)
	}
	if got := cveRadarHighMin(); got != 6.5 {
		t.Errorf("high override = %.1f, want 6.5", got)
	}
}

func TestCVERadarNVDScoreExtraction(t *testing.T) {
	raw := `{
      "id": "CVE-2026-0001",
      "vulnStatus": "Analyzed",
      "descriptions": [{"lang":"en","value":"GitLab workhorse path traversal"}],
      "metrics": {
        "cvssMetricV31": [{"cvssData":{"baseScore":10.0}}],
        "cvssMetricV2":  [{"cvssData":{"baseScore":7.5}}]
      }
    }`
	var c nvdCVEEntry
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := c.cveRadarScore(); got != 10.0 {
		t.Fatalf("score = %v, want 10.0 (highest across metric versions)", got)
	}
	if got := c.cveRadarDesc(); !strings.Contains(got, "GitLab") {
		t.Fatalf("desc = %q", got)
	}
}
