package seclab

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDatasetsLoadAndParse(t *testing.T) {
	for _, name := range Names() {
		raw, err := Raw(name)
		if err != nil {
			t.Fatalf("Raw(%q): %v", name, err)
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("dataset %q is not valid JSON: %v", name, err)
		}
	}
	if _, err := Raw("nope"); err == nil {
		t.Fatal("expected error for unknown dataset")
	}
}

func TestSSRFAndXSS(t *testing.T) {
	ssrf, err := SSRF()
	if err != nil || len(ssrf) == 0 {
		t.Fatalf("SSRF: %v (%d)", err, len(ssrf))
	}
	// Every flattened payload carries its group.
	for _, p := range ssrf {
		if p.Group == "" {
			t.Fatalf("SSRF payload missing group: %+v", p)
		}
	}
	xss, err := XSS()
	if err != nil || len(xss) == 0 {
		t.Fatalf("XSS: %v (%d)", err, len(xss))
	}
}

func TestFilters(t *testing.T) {
	// SSRF text + tag filter.
	meta, _ := FilterSSRF("metadata", "", 0)
	if len(meta) == 0 {
		t.Fatal("expected cloud-metadata SSRF payloads")
	}
	cors, _ := FilterSSRF("", "CORS", 0)
	if len(cors) == 0 {
		t.Fatal("expected CORS-tagged SSRF payloads")
	}
	for _, p := range cors {
		if !hasTag(p.Tags, "CORS") {
			t.Fatalf("tag filter leaked: %v", p.Tags)
		}
	}
	// XSS tag + event filter.
	svg, _ := FilterXSS("", "svg", "onload", 3)
	if len(svg) == 0 || len(svg) > 3 {
		t.Fatalf("xss svg/onload filter: %d", len(svg))
	}
	for _, p := range svg {
		if !strings.EqualFold(p.Tag, "svg") || !strings.Contains(strings.ToLower(p.Event), "onload") {
			t.Fatalf("xss filter leaked: tag=%q event=%q", p.Tag, p.Event)
		}
	}
	// Takeover: type split + limit + kind tagging.
	dns, _ := FilterTakeover("dns", "", 5)
	if len(dns) == 0 || len(dns) > 5 {
		t.Fatalf("takeover dns filter: %d", len(dns))
	}
	for _, r := range dns {
		if r["kind"] != "dns" {
			t.Fatalf("takeover kind not tagged: %v", r["kind"])
		}
	}
	all, _ := FilterTakeover("all", "", 0)
	sub, _ := Takeover("subdomain")
	dnsAll, _ := Takeover("dns")
	if len(all) != len(sub)+len(dnsAll) {
		t.Fatalf("all=%d want %d", len(all), len(sub)+len(dnsAll))
	}
}
