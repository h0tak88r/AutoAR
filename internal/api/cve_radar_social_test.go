package api

import (
	"testing"
	"time"
)

func TestParseRSSTime(t *testing.T) {
	cases := map[string]bool{
		"Tue, 06 Oct 2026 10:40:59 +0000": true,
		"Tue, 6 Oct 2026 10:40:59 +0000":  true,
		"2026-10-06T10:40:59Z":            true,
		"not a date":                      false,
	}
	for in, wantOK := range cases {
		ts, err := parseRSSTime(in)
		if wantOK && err != nil {
			t.Errorf("parseRSSTime(%q) failed: %v", in, err)
		}
		if !wantOK && err == nil {
			t.Errorf("parseRSSTime(%q) = %v, want error", in, ts)
		}
	}
}

func TestSocialPoCGate(t *testing.T) {
	yes := []string{
		"PoC released for CVE-2026-21589",
		"New exploit for Atlassian bugs",
		"watchTowr: you won't hear about these",
		"actively exploited in the wild",
		"Pre-auth RCE chain",
	}
	no := []string{
		"October Patch Tuesday CVE roundup",
		"Atlassian ships security updates",
		"how to harden your Jira",
	}
	for _, s := range yes {
		if !socialPoCGate(s) {
			t.Errorf("socialPoCGate(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if socialPoCGate(s) {
			t.Errorf("socialPoCGate(%q) = true, want false", s)
		}
	}
}

const wtRSSFixture = `<?xml version="1.0"?>
<rss version="2.0"><channel>
<item>
  <title>You Wont Hear About These, Even In Myths (CVE-2026-21589)</title>
  <link>https://labs.watchtowr.com/you-wont-hear-cve-2026-21589/</link>
  <pubDate>Tue, 06 Oct 2026 10:40:59 +0000</pubDate>
  <description>&lt;p&gt;full PoCs for &lt;b&gt;CVE-2026-21589&lt;/b&gt; below&lt;/p&gt;</description>
</item>
<item>
  <title>Old post (CVE-2026-99999)</title>
  <link>https://labs.watchtowr.com/old/</link>
  <pubDate>Mon, 05 Oct 2026 08:00:00 +0000</pubDate>
  <description>stale</description>
</item>
</channel></rss>`

func TestParseWatchTowrRSS(t *testing.T) {
	wm := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	out, maxTs := parseWatchTowrRSS([]byte(wtRSSFixture), wm)
	if len(out) != 1 {
		t.Fatalf("got %d CVEs, want 1 (only the item after watermark): %v", len(out), out)
	}
	link, ok := out["CVE-2026-21589"]
	if !ok || link != "https://labs.watchtowr.com/you-wont-hear-cve-2026-21589/" {
		t.Fatalf("CVE-2026-21589 -> %q, %v", link, ok)
	}
	if want := "06 Oct 2026 10:40:59 +0000"; maxTs.Format("02 Jan 2006 15:04:05 -0700") != want {
		t.Errorf("maxTs = %s, want %s", maxTs.Format("02 Jan 2006 15:04:05 -0700"), want)
	}
}

const hnFixture = `{"hits":[
  {"objectID":"41000001","title":"CVE-2026-21589 exploit released for Atlassian","url":"https://github.com/x/y","created_at_i":1791288000},
  {"objectID":"41000002","title":"October Patch Tuesday roundup","url":"https://msrc.example","created_at_i":1791288100}
]}`

func TestParseHNHits(t *testing.T) {
	wm := time.Unix(1791280000, 0).UTC()
	out, maxTs := parseHNHits([]byte(hnFixture), wm)
	if len(out) != 1 {
		t.Fatalf("got %d CVEs, want 1 (patch-tuesday hit must be gated out): %v", len(out), out)
	}
	if out["CVE-2026-21589"] != "https://news.ycombinator.com/item?id=41000001" {
		t.Fatalf("CVE-2026-21589 -> %q", out["CVE-2026-21589"])
	}
	// Watermark must advance past BOTH hits (both were processed/decided).
	if maxTs.Unix() != 1791288100 {
		t.Errorf("maxTs = %d, want 1791288100", maxTs.Unix())
	}
}

func TestMergeFeedHitsPersists(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	stored := map[string]cveRadarFeedHit{}
	merged, changed := mergeFeedHits(stored, map[string]string{"CVE-2026-1": "watchTowr blog: <https://a>"}, now)
	if !changed || merged["CVE-2026-1"] == "" {
		t.Fatalf("first hit not stored: %v", merged)
	}
	// Later cycle: the feed watermark moved on, nothing new — the hit is still there.
	merged, changed = mergeFeedHits(stored, map[string]string{"CVE-2026-1": "other: <https://b>"}, now.Add(24*time.Hour))
	if changed || merged["CVE-2026-1"] != "watchTowr blog: <https://a>" {
		t.Fatalf("persisted hit lost or overwritten: %v (changed=%v)", merged, changed)
	}
	merged, changed = mergeFeedHits(stored, nil, now.Add(cveRadarFeedHitsTTL+time.Hour))
	if !changed || len(merged) != 0 || len(stored) != 0 {
		t.Fatalf("expired hit not pruned: %v", merged)
	}
}

const sploitusFixture = `{"exploits":[
  {"title":"Exploit for CVE-2026-98260","score":7.8,"href":"https://github.com/tiamo1990/shancha-kernel-workshop","type":"github","published":"2026-11-21","id":"513BE762-64F6-5725-BF43-F0993FA46941","source":"root exploit for CVE-2026-98260 on Meta Quest 3"},
  {"title":"Vulners Software Audit","score":0,"href":"https://vulners.com","type":"unknown","published":"2026-11-24","id":"KS:SCANNER","source":"no cve here"},
  {"title":"Old exploit for CVE-2020-0001","score":9.8,"href":"https://exploit-db.com/x","type":"exploitdb","published":"2020-01-01","id":"OLD-123","source":"CVE-2020-0001 stale"}
]}`

func TestParseSploitusHits(t *testing.T) {
	wm := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	out, maxTs := parseSploitusHits([]byte(sploitusFixture), wm)
	// Only the fresh exploit maps: the audit row has no CVE, the 2020 item is
	// older than the watermark.
	if len(out) != 1 {
		t.Fatalf("got %d CVEs, want 1: %v", len(out), out)
	}
	if got := out["CVE-2026-98260"]; got != "https://sploitus.com/exploit?id=513BE762-64F6-5725-BF43-F0993FA46941" {
		t.Fatalf("CVE-2026-98260 -> %q", got)
	}
	// Watermark advances to the newest published date seen (the audit row's).
	if want := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC); !maxTs.Equal(want) {
		t.Errorf("maxTs = %s, want %s", maxTs, want)
	}
}

const fdRSSFixture = `<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0"><channel>
<item>
  <title>SAPBleed: Pre-Auth Memory Disclosure and RCE (CVE-2026-76964, CVE-2026-89126)</title>
  <link>https://seclists.org/fulldisclosure/2026/Nov/36</link>
  <pubDate>Mon, 17 Nov 2026 19:15:53 GMT</pubDate>
  <description>&lt;p&gt;Heap overflow, pre-auth RCE in SAP ICM&lt;/p&gt;</description>
</item>
<item>
  <title>APPLE-SA-11-13-2026-1 tvOS 27.2.1</title>
  <link>https://seclists.org/fulldisclosure/2026/Nov/35</link>
  <pubDate>Mon, 17 Nov 2026 19:15:40 GMT</pubDate>
  <description>&lt;p&gt;tvOS fixes CVE-2026-99999&lt;/p&gt;</description>
</item>
<item>
  <title>Old advisory (CVE-2020-0001)</title>
  <link>https://seclists.org/fulldisclosure/2020/Jan/1</link>
  <pubDate>Wed, 01 Jan 2020 00:00:00 GMT</pubDate>
  <description>stale</description>
</item>
</channel></rss>`

func TestParseFullDisclosureRSS(t *testing.T) {
	wm := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	out, maxTs := parseFullDisclosureRSS([]byte(fdRSSFixture), wm)
	// The SAP advisory's two CVEs map; the Apple SA bulletin's CVE is skipped;
	// the 2020 item is older than the watermark.
	if len(out) != 2 {
		t.Fatalf("got %d CVEs, want 2: %v", len(out), out)
	}
	if out["CVE-2026-76964"] != "https://seclists.org/fulldisclosure/2026/Nov/36" {
		t.Fatalf("CVE-2026-76964 -> %q", out["CVE-2026-76964"])
	}
	if _, ok := out["CVE-2026-99999"]; ok {
		t.Fatalf("Apple SA CVE must not be treated as a PoC: %v", out)
	}
	// Watermark advances past both in-window items (the SAP post is newest).
	if want := "17 Nov 2026 19:15:53"; maxTs.Format("02 Jan 2006 15:04:05") != want {
		t.Errorf("maxTs = %s, want %s", maxTs.Format("02 Jan 2006 15:04:05"), want)
	}
}
