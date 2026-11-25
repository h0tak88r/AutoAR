package scope

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/sw33tLie/bbscope/pkg/platforms/bugcrowd"
	"github.com/sw33tLie/bbscope/pkg/platforms/hackerone"
	"github.com/sw33tLie/bbscope/pkg/platforms/immunefi"
	"github.com/sw33tLie/bbscope/pkg/platforms/intigriti"
	"github.com/sw33tLie/bbscope/pkg/platforms/yeswehack"
	"github.com/sw33tLie/bbscope/pkg/scope"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Platform represents a bug bounty platform
type Platform string

const (
	PlatformHackerOne Platform = "h1"
	PlatformBugcrowd  Platform = "bc"
	PlatformIntigriti Platform = "it"
	PlatformYesWeHack Platform = "ywh"
	PlatformImmunefi  Platform = "immunefi"
)

// Options contains options for fetching scope
type Options struct {
	Platform     Platform
	Username     string
	Token        string
	Email        string
	Password     string
	Categories   string
	BBPOnly      bool
	PvtOnly      bool
	IncludeOOS   bool
	Concurrency  int
	PublicOnly   bool // For HackerOne
	ActiveOnly   bool // For HackerOne
	ExtractRoots bool // Extract root domains (default: true for backward compatibility)
}

// FetchScope fetches scope from the specified platform.
//
// WARNING: bbscope calls log.Fatal (os.Exit) on HTTP errors, bad tokens and
// rate limits, and indexes upstream strings unchecked. Never call this from
// the long-lived API process — run it in a disposable child (`autoar
// scope-fetch` / `autoar catalog-sync`).
func FetchScope(opts Options) ([]scope.ProgramData, error) {
	switch opts.Platform {
	case PlatformHackerOne:
		if opts.Username == "" || opts.Token == "" {
			return nil, fmt.Errorf("username and token are required for HackerOne")
		}
		auth := base64.StdEncoding.EncodeToString([]byte(opts.Username + ":" + opts.Token))
		if opts.Categories == "" {
			opts.Categories = "all"
		}
		if opts.Concurrency == 0 {
			opts.Concurrency = 3
		}
		programs, err := hackerone.GetAllProgramsScope(auth, opts.BBPOnly, opts.PvtOnly, opts.PublicOnly, opts.Categories, opts.ActiveOnly, opts.Concurrency, false, "t", " ", opts.IncludeOOS)
		return programs, err

	case PlatformBugcrowd:
		// bbscope's email/password sign-in predates Bugcrowd's Okta flow;
		// AutoAR signs in itself (accounts.BugcrowdSession) and passes the session.
		if opts.Token == "" {
			return nil, fmt.Errorf("a Bugcrowd session is required — add the account's email, password and 2FA secret in Settings so AutoAR can sign in")
		}
		if opts.Categories == "" {
			opts.Categories = "all"
		}
		if opts.Concurrency == 0 {
			opts.Concurrency = 3
		}
		programs, err := bugcrowd.GetAllProgramsScope(opts.Token, opts.BBPOnly, opts.PvtOnly, opts.Categories, "t", opts.Concurrency, " ", opts.IncludeOOS, false, nil)
		return programs, err

	case PlatformIntigriti:
		if opts.Token == "" {
			return nil, fmt.Errorf("token is required for Intigriti")
		}
		if opts.Categories == "" {
			opts.Categories = "all"
		}
		programs := intigriti.GetAllProgramsScope(opts.Token, opts.BBPOnly, opts.PvtOnly, opts.Categories, "t", " ", opts.IncludeOOS, false)
		return programs, nil

	case PlatformYesWeHack:
		if opts.Token == "" && (opts.Email == "" || opts.Password == "") {
			return nil, fmt.Errorf("token or email/password are required for YesWeHack")
		}
		if opts.Categories == "" {
			opts.Categories = "all"
		}
		token := opts.Token
		if token == "" {
			// Login with email/password
			var err error
			token, err = yeswehack.Login(opts.Email, opts.Password, "", "")
			if err != nil {
				return nil, fmt.Errorf("failed to login to YesWeHack: %w", err)
			}
		}
		programs := yeswehack.GetAllProgramsScope(token, opts.BBPOnly, opts.PvtOnly, opts.Categories, "t", " ", false)
		return programs, nil

	case PlatformImmunefi:
		if opts.Categories == "" {
			opts.Categories = "all"
		}
		if opts.Concurrency == 0 {
			opts.Concurrency = 5
		}
		programs := immunefi.GetAllProgramsScope(opts.Categories, opts.Concurrency)
		return programs, nil

	default:
		return nil, fmt.Errorf("unsupported platform: %s", opts.Platform)
	}
}

// FetchResult is the JSON a disposable `scope-fetch` child hands back to the
// API process (bbscope may os.Exit, so it never runs in-process there).
type FetchResult struct {
	Programs []scope.ProgramData `json:"programs"`
	Error    string              `json:"error,omitempty"`
}

// webCategories are asset categories (normalized: lowercase, '-'/' ' → '_')
// that describe web-reachable hosts. They win over nonWebCategoryTokens, so
// "web_application" stays web even though "application" alone is YesWeHack's
// executable type.
var webCategories = map[string]bool{
	"": true, "url": true, "wildcard": true, "domain": true, "website": true, "websites": true,
	"web": true, "api": true, "web_application": true, "websites_and_applications": true,
	"ip_address": true, "ip": true, "cidr": true, "iprange": true, "ip_range": true, "network": true,
}

// nonWebCategoryTokens mark a category as non-web when any WHOLE token of it
// matches (google_play_app_id → "app", other_apk → "apk", source_code →
// "code", mobile-application-ios → "mobile"). Tokens, never substrings.
var nonWebCategoryTokens = map[string]bool{
	"mobile": true, "android": true, "ios": true, "apple": true, "app": true, "apk": true, "ipa": true,
	"application": true, "executable": true, "executables": true, "exe": true, "code": true, "source": true,
	"hardware": true, "device": true, "smart": true, "contract": true, "ai": true, "model": true,
	"other": true, "testflight": true, "binary": true, "desktop": true, "windows": true, "iot": true,
	"blockchain": true, "dlt": true, "physical": true, "store": true,
}

// nonWebFileLabels are final labels that mark a target as a downloadable
// artifact rather than a host ("acme-installer.exe", "app-release.apk").
var nonWebFileLabels = map[string]bool{
	"apk": true, "ipa": true, "exe": true, "dmg": true, "deb": true, "rpm": true, "msi": true, "appx": true,
}

// appStoreHosts are store listings some programs put in web-typed fields;
// they are never scan targets or program hosts.
var appStoreHosts = map[string]bool{
	"play.google.com": true, "apps.apple.com": true, "itunes.apple.com": true,
	"testflight.apple.com": true, "apps.microsoft.com": true, "chrome.google.com": true,
	"chromewebstore.google.com": true, "addons.mozilla.org": true, "f-droid.org": true,
}

func splitTokens(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	})
}

// isMobileOrAppTarget reports whether a scope element is a non-web asset
// (mobile app, source repo, executable, hardware, "other", …) that must never
// become a scan root or a catalog host. It decides by the element's CATEGORY
// (whole tokens) and by unambiguous target shapes (app-store hosts, file
// extensions) — never by substrings of the host, which used to drop
// whatsapp.com ("app"), cloudflare.com ("cloud") or debian.org ("deb").
func isMobileOrAppTarget(target, category string) bool {
	cat := strings.ToLower(strings.TrimSpace(category))
	cat = strings.NewReplacer("-", "_", " ", "_").Replace(cat)
	if !webCategories[cat] {
		for _, tok := range splitTokens(cat) {
			if nonWebCategoryTokens[tok] {
				return true
			}
		}
	}
	pt, ok := ParseTarget(target)
	if !ok {
		return false
	}
	if appStoreHosts[pt.Host] {
		return true
	}
	labels := strings.Split(pt.Host, ".")
	return nonWebFileLabels[labels[len(labels)-1]]
}

// multiTenantSaaS are vendor domains whose subdomains (or URL paths) belong
// to the vendor's CUSTOMERS. A program listing acme.zendesk.com or
// https://github.com/acme/repo owns that one tenant — never the vendor. None
// of these (or anything under them) may become an enumeration root, and a
// path-bearing URL on one never stands for the vendor host itself.
var multiTenantSaaS = []string{
	"zendesk.com", "atlassian.net", "jira.com", "okta.com", "oktapreview.com", "okta-emea.com",
	"github.com", "github.io", "githubusercontent.com", "gitlab.com", "gitlab.io", "bitbucket.org",
	"bitbucket.io", "herokuapp.com", "herokudns.com", "azurewebsites.net", "azureedge.net",
	"azurefd.net", "azure-api.net", "cloudapp.net", "cloudapp.azure.com", "core.windows.net",
	"trafficmanager.net", "sharepoint.com", "onmicrosoft.com", "cloudfront.net", "amazonaws.com",
	"awsapps.com", "elasticbeanstalk.com", "appspot.com", "firebaseapp.com", "firebaseio.com",
	"web.app", "run.app", "cloudfunctions.net", "googleusercontent.com", "vercel.app", "now.sh",
	"netlify.app", "netlify.com", "pages.dev", "workers.dev", "fly.dev", "onrender.com",
	"myshopify.com", "salesforce.com", "force.com", "visualforce.com", "freshdesk.com",
	"freshservice.com", "statuspage.io", "wordpress.com", "wpengine.com", "wpenginepowered.com",
	"squarespace.com", "wixsite.com", "webflow.io", "ghost.io", "readme.io", "readthedocs.io",
	"gitbook.io", "notion.site", "hubspotpagebuilder.com", "service-now.com", "zohodesk.com",
	"helpscoutdocs.com", "uservoice.com", "intercom.help", "typeform.com", "surveymonkey.com",
	"fastly.net", "akamaized.net", "edgekey.net", "edgesuite.net", "digitaloceanspaces.com",
}

// saasRootOf returns the multiTenantSaaS vendor domain host is, or sits
// under ("" when none).
func saasRootOf(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	for _, d := range multiTenantSaaS {
		if host == d || strings.HasSuffix(host, "."+d) {
			return d
		}
	}
	return ""
}

// IsMultiTenantSaaS reports whether host is, or sits under, a multi-tenant
// SaaS vendor domain (see multiTenantSaaS).
func IsMultiTenantSaaS(host string) bool { return saasRootOf(host) != "" }

// ParsedTarget is a scope target reduced to its host.
type ParsedTarget struct {
	Host     string // lowercase host: no scheme, userinfo, port, path or wildcard labels
	Wildcard bool   // the target covered subdomains of Host ("*.host", "api.*.host")
	HasPath  bool   // a URL path/query beyond "/" was attached (a resource ON the host)
	IsIP     bool
}

// ParseTarget normalizes a raw scope target ("*.acme.com",
// "https://api.acme.com:8443/v1", "acme.com") into a ParsedTarget. ok is
// false for anything that is not a usable host (free text, package ids
// without a dot, "acme.*", invalid characters).
func ParseTarget(target string) (ParsedTarget, bool) {
	var pt ParsedTarget
	t := strings.ToLower(strings.TrimSpace(target))
	if t == "" || strings.ContainsAny(t, " \t\r\n") {
		return pt, false
	}
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		pt.HasPath = t[i:] != "/"
		t = t[:i]
	}
	if i := strings.LastIndex(t, "@"); i >= 0 {
		t = t[i+1:]
	}
	if strings.Count(t, ":") == 1 {
		t = t[:strings.Index(t, ":")]
	}
	t = strings.Trim(t, ".")
	if net.ParseIP(t) != nil {
		pt.Host, pt.IsIP = t, true
		return pt, true
	}
	if strings.ContainsAny(t, "*?") {
		// Keep only the fixed suffix after the last wildcard label:
		// "*.acme.com" → acme.com, "api.*.acme.com" → acme.com,
		// "*-dev.acme.com" → acme.com; "acme.*" leaves nothing usable.
		labels := strings.Split(t, ".")
		last := -1
		for i, l := range labels {
			if strings.ContainsAny(l, "*?") {
				last = i
			}
		}
		t = strings.Join(labels[last+1:], ".")
		pt.Wildcard = true
	}
	if t == "" || !strings.Contains(t, ".") {
		return pt, false
	}
	if !isASCII(t) {
		a, err := idna.Lookup.ToASCII(t)
		if err != nil {
			return pt, false
		}
		t = a
	}
	for _, r := range t {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_') {
			return pt, false
		}
	}
	pt.Host = t
	return pt, true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// RegistrableDomain returns host's eTLD+1 from the public-suffix list
// compiled into golang.org/x/net/publicsuffix (ICANN + private sections, so
// tenants of PSL-listed platforms such as acme.github.io are registrable on
// their own). No runtime download, no cache file. ok is false when host is
// itself a public suffix.
func RegistrableDomain(host string) (string, bool) {
	reg, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return "", false
	}
	return reg, true
}

// apexRootCategory reports whether a bare apex listing may stand for the
// whole domain: only when the platform typed it as a wildcard/domain, or gave
// no type at all (aggregator rows).
func apexRootCategory(category string) bool {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "", "wildcard", "domain":
		return true
	}
	return false
}

// ElementRoot returns the enumeration root a scope element authorizes, if
// any. Only wildcards ("*.x" → x) and a bare apex explicitly typed as a
// wildcard/domain (or untyped) qualify. A specific host (app.acme.com,
// acme.zendesk.com, https://github.com/acme/repo) authorizes that host only —
// widening it to the registrable parent is what used to mass-scan
// out-of-scope subdomains and whole SaaS vendors.
func ElementRoot(e scope.ScopeElement) (string, bool) {
	if isMobileOrAppTarget(e.Target, e.Category) {
		return "", false
	}
	pt, ok := ParseTarget(e.Target)
	if !ok || pt.IsIP || IsMultiTenantSaaS(pt.Host) {
		return "", false
	}
	reg, ok := RegistrableDomain(pt.Host)
	if !ok {
		return "", false
	}
	if pt.Wildcard {
		return pt.Host, true
	}
	if pt.HasPath || pt.Host != reg || !apexRootCategory(e.Category) {
		return "", false
	}
	return reg, true
}

// PublicProgramURL converts a platform's API program URL to its human-facing,
// browsable URL. bbscope returns YesWeHack programs as
// https://api.yeswehack.com/programs/<slug>, but the page a researcher opens is
// https://yeswehack.com/programs/<slug>. Other platforms are returned unchanged.
func PublicProgramURL(u string) string {
	return strings.Replace(u, "://api.yeswehack.com/", "://yeswehack.com/", 1)
}

// ScopeElementRoots extracts unique enumeration roots (see ElementRoot) from
// a list of scope elements, skipping non-web assets. Callers must carry the
// element categories for the asset-type filter to apply.
func ScopeElementRoots(elems []scope.ScopeElement) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range elems {
		if d, ok := ElementRoot(e); ok && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// InScopeRoots / OutScopeRoots are convenience wrappers over ScopeElementRoots.
func InScopeRoots(pd scope.ProgramData) []string  { return ScopeElementRoots(pd.InScope) }
func OutScopeRoots(pd scope.ProgramData) []string { return ScopeElementRoots(pd.OutOfScope) }

// ExtractRootDomains returns the enumeration roots across programs: each
// program's in-scope roots minus any root that same program lists out of
// scope. Out-of-scope elements never contribute roots. The error is kept for
// API compatibility; the embedded public-suffix list cannot fail to load.
func ExtractRootDomains(programs []scope.ProgramData) ([]string, error) {
	rootDomains := make(map[string]bool)
	for _, program := range programs {
		oos := map[string]bool{}
		for _, r := range OutScopeRoots(program) {
			oos[r] = true
		}
		for _, r := range InScopeRoots(program) {
			if !oos[r] {
				rootDomains[r] = true
			}
		}
	}

	result := make([]string, 0, len(rootDomains))
	for domain := range rootDomains {
		result = append(result, domain)
	}
	sort.Strings(result)
	return result, nil
}

// CatalogEntry is one host-level catalog row: an exact host ("app.acme.com")
// or a wildcard ("*.acme.com"), in or out of scope.
type CatalogEntry struct {
	Domain  string
	InScope bool
}

// catalogKey reduces a scope element to its catalog key: "*.x" for
// wildcards, the bare host otherwise. Non-web assets, IPs/CIDRs, public
// suffixes, vendor-wide SaaS wildcards (*.zendesk.com would claim every
// customer tenant) and path-bearing URLs on SaaS hosts (a repo, not
// github.com) are dropped.
func catalogKey(e scope.ScopeElement) (string, bool) {
	if isMobileOrAppTarget(e.Target, e.Category) {
		return "", false
	}
	pt, ok := ParseTarget(e.Target)
	if !ok || pt.IsIP {
		return "", false
	}
	if _, ok := RegistrableDomain(pt.Host); !ok {
		return "", false
	}
	if pt.Wildcard {
		if pt.Host == saasRootOf(pt.Host) {
			return "", false
		}
		return "*." + pt.Host, true
	}
	if pt.HasPath && IsMultiTenantSaaS(pt.Host) {
		return "", false
	}
	return pt.Host, true
}

// CatalogEntries builds a program's host-level catalog rows from its raw
// scope: exact hosts and wildcards exactly as listed, never widened to the
// registrable root. An entry listed both in and out of scope is stored out of
// scope — explicit exclusions take precedence.
func CatalogEntries(pd scope.ProgramData) []CatalogEntry {
	state := map[string]bool{}
	var order []string
	add := func(elems []scope.ScopeElement, in bool) {
		for _, e := range elems {
			k, ok := catalogKey(e)
			if !ok {
				continue
			}
			if prev, seen := state[k]; seen {
				state[k] = prev && in
				continue
			}
			order = append(order, k)
			state[k] = in
		}
	}
	add(pd.OutOfScope, false)
	add(pd.InScope, true)
	out := make([]CatalogEntry, 0, len(order))
	for _, k := range order {
		out = append(out, CatalogEntry{Domain: k, InScope: state[k]})
	}
	return out
}

// ExtractRawTargets extracts raw targets from scope data (without root domain extraction)
func ExtractRawTargets(programs []scope.ProgramData) []string {
	targets := make(map[string]bool)

	// Process all programs
	for _, program := range programs {
		// Process in-scope targets
		for _, elem := range program.InScope {
			target := strings.TrimSpace(elem.Target)
			if target != "" {
				targets[target] = true
			}
		}

		// Process out-of-scope targets if needed
		for _, elem := range program.OutOfScope {
			target := strings.TrimSpace(elem.Target)
			if target != "" {
				targets[target] = true
			}
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(targets))
	for target := range targets {
		result = append(result, target)
	}

	return result
}

// WriteRootDomains writes root domains to file or stdout
func WriteRootDomains(domains []string, outputFile string) error {
	if outputFile == "" {
		// Write to stdout
		for _, domain := range domains {
			fmt.Println(domain)
		}
		return nil
	}

	// Write to file
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	for _, domain := range domains {
		if _, err := fmt.Fprintln(file, domain); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
	}

	return nil
}
