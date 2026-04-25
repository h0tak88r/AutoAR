package analyzer

// manifest_parser.go — XML-based AndroidManifest.xml parser.
//
// Replaces the fragile regex-based component detection functions in analyzer.go.
// Uses only the standard library encoding/xml package — no new dependencies.
//
// Why encoding/xml instead of avast/apkparser or shogo82148/androidbinary:
//   - Those packages parse BINARY AXML from a raw .apk zip.
//   - We work with the DECODED plain-text XML produced by jadx.
//   - encoding/xml handles decoded XML perfectly with zero extra deps.
//
// Key improvements over regex:
//   - Attribute ORDER independent (regex assumed android:name always before android:exported).
//   - No false positives from multi-line (?s) bleed-through.
//   - Correctly handles all component types in a single pass.
//   - Covers <uses-sdk> for minSdkVersion / targetSdkVersion extraction.

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
	"sync"
)

// ── Manifest XML structures ───────────────────────────────────────────────────
// We map only the attributes we care about; unknown elements/attributes are ignored.

type xmlManifest struct {
	XMLName     xml.Name   `xml:"manifest"`
	Package     string     `xml:"package,attr"`
	VersionName string     `xml:"versionName,attr"`
	VersionCode string     `xml:"versionCode,attr"`
	UsesSdk     xmlUsesSdk `xml:"uses-sdk"`
	Application xmlApp     `xml:"application"`
}

type xmlUsesSdk struct {
	MinSdkVersion    string `xml:"minSdkVersion,attr"`
	TargetSdkVersion string `xml:"targetSdkVersion,attr"`
	MaxSdkVersion    string `xml:"maxSdkVersion,attr"`
}

type xmlApp struct {
	Debuggable       string        `xml:"debuggable,attr"`
	AllowBackup      string        `xml:"allowBackup,attr"`
	NetworkSecurity  string        `xml:"networkSecurityConfig,attr"`
	UsesCleartextTraffic string   `xml:"usesCleartextTraffic,attr"`
	BackupAgent      string        `xml:"backupAgent,attr"`
	Activities       []xmlActivity `xml:"activity"`
	Services         []xmlService  `xml:"service"`
	Receivers        []xmlReceiver `xml:"receiver"`
	Providers        []xmlProvider `xml:"provider"`
}

type xmlIntentFilter struct {
	Actions    []xmlAttrName `xml:"action"`
	Categories []xmlAttrName `xml:"category"`
	Data       []xmlData     `xml:"data"`
}

type xmlAttrName struct {
	Name string `xml:"name,attr"`
}

type xmlData struct {
	Scheme string `xml:"scheme,attr"`
	Host   string `xml:"host,attr"`
	Path   string `xml:"path,attr"`
}

type xmlActivity struct {
	Name          string            `xml:"name,attr"`
	Exported      string            `xml:"exported,attr"`
	TaskAffinity  string            `xml:"taskAffinity,attr"`
	LaunchMode    string            `xml:"launchMode,attr"`
	Permission    string            `xml:"permission,attr"`
	IntentFilters []xmlIntentFilter `xml:"intent-filter"`
}

type xmlService struct {
	Name          string            `xml:"name,attr"`
	Exported      string            `xml:"exported,attr"`
	Permission    string            `xml:"permission,attr"`
	IntentFilters []xmlIntentFilter `xml:"intent-filter"`
}

type xmlReceiver struct {
	Name          string            `xml:"name,attr"`
	Exported      string            `xml:"exported,attr"`
	Permission    string            `xml:"permission,attr"`
	IntentFilters []xmlIntentFilter `xml:"intent-filter"`
}

type xmlProvider struct {
	Name        string `xml:"name,attr"`
	Exported    string `xml:"exported,attr"`
	Authorities string `xml:"authorities,attr"`
	Permission  string `xml:"permission,attr"`
	ReadPermission  string `xml:"readPermission,attr"`
	WritePermission string `xml:"writePermission,attr"`
}

// ── ParsedManifest is the result of a full manifest parse ────────────────────

type ParsedManifest struct {
	PackageName      string
	VersionName      string
	VersionCode      string
	MinSdkVersion    string
	TargetSdkVersion string

	// Component findings (formatted for the existing results map)
	ExportedActivities              []string
	ExportedServices                []string
	ExportedBroadcastReceivers      []string
	ExportedContentProviders        []string
	DeepLinks                       []string
	CustomURLSchemes                 []string
	TaskAffinityActivities          []string
	SingleTaskActivities            []string
	WebViewActivities               []string
	FileProviderExports             []string
	DebugMode                       []string
	AllowBackup                     []string

	// New checks
	CleartextTrafficAllowed         []string // android:usesCleartextTraffic="true"
	MissingNetworkSecurityConfig    []string // no networkSecurityConfig set
	UnprotectedDeepLinks            []string // deep link activity with no permission
	UnprotectedExportedActivities   []string // exported activity with no permission
	UnprotectedExportedReceivers    []string // exported receiver with no permission
	UnsafeContentProvider           []string // exported provider with no read/write permissions
}

// ── ParseManifestXML parses a decoded AndroidManifest.xml ────────────────────

func ParseManifestXML(path string) (*ParsedManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}

	// encoding/xml is strict about namespaces; jadx uses android: prefix.
	// We strip the namespace declarations so attribute matching works cleanly.
	cleaned := stripNamespaceDeclarations(data)

	var m xmlManifest
	if err := xml.Unmarshal(cleaned, &m); err != nil {
		return nil, fmt.Errorf("parse manifest xml: %w", err)
	}

	pm := &ParsedManifest{
		PackageName:      m.Package,
		VersionName:      m.VersionName,
		VersionCode:      m.VersionCode,
		MinSdkVersion:    m.UsesSdk.MinSdkVersion,
		TargetSdkVersion: m.UsesSdk.TargetSdkVersion,
	}

	app := m.Application

	// ── debuggable ────────────────────────────────────────────────────────────
	if strings.EqualFold(app.Debuggable, "true") {
		pm.DebugMode = []string{"AndroidManifest.xml: android:debuggable=\"true\" (application is debuggable — attach debugger, extract secrets)"}
	}

	// ── allowBackup ───────────────────────────────────────────────────────────
	if strings.EqualFold(app.AllowBackup, "true") {
		pm.AllowBackup = []string{"AndroidManifest.xml: android:allowBackup=\"true\" (ADB backup can extract app data without root)"}
	}

	// ── cleartext traffic ─────────────────────────────────────────────────────
	if strings.EqualFold(app.UsesCleartextTraffic, "true") {
		pm.CleartextTrafficAllowed = []string{"AndroidManifest.xml: android:usesCleartextTraffic=\"true\" (HTTP traffic allowed — credentials/tokens may be transmitted in plaintext)"}
	}

	// ── missing network security config ───────────────────────────────────────
	if app.NetworkSecurity == "" && !strings.EqualFold(app.UsesCleartextTraffic, "false") {
		pm.MissingNetworkSecurityConfig = []string{"AndroidManifest.xml: networkSecurityConfig not set — no certificate pinning or cleartext traffic restrictions defined"}
	}

	// ── Activities ────────────────────────────────────────────────────────────
	for _, a := range app.Activities {
		name := a.Name

		exported := isExported(a.Exported, a.IntentFilters)

		if exported {
			ctx := buildActivityContext(a)
			pm.ExportedActivities = append(pm.ExportedActivities,
				fmt.Sprintf("AndroidManifest.xml: %s (Context: %s)", name, ctx))

			// Exported with no permission = privilege escalation risk
			if a.Permission == "" {
				pm.UnprotectedExportedActivities = append(pm.UnprotectedExportedActivities,
					fmt.Sprintf("AndroidManifest.xml: %s exported with no android:permission (any app can start this activity)", name))
			}
		}

		// Task hijacking: custom taskAffinity
		if a.TaskAffinity != "" && a.TaskAffinity != m.Package {
			ctx := buildActivityContext(a)
			pm.TaskAffinityActivities = append(pm.TaskAffinityActivities,
				fmt.Sprintf("AndroidManifest.xml: %s (TaskAffinity: %s) (Context: %s)", name, a.TaskAffinity, ctx))
		}

		// singleTask launch mode
		if strings.EqualFold(a.LaunchMode, "singleTask") ||
			strings.EqualFold(a.LaunchMode, "2") { // apktool sometimes outputs numeric code
			ctx := buildActivityContext(a)
			pm.SingleTaskActivities = append(pm.SingleTaskActivities,
				fmt.Sprintf("AndroidManifest.xml: %s (LaunchMode: singleTask) (Context: %s)", name, ctx))
		}

		// Deep links & schemes
		for _, filter := range a.IntentFilters {
			hasView := false
			for _, action := range filter.Actions {
				if action.Name == "android.intent.action.VIEW" {
					hasView = true
				}
			}
			if !hasView {
				continue
			}

			// WebView: has BROWSABLE category
			for _, cat := range filter.Categories {
				if cat.Name == "android.intent.category.BROWSABLE" {
					ctx := buildActivityContext(a)
					pm.WebViewActivities = append(pm.WebViewActivities,
						fmt.Sprintf("AndroidManifest.xml: %s (Context: %s)", name, ctx))
					break
				}
			}

			// Schemes
			for _, d := range filter.Data {
				if d.Scheme != "" {
					if isHTTP := d.Scheme == "http" || d.Scheme == "https"; !isHTTP {
						pm.CustomURLSchemes = append(pm.CustomURLSchemes,
							fmt.Sprintf("AndroidManifest.xml: Custom scheme '%s://'", d.Scheme))
					}
					// Deep link if has DEFAULT category too
					for _, cat := range filter.Categories {
						if cat.Name == "android.intent.category.DEFAULT" {
							pm.DeepLinks = append(pm.DeepLinks,
								fmt.Sprintf("AndroidManifest.xml: %s -> %s:// (Context: %s)",
									name, d.Scheme, buildActivityContext(a)))
							// Unprotected deep link: no permission guard
							if a.Permission == "" {
								pm.UnprotectedDeepLinks = append(pm.UnprotectedDeepLinks,
									fmt.Sprintf("AndroidManifest.xml: %s handles deep link %s:// with no android:permission — open redirect / intent hijacking risk",
										name, d.Scheme))
							}
						}
					}
				}
			}
		}
	}

	// ── Services ──────────────────────────────────────────────────────────────
	for _, svc := range app.Services {
		if isExported(svc.Exported, svc.IntentFilters) {
			pm.ExportedServices = append(pm.ExportedServices,
				fmt.Sprintf("AndroidManifest.xml: %s (Context: exported service)", svc.Name))
		}
	}

	// ── Broadcast receivers ───────────────────────────────────────────────────
	for _, recv := range app.Receivers {
		if isExported(recv.Exported, recv.IntentFilters) {
			pm.ExportedBroadcastReceivers = append(pm.ExportedBroadcastReceivers,
				fmt.Sprintf("AndroidManifest.xml: %s (Context: exported broadcast receiver)", recv.Name))
			// No permission guard = intent hijacking / information disclosure
			if recv.Permission == "" {
				pm.UnprotectedExportedReceivers = append(pm.UnprotectedExportedReceivers,
					fmt.Sprintf("AndroidManifest.xml: %s exported broadcast receiver with no android:permission — any app can send intents to it", recv.Name))
			}
		}
	}

	// ── Content providers ─────────────────────────────────────────────────────
	for _, prov := range app.Providers {
		exported := strings.EqualFold(prov.Exported, "true")
		if exported {
			pm.ExportedContentProviders = append(pm.ExportedContentProviders,
				fmt.Sprintf("AndroidManifest.xml: %s (Context: exported content provider)", prov.Name))

			// File provider with explicit authorities
			if prov.Authorities != "" {
				pm.FileProviderExports = append(pm.FileProviderExports,
					fmt.Sprintf("AndroidManifest.xml: %s (Authority: %s) (Context: exported provider)", prov.Name, prov.Authorities))
			}

			// No read/write permission = data theft risk
			if prov.Permission == "" && prov.ReadPermission == "" && prov.WritePermission == "" {
				pm.UnsafeContentProvider = append(pm.UnsafeContentProvider,
					fmt.Sprintf("AndroidManifest.xml: %s exported with no read/writePermission — any app can read/write provider data", prov.Name))
			}
		}
	}

	return pm, nil
}

// ── InjectIntoResults merges ParsedManifest into the existing results map ─────

func (pm *ParsedManifest) InjectIntoResults(results map[string][]string, mu *sync.Mutex) {
	inject := func(key string, vals []string) {
		if len(vals) == 0 {
			return
		}
		mu.Lock()
		results[key] = append(results[key], vals...)
		mu.Unlock()
	}
	inject("ExportedActivities", pm.ExportedActivities)
	inject("ExportedServices", pm.ExportedServices)
	inject("ExportedBroadcastReceivers", pm.ExportedBroadcastReceivers)
	inject("ExportedContentProviders", pm.ExportedContentProviders)
	inject("DeepLinks", pm.DeepLinks)
	inject("CustomURLSchemes", pm.CustomURLSchemes)
	inject("taskAffinity", pm.TaskAffinityActivities)
	inject("SingleTaskLaunchMode", pm.SingleTaskActivities)
	inject("WebViews", pm.WebViewActivities)
	inject("FileProviderExports", pm.FileProviderExports)
	inject("DebugMode", pm.DebugMode)
	inject("AllowBackup", pm.AllowBackup)
	// New checks
	inject("CleartextTraffic", pm.CleartextTrafficAllowed)
	inject("MissingNetworkSecurityConfig", pm.MissingNetworkSecurityConfig)
	inject("UnprotectedDeepLinks", pm.UnprotectedDeepLinks)
	inject("UnprotectedExportedActivities", pm.UnprotectedExportedActivities)
	inject("UnprotectedExportedReceivers", pm.UnprotectedExportedReceivers)
	inject("UnsafeContentProvider", pm.UnsafeContentProvider)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// isExported determines the effective exported value per Android rules:
//   - "true"  → explicitly exported
//   - "false" → explicitly NOT exported
//   - ""      → implicitly exported IF the component has intent-filters
func isExported(attr string, filters []xmlIntentFilter) bool {
	switch strings.ToLower(strings.TrimSpace(attr)) {
	case "true":
		return true
	case "false":
		return false
	default:
		return len(filters) > 0 // implicit export rule (pre-Android 12)
	}
}

func buildActivityContext(a xmlActivity) string {
	parts := []string{}
	if a.LaunchMode != "" {
		parts = append(parts, "launchMode="+a.LaunchMode)
	}
	if a.TaskAffinity != "" {
		parts = append(parts, "taskAffinity="+a.TaskAffinity)
	}
	if a.Exported != "" {
		parts = append(parts, "exported="+a.Exported)
	}
	for _, f := range a.IntentFilters {
		for _, action := range f.Actions {
			parts = append(parts, "action="+action.Name)
		}
	}
	if len(parts) == 0 {
		return "activity"
	}
	return strings.Join(parts, ", ")
}

// stripNamespaceDeclarations rewrites the XML so encoding/xml can match
// android:xxx attributes without needing full namespace resolution.
// jadx emits: xmlns:android="http://schemas.android.com/apk/res/android"
// encoding/xml sees "android" as a namespace prefix and strips it from attr names.
// We rename "android:foo" → "foo" so our struct tags match cleanly.
func stripNamespaceDeclarations(data []byte) []byte {
	s := string(data)
	// Remove the namespace declaration
	s = strings.ReplaceAll(s, ` xmlns:android="http://schemas.android.com/apk/res/android"`, "")
	s = strings.ReplaceAll(s, ` xmlns:tools="http://schemas.android.com/tools"`, "")
	// Replace android: prefix on attributes
	s = strings.ReplaceAll(s, "android:", "")
	// Remove tools: prefixed attrs (we don't need them)
	// Simple approach: remove tools:xxx="..." patterns
	return []byte(s)
}
