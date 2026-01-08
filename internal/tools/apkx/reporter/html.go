package reporter

import (
	"bytes"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type HTMLReportData struct {
	APKName         string
	PackageName     string
	Version         string
	MinSdkVersion   string
	ScanTime        string
	TotalFindings   int
	Categories      map[string]CategoryData
	Vulnerabilities []VulnerabilityData
	Summary         SummaryData
}

type CategoryData struct {
	Name     string
	Count    int
	Findings []FindingData
}

type FindingData struct {
	File    string
	Match   string
	Context string
}

type VulnerabilityData struct {
	Type        string
	Severity    string
	Description string
	Details     string
}

type SummaryData struct {
	TotalFiles      int
	TotalPatterns   int
	Vulnerabilities int
	HighRisk        int
}

func GenerateHTMLReport(data HTMLReportData) (string, error) {
	tmpl := template.Must(template.New("report").Funcs(template.FuncMap{
		"gt":         func(a, b int) bool { return a > b },
		"stripAnsi":  stripAnsiCodes,
		"formatText": formatText,
		"splitLines": func(s string) []string { return strings.Split(s, "\n") },
	}).Parse(htmlTemplate))

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func stripAnsiCodes(text string) string {
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return ansiRegex.ReplaceAllString(text, "")
}

func formatText(text string) string {
	text = stripAnsiCodes(text)
	text = strings.TrimSpace(text)
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")
	text = regexp.MustCompile(`(❯ [A-Za-z]+:)`).ReplaceAllString(text, "\n\n$1")
	text = regexp.MustCompile(`(• [A-Za-z])`).ReplaceAllString(text, "\n$1")
	text = regexp.MustCompile(`(│ [A-Za-z])`).ReplaceAllString(text, "\n$1")
	text = regexp.MustCompile(`(╭─ [A-Za-z]+)`).ReplaceAllString(text, "\n\n$1")
	text = regexp.MustCompile(`(╰─)`).ReplaceAllString(text, "\n$1")
	text = strings.TrimSpace(text)
	text = regexp.MustCompile(`\n{3,}`).ReplaceAllString(text, "\n\n")
	return text
}

func getSeverityIcon(severity string) string {
	switch strings.ToLower(severity) {
	case "high":
		return "🔴"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "ℹ️"
	}
}

// ExtractMinSdkVersion extracts minSdkVersion from AndroidManifest.xml
func ExtractMinSdkVersion(decompileDir string) string {
	// Look for AndroidManifest.xml in common decompilation output locations
	manifestPaths := []string{
		filepath.Join(decompileDir, "AndroidManifest.xml"),
		filepath.Join(decompileDir, "sources", "AndroidManifest.xml"),
		filepath.Join(decompileDir, "resources", "AndroidManifest.xml"),
		filepath.Join(decompileDir, "res", "AndroidManifest.xml"),
		filepath.Join(decompileDir, "resources", "com.jbl.oneapp.apk", "AndroidManifest.xml"),
	}

	var manifestPath string
	for _, path := range manifestPaths {
		if _, err := os.Stat(path); err == nil {
			manifestPath = path
			break
		}
	}

	if manifestPath == "" {
		return ""
	}

	// Read the AndroidManifest.xml file
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		return ""
	}

	manifestContent := string(content)

	// Extract minSdkVersion using regex
	minSdkRegex := regexp.MustCompile(`android:minSdkVersion\s*=\s*["'](\d+)["']`)
	if matches := minSdkRegex.FindStringSubmatch(manifestContent); len(matches) > 1 {
		return matches[1]
	}

	// Try alternative pattern without quotes
	minSdkRegex2 := regexp.MustCompile(`android:minSdkVersion\s*=\s*(\d+)`)
	if matches := minSdkRegex2.FindStringSubmatch(manifestContent); len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// ExtractPackageInfo extracts package name and version from AndroidManifest.xml
func ExtractPackageInfo(decompileDir string) (packageName, version string) {
	// Look for AndroidManifest.xml in common decompilation output locations
	manifestPaths := []string{
		filepath.Join(decompileDir, "AndroidManifest.xml"),
		filepath.Join(decompileDir, "sources", "AndroidManifest.xml"),
		filepath.Join(decompileDir, "resources", "AndroidManifest.xml"),
		filepath.Join(decompileDir, "res", "AndroidManifest.xml"),
	}

	var manifestPath string
	for _, path := range manifestPaths {
		if _, err := os.Stat(path); err == nil {
			manifestPath = path
			break
		}
	}

	if manifestPath == "" {
		return "", ""
	}

	// Read the AndroidManifest.xml file
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", ""
	}

	manifestContent := string(content)

	// Extract package name
	packageRegex := regexp.MustCompile(`package\s*=\s*["']([^"']+)["']`)
	if matches := packageRegex.FindStringSubmatch(manifestContent); len(matches) > 1 {
		packageName = matches[1]
	}

	// Extract version name
	versionRegex := regexp.MustCompile(`android:versionName\s*=\s*["']([^"']+)["']`)
	if matches := versionRegex.FindStringSubmatch(manifestContent); len(matches) > 1 {
		version = matches[1]
	}

	// If version name not found, try version code
	if version == "" {
		versionCodeRegex := regexp.MustCompile(`android:versionCode\s*=\s*["']([^"']+)["']`)
		if matches := versionCodeRegex.FindStringSubmatch(manifestContent); len(matches) > 1 {
			version = "v" + matches[1]
		}
	}

	return packageName, version
}

const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK Security Analysis Report - {{.APKName}}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --bg-primary: #1a1a1a;
            --bg-secondary: #2d2d2d;
            --bg-tertiary: #3a3a3a;
            --text-primary: #ffffff;
            --text-secondary: #b0b0b0;
            --text-muted: #808080;
            --accent-primary: #00d4ff;
            --accent-secondary: #0099cc;
            --danger: #ff4757;
            --warning: #ffa502;
            --success: #2ed573;
            --border-color: #404040;
            --shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        }
        
        body {
            font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background: var(--bg-primary);
            min-height: 100vh;
            display: flex;
        }
        
        /* Sidebar */
        .sidebar {
            width: 320px;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            position: fixed;
            height: 100vh;
            overflow-y: auto;
            z-index: 1000;
            transition: transform 0.3s ease;
            box-shadow: var(--shadow);
        }
        
        .sidebar-close {
            display: none;
            position: absolute;
            top: 1rem;
            right: 1rem;
            background: var(--danger);
            color: white;
            border: none;
            width: 30px;
            height: 30px;
            border-radius: 50%;
            cursor: pointer;
            font-size: 1.2rem;
            z-index: 1001;
            align-items: center;
            justify-content: center;
        }
        
        .sidebar-close:hover {
            background: #e74c3c;
        }
        
        .sidebar-toggle {
            display: none;
            position: fixed;
            top: 1rem;
            left: 1rem;
            background: var(--accent-primary);
            color: var(--bg-primary);
            border: none;
            padding: 0.75rem 1rem;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 600;
            z-index: 1002;
            box-shadow: var(--shadow);
        }
        
        .sidebar-toggle:hover {
            background: var(--accent-secondary);
        }
        
        .sidebar.collapsed {
            transform: translateX(-100%);
        }
        
        .sidebar-header {
            padding: 24px;
            background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border-color);
        }
        
        .sidebar-header h2 {
            font-size: 1.4em;
            margin-bottom: 8px;
            color: var(--accent-primary);
        }
        
        .sidebar-header .subtitle {
            font-size: 0.9em;
            color: var(--text-secondary);
        }
        
        .nav-section {
            margin-bottom: 32px;
        }
        
        .nav-section h3 {
            padding: 0 24px 12px;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 12px;
        }
        
        .nav-item {
            display: block;
            padding: 16px 24px;
            color: var(--text-primary);
            text-decoration: none;
            transition: all 0.3s ease;
            border-left: 3px solid transparent;
            cursor: pointer;
            position: relative;
        }
        
        .nav-item:hover {
            background: var(--bg-tertiary);
            border-left-color: var(--accent-primary);
            transform: translateX(4px);
        }
        
        .nav-item.active {
            background: var(--bg-tertiary);
            border-left-color: var(--accent-primary);
        }
        
        .nav-item .count {
            float: right;
            background: var(--danger);
            color: white;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: 600;
            min-width: 20px;
            text-align: center;
        }
        
        .nav-item .count.zero {
            background: var(--text-muted);
        }
        
        .nav-item .count.success {
            background: var(--success);
        }
        
        .nav-badge {
            float: right;
            background: var(--accent-primary);
            color: var(--bg-primary);
            padding: 0.2rem 0.5rem;
            border-radius: 12px;
            font-size: 0.7rem;
            font-weight: bold;
            min-width: 20px;
            text-align: center;
            white-space: nowrap;
            flex-shrink: 0;
        }
        
        .nav-badge.danger { background: var(--danger); }
        .nav-badge.warning { background: var(--warning); }
        .nav-badge.success { background: var(--success); }
        
        .header-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }
        
        .info-item {
            background: var(--bg-tertiary);
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid var(--accent-primary);
        }
        
        .info-item h3 {
            color: var(--text-secondary);
            font-size: 0.8rem;
            text-transform: uppercase;
            margin-bottom: 0.5rem;
        }
        
        .info-item p {
            color: var(--text-primary);
            font-size: 1.1rem;
            font-weight: 500;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: var(--bg-secondary);
            padding: 1.5rem;
            border-radius: 12px;
            text-align: center;
            box-shadow: var(--shadow);
            transition: transform 0.2s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
        }
        
        .stat-card.danger { border-left: 4px solid var(--danger); }
        .stat-card.warning { border-left: 4px solid var(--warning); }
        .stat-card.success { border-left: 4px solid var(--success); }
        .stat-card.info { border-left: 4px solid var(--accent-primary); }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }
        
        .stat-number.danger { color: var(--danger); }
        .stat-number.warning { color: var(--warning); }
        .stat-number.success { color: var(--success); }
        .stat-number.info { color: var(--accent-primary); }
        
        .stat-label {
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .section {
            background: var(--bg-secondary);
            border-radius: 12px;
            margin-bottom: 2rem;
            box-shadow: var(--shadow);
            overflow: hidden;
        }
        
        .section-header {
            background: var(--bg-tertiary);
            padding: 1.5rem 2rem;
            border-bottom: 1px solid var(--border-color);
        }
        
        .section-header h2 {
            font-size: 1.5rem;
            color: var(--text-primary);
        }
        
        .section-content {
            padding: 2rem;
        }
        
        .vulnerability {
            background: var(--bg-tertiary);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-left: 4px solid var(--warning);
            transition: all 0.2s ease;
        }
        
        .vulnerability:hover {
            transform: translateX(4px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
        }
        
        .vulnerability.high { border-left-color: var(--danger); }
        .vulnerability.medium { border-left-color: var(--warning); }
        .vulnerability.low { border-left-color: var(--success); }
        
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .vuln-title {
            font-size: 1.2rem;
            font-weight: 600;
            color: var(--text-primary);
        }
        
        .vuln-severity {
            padding: 0.3rem 0.8rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .vuln-severity.high {
            background: var(--danger);
            color: white;
        }
        
        .vuln-severity.medium {
            background: var(--warning);
            color: var(--bg-primary);
        }
        
        .vuln-severity.low {
            background: var(--success);
            color: var(--bg-primary);
        }
        
        .vuln-description {
            color: var(--text-secondary);
            margin-bottom: 1rem;
            line-height: 1.6;
        }
        
        .vuln-context {
            background: var(--bg-primary);
            padding: 1rem;
            border-radius: 6px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.9rem;
            color: var(--text-muted);
            border: 1px solid var(--border-color);
            word-wrap: break-word;
            white-space: pre-wrap;
            word-break: break-all;
            overflow-x: auto;
        }
        
        .pattern-category {
            margin-bottom: 2rem;
        }
        
        .pattern-category h3 {
            color: var(--accent-primary);
            margin-bottom: 1rem;
            font-size: 1.2rem;
        }
        
        .pattern-item {
            background: var(--bg-tertiary);
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-radius: 8px;
            border-left: 4px solid var(--accent-primary);
            transition: all 0.2s ease;
        }
        
        .pattern-item:hover {
            transform: translateX(4px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
        }
        
        .pattern-header {
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border-color);
        }
        
        .pattern-header strong {
            color: var(--text-primary);
            font-size: 0.9rem;
        }
        
        .pattern-context {
            margin-top: 1rem;
        }
        
        .pattern-context pre {
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 1rem;
            margin: 0;
            overflow-x: auto;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.85rem;
            line-height: 1.4;
            color: var(--text-muted);
            word-wrap: break-word;
            white-space: pre-wrap;
            word-break: break-all;
        }
        
        .pattern-context code {
            background: none;
            padding: 0;
            color: inherit;
            font-size: inherit;
        }
        
        .empty-state {
            text-align: center;
            padding: 3rem;
            color: var(--text-muted);
        }
        
        .empty-state h3 {
            margin-bottom: 1rem;
            color: var(--text-secondary);
        }
        
        /* Controls */
        .controls {
            padding: 0 24px 24px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .control-group {
            margin-bottom: 20px;
        }
        
        .control-group label {
            display: block;
            font-size: 0.85em;
            margin-bottom: 8px;
            color: var(--text-secondary);
            font-weight: 500;
        }
        
        .control-group select,
        .control-group input {
            width: 100%;
            padding: 12px 16px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            background: var(--bg-tertiary);
            color: var(--text-primary);
            font-size: 0.9em;
            transition: all 0.3s ease;
        }
        
        .control-group select:focus,
        .control-group input:focus {
            outline: none;
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 3px rgba(0, 212, 255, 0.1);
        }
        
        .control-group input::placeholder {
            color: var(--text-muted);
        }
        
        .toggle-btn {
            background: var(--accent-primary);
            color: var(--bg-primary);
            border: none;
            padding: 12px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.9em;
            font-weight: 600;
            width: 100%;
            margin-bottom: 12px;
            transition: all 0.3s ease;
        }
        
        .toggle-btn:hover {
            background: var(--accent-secondary);
            transform: translateY(-2px);
        }
        
        .toggle-btn.active {
            background: var(--danger);
        }
        
        /* Main content */
        .main-content {
            flex: 1;
            margin-left: 320px;
            transition: margin-left 0.3s ease;
        }
        
        .main-content.expanded {
            margin-left: 0;
        }
        
        .top-bar {
            background: var(--bg-secondary);
            padding: 20px 32px;
            box-shadow: var(--shadow);
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
            border-bottom: 1px solid var(--border-color);
        }
        
        .menu-toggle {
            background: var(--accent-primary);
            color: var(--bg-primary);
            border: none;
            padding: 12px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1em;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .menu-toggle:hover {
            background: var(--accent-secondary);
            transform: translateY(-2px);
        }
        
        .view-controls {
            display: flex;
            gap: 12px;
            align-items: center;
        }
        
        .view-toggle {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            padding: 10px 18px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.9em;
            color: var(--text-primary);
            transition: all 0.3s ease;
        }
        
        .view-toggle:hover {
            background: var(--bg-primary);
            border-color: var(--accent-primary);
        }
        
        .view-toggle.active {
            background: var(--accent-primary);
            color: var(--bg-primary);
            border-color: var(--accent-primary);
        }
        
        .export-btn {
            background: var(--success);
            color: var(--bg-primary);
            border: none;
            padding: 10px 18px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.9em;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .export-btn:hover {
            background: #26c965;
            transform: translateY(-2px);
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 32px;
        }
        
        .header {
            background: var(--bg-secondary);
            color: var(--text-primary);
            padding: 40px;
            border-radius: 16px;
            margin-bottom: 32px;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
        }
        
        .header h1 {
            font-size: 2.8em;
            margin-bottom: 16px;
            font-weight: 700;
            color: var(--accent-primary);
        }
        
        .header .subtitle {
            font-size: 1.3em;
            opacity: 0.9;
            font-weight: 500;
        }
        
        /* Content sections */
        .content-section {
            display: none;
            background: var(--bg-secondary);
            padding: 32px;
            border-radius: 16px;
            box-shadow: var(--shadow);
            margin-bottom: 32px;
            border: 1px solid var(--border-color);
        }
        
        .content-section.active {
            display: block;
        }
        
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding-bottom: 20px;
            border-bottom: 2px solid var(--accent-primary);
        }
        
        .section-title {
            font-size: 2em;
            color: var(--text-primary);
            margin: 0;
            font-weight: 700;
        }
        
        .section-stats {
            display: flex;
            gap: 20px;
            align-items: center;
        }
        
        .stat-item {
            text-align: center;
            padding: 16px 20px;
            background: var(--bg-tertiary);
            border-radius: 12px;
            border-left: 4px solid var(--accent-primary);
            min-width: 100px;
        }
        
        .stat-number {
            font-size: 1.8em;
            font-weight: 700;
            color: var(--text-primary);
        }
        
        .stat-label {
            font-size: 0.9em;
            color: var(--text-secondary);
            margin-top: 8px;
            font-weight: 500;
        }
        
        /* Filter and search */
        .filter-bar {
            background: var(--bg-tertiary);
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 24px;
            display: flex;
            gap: 20px;
            align-items: center;
            flex-wrap: wrap;
            border: 1px solid var(--border-color);
        }
        
        .filter-group {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .filter-group label {
            font-weight: 600;
            color: var(--text-primary);
            white-space: nowrap;
        }
        
        .filter-group select,
        .filter-group input {
            padding: 12px 16px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            background: var(--bg-secondary);
            color: var(--text-primary);
            font-size: 0.9em;
        }
        
        .search-box {
            flex: 1;
            min-width: 250px;
        }
        
        .search-box input {
            width: 100%;
            padding: 14px 20px;
            border: 1px solid var(--border-color);
            border-radius: 25px;
            font-size: 0.9em;
            background: var(--bg-secondary);
            color: var(--text-primary);
        }
        
        .search-box input:focus {
            outline: none;
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 3px rgba(0, 212, 255, 0.1);
        }
        
        /* Summary cards */
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 24px;
            margin-bottom: 32px;
        }
        
        .card {
            background: var(--bg-secondary);
            padding: 28px;
            border-radius: 16px;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 20px;
        }
        
        .card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.4);
            border-color: var(--accent-primary);
        }
        
        .card-icon {
            font-size: 2.5em;
            opacity: 0.8;
            flex-shrink: 0;
        }
        
        .card-content {
            flex: 1;
        }
        
        .card h3 {
            color: var(--text-secondary);
            margin-bottom: 8px;
            font-size: 1em;
            font-weight: 500;
        }
        
        .card .number {
            font-size: 2.4em;
            font-weight: 700;
            color: var(--text-primary);
            line-height: 1;
        }
        
        /* Vulnerabilities */
        .vulnerability {
            border-left: 4px solid var(--accent-primary);
            padding: 24px;
            margin: 24px 0;
            background: var(--bg-tertiary);
            border-radius: 0 12px 12px 0;
            border: 1px solid var(--border-color);
        }
        
        .vulnerability-header {
            display: flex;
            align-items: center;
            margin-bottom: 16px;
        }
        
        .severity-badge {
            padding: 8px 16px;
            border-radius: 20px;
            color: white;
            font-weight: 700;
            margin-right: 16px;
            font-size: 0.9em;
        }
        
        .severity-high { background-color: var(--danger); }
        .severity-medium { background-color: var(--warning); color: var(--bg-primary); }
        .severity-low { background-color: var(--success); }
        
        .vulnerability h3 {
            color: var(--text-primary);
            margin-bottom: 12px;
            font-size: 1.3em;
        }
        
        .vulnerability-section {
            margin: 16px 0;
        }
        
        .vulnerability-section h4 {
            color: var(--accent-primary);
            margin-bottom: 8px;
            font-size: 1.1em;
        }
        
        /* Findings */
        .category {
            margin: 32px 0;
            padding: 24px;
            border: 1px solid var(--border-color);
            border-radius: 12px;
            background: var(--bg-secondary);
        }
        
        .category-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 2px solid var(--accent-primary);
        }
        
        .category h3 {
            color: var(--accent-primary);
            font-size: 1.5em;
            font-weight: 700;
        }
        
        .count-badge {
            background: var(--accent-primary);
            color: var(--bg-primary);
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: 700;
            font-size: 0.9em;
        }
        
        .finding {
            background: var(--bg-tertiary);
            padding: 20px;
            margin: 16px 0;
            border-radius: 8px;
            border-left: 4px solid var(--accent-primary);
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            border: 1px solid var(--border-color);
        }
        
        .finding-file {
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 12px;
            font-size: 1.1em;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .finding-match {
            background: var(--bg-primary);
            padding: 16px;
            border-radius: 8px;
            font-family: 'JetBrains Mono', 'Courier New', monospace;
            margin: 12px 0;
            word-break: break-all;
            border: 1px solid var(--border-color);
            font-size: 0.9em;
            color: var(--text-secondary);
        }
        
        .finding-context {
            color: var(--text-secondary);
            font-size: 0.9em;
            background: var(--bg-primary);
            padding: 16px;
            border-radius: 8px;
            margin-top: 12px;
            word-break: break-word;
            white-space: pre-wrap;
            max-height: 300px;
            overflow-y: auto;
            border-left: 3px solid var(--accent-primary);
            border: 1px solid var(--border-color);
        }
        
        .finding-context pre {
            margin: 0;
            padding: 0;
            background: transparent;
            border: none;
            font-family: inherit;
            white-space: pre-wrap;
            word-break: break-word;
        }
        
        .context-preview {
            background: var(--bg-secondary);
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 12px;
            font-family: 'JetBrains Mono', 'Courier New', monospace;
            font-size: 0.85em;
            line-height: 1.4;
            white-space: pre-wrap;
            color: var(--text-secondary);
            max-height: 200px;
            overflow: hidden;
            position: relative;
        }
        
        .context-preview::after {
            content: '...';
            position: absolute;
            bottom: 0;
            right: 0;
            background: var(--bg-secondary);
            padding: 0 8px;
            color: var(--text-muted);
        }
        
        .context-toggle {
            background: var(--accent-primary);
            color: var(--bg-primary);
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85em;
            font-weight: 600;
            margin-top: 8px;
            transition: all 0.3s ease;
        }
        
        .context-toggle:hover {
            background: var(--accent-secondary);
            transform: translateY(-1px);
        }
        
        .context-full {
            display: block;
        }
        
        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            margin: 24px 0;
            gap: 12px;
        }
        
        .pagination button {
            background: var(--accent-primary);
            color: var(--bg-primary);
            border: none;
            padding: 12px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .pagination button:hover {
            background: var(--accent-secondary);
            transform: translateY(-2px);
        }
        
        .pagination button:disabled {
            background: var(--text-muted);
            cursor: not-allowed;
            transform: none;
        }
        
        .pagination .current {
            background: var(--accent-secondary);
            font-weight: 700;
        }
        
        .footer {
            text-align: center;
            padding: 32px;
            color: var(--text-muted);
            border-top: 1px solid var(--border-color);
            margin-top: 32px;
        }
        
        .no-findings {
            text-align: center;
            padding: 60px;
            color: var(--success);
            font-size: 1.3em;
        }
        
        /* Responsive design */
        @media (max-width: 768px) {
            .sidebar {
                width: 100%;
                transform: translateX(-100%);
            }
            
            .sidebar:not(.collapsed) {
                transform: translateX(0);
            }
            
            .sidebar-close {
                display: flex;
            }
            
            .sidebar-toggle {
                display: block;
            }
            
            .main-content {
                margin-left: 0;
                padding-top: 4rem;
            }
            
            .nav-badge {
                font-size: 0.6rem;
                padding: 0.1rem 0.3rem;
                min-width: 16px;
            }
            
            .pattern-context pre {
                font-size: 0.75rem;
                padding: 0.75rem;
            }
        }
        
        @media (max-width: 480px) {
            .nav-badge {
                font-size: 0.5rem;
                padding: 0.1rem 0.2rem;
                min-width: 14px;
            }
            
            .nav-item {
                padding: 0.75rem 1rem;
                font-size: 0.9rem;
            }
        }
        
        @media (min-width: 769px) and (max-width: 1024px) {
            .sidebar {
                width: 280px;
            }
            
            .main-content {
                margin-left: 280px;
            }
            
            .nav-badge {
                font-size: 0.65rem;
                padding: 0.15rem 0.4rem;
            }
        }
        
        /* Ensure sidebar is visible by default on larger screens, but still collapsible */
        @media (min-width: 769px) {
            .sidebar:not(.collapsed) {
                transform: translateX(0) !important;
            }
        }
        
        @media (max-width: 768px) {
            .top-bar {
                padding: 16px 20px;
            }
            
            .filter-bar {
                flex-direction: column;
                align-items: stretch;
            }
            
            .filter-group {
                justify-content: space-between;
            }
            
            .section-stats {
                flex-direction: column;
                gap: 12px;
            }
            
            .summary-cards {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
        <!-- Sidebar -->
    <div class="sidebar" id="sidebar">
        <button class="sidebar-close" id="sidebarClose" onclick="toggleSidebar()">×</button>
        <div class="sidebar-header">
            <h1>📱 APK Analysis</h1>
            <p>Security Report</p>
        </div>
        
        <nav class="sidebar-nav">
            <div class="nav-section">
                <h3>Overview</h3>
                <a href="#summary" class="nav-item active">
                    📊 Summary
                    <span class="nav-badge info">{{.TotalFindings}}</span>
                </a>
                <a href="#vulnerabilities" class="nav-item">
                    🛡️ Vulnerabilities
                    <span class="nav-badge danger">{{.Summary.Vulnerabilities}}</span>
                </a>
                <a href="#patterns" class="nav-item">
                    🔍 Pattern Matches
                    <span class="nav-badge info">{{.TotalFindings}}</span>
                </a>
            </div>
            
            <div class="nav-section">
                <h3>Categories</h3>
                {{range .Categories}}
                {{if gt .Count 0}}
                <a href="#{{.Name}}" class="nav-item">
                    {{.Name}}
                    <span class="nav-badge info">{{.Count}}</span>
                </a>
                {{end}}
                {{end}}
            </div>
        </nav>
    </div>
    
    <!-- Main Content -->
    <div class="main-content" id="mainContent">
        <button class="sidebar-toggle" id="sidebarToggle" onclick="toggleSidebar()">☰ Menu</button>
        <div class="header">
            <h1>APK Security Analysis Report</h1>
            <div class="header-info">
                <div class="info-item">
                    <h3>APK Name</h3>
                    <p>{{.APKName}}</p>
                </div>
                {{if .PackageName}}
                <div class="info-item">
                    <h3>Package</h3>
                    <p>{{.PackageName}}</p>
                </div>
                {{end}}
                {{if .Version}}
                <div class="info-item">
                    <h3>Version</h3>
                    <p>{{.Version}}</p>
                </div>
                {{end}}
                {{if .MinSdkVersion}}
                <div class="info-item">
                    <h3>Min SDK</h3>
                    <p>{{.MinSdkVersion}}</p>
                </div>
                {{end}}
                <div class="info-item">
                    <h3>Analysis Time</h3>
                    <p>{{.ScanTime}}</p>
                </div>
            </div>
        </div>
        
        <div id="summary" class="stats-grid">
            <div class="stat-card danger">
                <div class="stat-number danger">{{.Summary.HighRisk}}</div>
                <div class="stat-label">High Risk</div>
            </div>
            <div class="stat-card warning">
                <div class="stat-number warning">{{.Summary.Vulnerabilities}}</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
            <div class="stat-card success">
                <div class="stat-number success">{{.Summary.TotalFiles}}</div>
                <div class="stat-label">Files Analyzed</div>
            </div>
            <div class="stat-card info">
                <div class="stat-number info">{{.TotalFindings}}</div>
                <div class="stat-label">Total Findings</div>
            </div>
        </div>
            
        <div id="vulnerabilities" class="section">
            <div class="section-header">
                <h2>🛡️ Security Vulnerabilities</h2>
            </div>
            <div class="section-content">
                {{if .Vulnerabilities}}
                    {{range .Vulnerabilities}}
                    <div class="vulnerability {{.Severity}}">
                        <div class="vuln-header">
                            <div class="vuln-title">{{.Type}}</div>
                            <div class="vuln-severity {{.Severity}}">{{.Severity}}</div>
                        </div>
                        <div class="vuln-description">{{.Description}}</div>
                        {{if .Details}}
                        <div class="vuln-context">{{.Details}}</div>
                        {{end}}
                    </div>
                    {{end}}
                {{else}}
                <div class="empty-state">
                    <h3>[ + ]No Vulnerabilities Found</h3>
                    <p>No security vulnerabilities were detected in this APK.</p>
                </div>
                {{end}}
            </div>
        </div>
            
        <div id="patterns" class="section">
            <div class="section-header">
                <h2>🔍 Pattern Matches</h2>
            </div>
            <div class="section-content">
                {{if .Categories}}
                    {{$hasFindings := false}}
                    {{range $category, $data := .Categories}}
                    {{if gt $data.Count 0}}
                    {{$hasFindings = true}}
                    <div class="pattern-category" id="{{$data.Name}}">
                        <h3>{{$data.Name}}</h3>
                        {{range $index, $finding := $data.Findings}}
                        <div class="pattern-item">
                            <div class="pattern-header">
                                <strong>File: {{.File | stripAnsi}}</strong>
                            </div>
                            <div class="pattern-context">
                                <pre><code>{{.Match | stripAnsi}}</code></pre>
                                {{if .Context}}
                                <div class="pattern-context">
                                    <pre><code>{{.Context | stripAnsi | formatText}}</code></pre>
                                </div>
                                {{end}}
                            </div>
                        </div>
                        {{end}}
                    </div>
                    {{end}}
                    {{end}}
                    {{if not $hasFindings}}
                    <div class="empty-state">
                        <h3>[ + ]No Pattern Matches Found</h3>
                        <p>No sensitive information patterns were detected in this APK.</p>
                    </div>
                    {{end}}
                {{else}}
                <div class="empty-state">
                    <h3>[ + ]No Pattern Matches Found</h3>
                    <p>No sensitive information patterns were detected in this APK.</p>
                </div>
                {{end}}
            </div>
        </div>
            
            <div class="footer">
                <p>Generated by apkX Security Scanner on {{.ScanTime}}</p>
                <p>For more information, visit the apkX documentation</p>
            </div>
        </div>
    </div>
    
    <script>
        // Enhanced navigation with better error handling
        document.addEventListener('DOMContentLoaded', function() {
            // Initialize navigation
            document.querySelectorAll('.nav-item').forEach(item => {
                item.addEventListener('click', function(e) {
                    e.preventDefault();
                    
                    // Remove active class from all items
                    document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
                    
                    // Add active class to clicked item
                    this.classList.add('active');
                    
                    // Get target section ID
                    const targetId = this.getAttribute('href').substring(1);
                    console.log('Attempting to scroll to:', targetId);
                    
                    // Try to find the target element
                    let targetElement = document.getElementById(targetId);
                    
                    // If not found, try to find by class or other methods
                    if (!targetElement) {
                        // For pattern categories, look for the category within patterns section
                        if (targetId !== 'summary' && targetId !== 'vulnerabilities' && targetId !== 'patterns') {
                            targetElement = document.querySelector('#patterns .pattern-category[id="' + targetId + '"]');
                        }
                    }
                    
                    if (targetElement) {
                        console.log('Found target element, scrolling...');
                        targetElement.scrollIntoView({ 
                            behavior: 'smooth',
                            block: 'start',
                            inline: 'nearest'
                        });
                    } else {
                        console.log('Target element not found:', targetId);
                        // Fallback: scroll to top
                        window.scrollTo({ top: 0, behavior: 'smooth' });
                    }
                });
            });
            
            // Add smooth scrolling for better UX
            document.documentElement.style.scrollBehavior = 'smooth';
        });
        
        // Mobile menu toggle
        function toggleSidebar() {
            const sidebar = document.querySelector('.sidebar');
            const mainContent = document.querySelector('.main-content');
            
            sidebar.classList.toggle('collapsed');
            
            // On mobile, also adjust main content
            if (window.innerWidth <= 768) {
                if (sidebar.classList.contains('collapsed')) {
                    mainContent.style.marginLeft = '0';
                } else {
                    mainContent.style.marginLeft = '0';
                }
            }
        }
        
        // Add responsive behavior for badges
        function handleResize() {
            const sidebar = document.querySelector('.sidebar');
            const badges = document.querySelectorAll('.nav-badge');
            
            // Adjust badge size based on sidebar width
            if (sidebar.offsetWidth < 300) {
                badges.forEach(badge => {
                    badge.style.fontSize = '0.6rem';
                    badge.style.padding = '0.1rem 0.3rem';
                });
            } else {
                badges.forEach(badge => {
                    badge.style.fontSize = '0.7rem';
                    badge.style.padding = '0.2rem 0.5rem';
                });
            }
        }
        
        // Handle window resize
        window.addEventListener('resize', handleResize);
        
        // Initialize on load
        window.addEventListener('load', handleResize);
    </script>
</body>
</html>
`
