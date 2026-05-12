package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/r2storage"
)

// GetScanResultsDir returns the local directory for a scan's results: <resultsDir>/{scanID}/
// Uses the same base directory as the rest of the app (AUTOAR_RESULTS_DIR or new-results).
func GetScanResultsDir(scanID string) string {
	return filepath.Join(GetResultsDir(), scanID)
}

// toScanR2Key converts a local file path to an R2 object key, preserving directory structure.
// Produces keys like: new-results/<scanID>/<fileName>
// Falls back to stripping leading slash if "new-results/" prefix not found.
func toScanR2Key(localPath string) string {
	if idx := strings.Index(localPath, "new-results/"); idx >= 0 {
		return localPath[idx:]
	}
	return strings.TrimPrefix(localPath, "/")
}

// WriteJSONToScanDir writes structured JSON data to a scan's local results directory,
// uploads to R2 under the correct path (new-results/<scanID>/<fileName>), and indexes
// the artifact in the DB so the dashboard can find it.
func WriteJSONToScanDir(scanID, fileName string, data interface{}) error {
	scanDir := GetScanResultsDir(scanID)
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		return fmt.Errorf("create scan dir: %w", err)
	}

	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}

	filePath := filepath.Join(scanDir, fileName)
	if err := os.WriteFile(filePath, raw, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	category := "other"
	if strings.Contains(fileName, "vulnerabilities") || strings.Contains(fileName, "vuln") {
		category = "vulnerability"
	} else if strings.Contains(fileName, "subs") || strings.Contains(fileName, "tech") || strings.Contains(fileName, "cname") || strings.Contains(fileName, "url") {
		category = "recon"
	}

	module := ""
	lf := strings.ToLower(fileName)
	if strings.Contains(lf, "katana") {
		module = "katana-crawler"
	} else if strings.Contains(lf, "github-secret") || strings.Contains(lf, "trufflehog") {
		module = "github-scan"
	} else if strings.Contains(lf, "js-endpoint") {
		module = "js-endpoints"
	} else if strings.Contains(lf, "js-secret") || strings.Contains(lf, "js-exposure") {
		module = "js-analysis"
	} else if strings.Contains(lf, "url") {
		module = "url-collection"
	} else if strings.Contains(lf, "subdomain") {
		module = "subdomain-enum"
	} else if idx := strings.Index(fileName, "-"); idx > 0 {
		module = fileName[:idx]
	}

	artifact := &db.ScanArtifact{
		ScanID:      strings.TrimSpace(scanID),
		FileName:    fileName,
		LocalPath:   filePath,
		SizeBytes:   int64(len(raw)),
		LineCount:   countNonEmptyLines(raw),
		ContentType: "application/json",
		Category:    category,
		Module:      module,
		CreatedAt:   time.Now().UTC(),
	}

	// Upload to R2 under the correct domain-scoped path
	if r2storage.IsEnabled() {
		artifact.R2Key = toScanR2Key(filePath)
		artifact.PublicURL = r2storage.UploadResultFileAndLog(filePath, artifact.R2Key)
		GetLogger().Infof("[JSON] Uploaded %s → R2:%s", fileName, artifact.R2Key)
	}

	// Index in DB so dashboard /results/summary can find it
	if artifact.ScanID != "" {
		if err := db.AppendScanArtifact(artifact); err != nil {
			GetLogger().Errorf("[JSON] failed to index artifact %s for scan %s: %v", fileName, scanID, err)
		}

		// Increment the scan findings counter so the Recent Scans listing shows a badge.
		// Blocklist approach: skip known recon/pipeline input files; count everything else.
		// This ensures new scanners (dalfox, nuclei, custom tools) work without any code change.
		isNoFindings := strings.Contains(fileName, "no-findings") ||
			strings.Contains(fileName, "no_findings")
		// Recon data files — these are pipeline inputs, not vulnerability findings.
		isReconFile := strings.Contains(fileName, "js-url") ||
			strings.Contains(fileName, "js-urls") ||
			strings.Contains(fileName, "katana-urls") ||
			strings.Contains(fileName, "all-url") ||
			strings.Contains(fileName, "all-subs") ||
			strings.Contains(fileName, "live-subs") ||
			strings.Contains(fileName, "live-hosts") ||
			strings.Contains(fileName, "livehosts") ||
			strings.Contains(fileName, "subdomains") ||
			strings.Contains(fileName, "enumerated-subs") ||
			strings.Contains(fileName, "tech-detect") ||
			strings.Contains(fileName, "cname-records") ||
			strings.Contains(fileName, "cnames") ||
			strings.Contains(fileName, "httpx") ||
			strings.Contains(fileName, "wayback") ||
			strings.Contains(fileName, "gospider") ||
			strings.Contains(fileName, "interesting-urls") ||
			strings.Contains(fileName, "nuclei-summary") ||
			strings.Contains(fileName, "scan-manifest") ||
			strings.Contains(fileName, "dns-takeover-vulnerabilities") // counted separately via WriteDNSTakeoverJSON
		if !isReconFile && !isNoFindings && len(raw) > 10 {
			// Count items in the JSON to get an accurate finding count.
			findingCount := 0
			var parsed interface{}
			if jsonErr := json.Unmarshal(raw, &parsed); jsonErr == nil {
				switch v := parsed.(type) {
				case []interface{}:
					// Filter out "no findings" sentinel objects
					for _, item := range v {
						if m, ok := item.(map[string]interface{}); ok {
							if f, _ := m["finding"].(string); strings.Contains(strings.ToLower(f), "no finding") {
								continue
							}
						}
						findingCount++
					}
				case map[string]interface{}:
					for _, key := range []string{"findings", "results", "items", "vulnerabilities", "matches"} {
						if arr, ok := v[key].([]interface{}); ok {
							findingCount = len(arr)
							break
						}
					}
				}
			}
			if findingCount > 0 {
				// Use files_uploaded as a cumulative findings counter.
				if rec, dbErr := db.GetScan(artifact.ScanID); dbErr == nil && rec != nil {
					_ = db.UpdateScanStats(artifact.ScanID, rec.FilesUploaded+findingCount, rec.ErrorCount)
				}
			}
		}
	}

	GetLogger().Infof("[JSON] Wrote %s (%d bytes) for scan %s", fileName, len(raw), scanID)
	return nil
}

// WriteTextToScanDir writes raw text/bytes to a scan's local results directory and uploads to R2.
func WriteTextToScanDir(scanID, fileName string, content []byte) error {
	scanDir := GetScanResultsDir(scanID)
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		return fmt.Errorf("create scan dir: %w", err)
	}

	filePath := filepath.Join(scanDir, fileName)
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	artifact := &db.ScanArtifact{
		ScanID:      strings.TrimSpace(scanID),
		FileName:    fileName,
		LocalPath:   filePath,
		SizeBytes:   int64(len(content)),
		LineCount:   countNonEmptyLines(content),
		ContentType: "application/json",
		CreatedAt:   time.Now().UTC(),
	}

	if len(content) > 0 && r2storage.IsEnabled() {
		artifact.R2Key = toScanR2Key(filePath)
		artifact.PublicURL = r2storage.UploadResultFileAndLog(filePath, artifact.R2Key)
		GetLogger().Infof("[JSON] Uploaded %s → R2:%s", fileName, artifact.R2Key)
	}

	if artifact.ScanID != "" {
		if err := db.AppendScanArtifact(artifact); err != nil {
			GetLogger().Errorf("[JSON] failed to index artifact %s for scan %s: %v", fileName, scanID, err)
		}
	}

	GetLogger().Infof("[JSON] Wrote %s (%d bytes) for scan %s", fileName, len(content), scanID)
	return nil
}

// LinesToJSON converts a slice of text lines into a JSON scan result payload.
// The output structure: {scan_id, target, scan_type, generated, items: [...], count}
func LinesToJSON(scanID, target, scanType string, lines []string) map[string]interface{} {
	items := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			items = append(items, l)
		}
	}
	return map[string]interface{}{
		"scan_id":   scanID,
		"target":    target,
		"scan_type": scanType,
		"generated": time.Now().UTC().Format(time.RFC3339),
		"items":     items,
		"count":     len(items),
	}
}

// WriteLinesAsJSON is a convenience: wraps lines in JSON and writes to the scan dir.
func WriteLinesAsJSON(scanID, target, scanType, fileName string, lines []string) error {
	payload := LinesToJSON(scanID, target, scanType, lines)
	return WriteJSONToScanDir(scanID, fileName, payload)
}

// WriteNoFindingsJSON writes a JSON artifact indicating that the module ran successfully but found no vulnerabilities.
// This prevents raw text summary files from being parsed as false positive findings in the UI.
func WriteNoFindingsJSON(scanID, target, scanType, fileName string) error {
	payload := []map[string]interface{}{
		{
			"target":   nil,
			"finding":  "No findings found",
			"severity": "info",
			"type":     scanType,
		},
	}
	GetLogger().Infof("[JSON] Writing 'No findings' result for %s (scan %s)", scanType, scanID)
	return WriteJSONToScanDir(scanID, fileName, payload)
}

// dnsTakeoverFinding is one structured finding from the DNS takeover module.
type dnsTakeoverFinding struct {
	Target     string `json:"target"`           // IP or subdomain
	Type       string `json:"type"`             // "dangling-ip", "azure-takeover", "aws-takeover", "ns-takeover", "cloudflare-tunnel"
	Status     string `json:"status,omitempty"` // "inactive", "NXDOMAIN", etc.
	Details    string `json:"details"`          // original raw line
	Subdomains int    `json:"subdomains,omitempty"`
}

// parseDNSTakeoverLine parses bracket-format lines from the DNS module into a structured finding.
//
// Supported formats:
//   [CANDIDATE] [IP:104.26.7.206] [STATUS:inactive] [SUBDOMAINS:3] [EXAMPLES:...]
//   [VULNERABLE] [SUBDOMAIN:sub.example.com] [CNAME:x.cloudapp.net] [SERVICE:Azure] [STATUS:NXDOMAIN]
//   [VULNERABLE] [SUBDOMAIN:sub.example.com] [NS:ns1.example.com] [PROVIDER:DigitalOcean]
func parseDNSTakeoverLine(line string) *dnsTakeoverFinding {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	// Extract all [KEY:VALUE] or [KEYWORD] bracket groups
	fields := map[string]string{}
	var keywords []string
	rest := line
	for {
		start := strings.Index(rest, "[")
		if start < 0 {
			break
		}
		end := strings.Index(rest[start:], "]")
		if end < 0 {
			break
		}
		content := rest[start+1 : start+end]
		rest = rest[start+end+1:]
		if idx := strings.Index(content, ":"); idx >= 0 {
			k := strings.ToUpper(strings.TrimSpace(content[:idx]))
			v := strings.TrimSpace(content[idx+1:])
			fields[k] = v
		} else {
			keywords = append(keywords, strings.ToUpper(strings.TrimSpace(content)))
		}
	}

	if len(keywords) == 0 && len(fields) == 0 {
		return nil
	}

	f := &dnsTakeoverFinding{Details: line}

	// Determine the primary keyword: CANDIDATE or VULNERABLE
	keyword := ""
	if len(keywords) > 0 {
		keyword = keywords[0]
	}

	// Determine type
	switch {
	case fields["SERVICE"] == "Azure":
		f.Type = "azure-takeover"
	case fields["SERVICE"] == "AWS":
		f.Type = "aws-takeover"
	case fields["NS"] != "":
		f.Type = "ns-takeover"
	case fields["IP"] != "" && keyword == "CANDIDATE":
		f.Type = "dangling-ip"
	case keyword == "VULNERABLE":
		f.Type = "dns-takeover"
	default:
		f.Type = "dns-candidate"
	}

	// Extract primary target
	switch {
	case fields["IP"] != "":
		f.Target = fields["IP"]
	case fields["SUBDOMAIN"] != "":
		f.Target = fields["SUBDOMAIN"]
	case fields["HOST"] != "":
		f.Target = fields["HOST"]
	default:
		// Bare line that doesn't match — use the line itself
		f.Target = line
	}

	f.Status = fields["STATUS"]

	// Parse subdomains count
	if s := fields["SUBDOMAINS"]; s != "" {
		n := 0
		for _, c := range s {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			}
		}
		f.Subdomains = n
	}

	return f
}

// WriteDNSTakeoverJSON parses raw bracket-format DNS finding lines into structured JSON
// and writes it to the scan results directory. This replaces WriteLinesAsJSON for DNS
// findings so the dashboard parser gets proper target/type fields instead of raw strings.
func WriteDNSTakeoverJSON(scanID, domain string, lines []string) error {
	findings := make([]dnsTakeoverFinding, 0, len(lines))
	seen := map[string]struct{}{}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if _, dup := seen[l]; dup {
			continue
		}
		seen[l] = struct{}{}
		if f := parseDNSTakeoverLine(l); f != nil {
			findings = append(findings, *f)
		}
	}
	if len(findings) == 0 {
		return nil
	}
	payload := map[string]interface{}{
		"scan_id":   scanID,
		"target":    domain,
		"scan_type": "dns-takeover",
		"generated": time.Now().UTC().Format(time.RFC3339),
		"findings":  findings,
		"count":     len(findings),
	}
	return WriteJSONToScanDir(scanID, "dns-takeover-vulnerabilities.json", payload)
}
