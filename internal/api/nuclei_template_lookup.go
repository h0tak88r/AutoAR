package api

// Resolve the nuclei template a finding matched, so the validation agent can
// reproduce the exact request + matcher instead of guessing from the matched
// URL. A nuclei "hit" only means the matcher words were present; the agent has
// to replay the template's request and confirm every condition against the
// live response. Reads are confined to the bundled template tree and (only via
// the path the scan itself recorded) the results dir.

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

const templateYAMLMax = 4000

var tplIDLineRE = regexp.MustCompile(`(?mi)^\s*id:\s*["']?([A-Za-z0-9._-]+)`)

// nucleiTemplateForFinding returns (source label, YAML) of the template the
// finding matched, or ("","") when it isn't a resolvable template hit.
func nucleiTemplateForFinding(f *db.Finding) (label, yaml string) {
	if f == nil || strings.TrimSpace(f.TemplateID) == "" {
		return "", ""
	}
	bundled := filepath.Join(utils.GetRootDir(), "nuclei_templates")

	// 1. The exact template path the scan recorded (sweeps store template=<path>,
	// a single file or a staged dir). Only honoured if it sits under a root we
	// allow, so a crafted command can't read arbitrary files.
	if f.ScanID != "" {
		if rec, err := db.GetScan(f.ScanID); err == nil && rec != nil {
			if p := commandTemplate(rec.Command); p != "" && withinAny(p, bundled, utils.GetResultsDir()) {
				if y := templateFromPath(p, f.TemplateID); y != "" {
					return "scan " + f.ScanID, y
				}
			}
		}
	}

	// 2. The bundled template tree, by id (then CVE filename).
	if y, p := templateByID(bundled, f.TemplateID, f.CVE); y != "" {
		return filepath.Base(p), y
	}
	return "", ""
}

// templateFromPath reads a single template file, or walks a dir for the one
// whose id matches.
func templateFromPath(p, id string) string {
	st, err := os.Stat(p)
	if err != nil {
		return ""
	}
	if !st.IsDir() {
		raw, err := os.ReadFile(p)
		if err != nil {
			return ""
		}
		return clipText(string(raw), templateYAMLMax)
	}
	y, _ := templateByID(p, id, "")
	return y
}

// templateByID walks root for a .yaml/.yml whose `id:` equals id; failing that,
// whose filename is <cve>.yaml. Bounded so a large tree can't stall validation.
func templateByID(root, id, cve string) (yaml, path string) {
	id = strings.TrimSpace(id)
	cveFile := ""
	if cve != "" {
		cveFile = strings.ToLower(strings.TrimSpace(cve)) + ".yaml"
	}
	var cveYAML, cvePath string
	seen := 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}
		if seen++; seen > 20000 {
			return fs.SkipAll
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		if id != "" {
			if m := tplIDLineRE.FindSubmatch(raw); m != nil && strings.EqualFold(string(m[1]), id) {
				yaml, path = clipText(string(raw), templateYAMLMax), p
				return fs.SkipAll
			}
		}
		if cveYAML == "" && cveFile != "" && name == cveFile {
			cveYAML, cvePath = clipText(string(raw), templateYAMLMax), p
		}
		return nil
	})
	if yaml == "" {
		yaml, path = cveYAML, cvePath
	}
	return yaml, path
}

// withinAny reports whether p resolves inside one of the allowed roots.
func withinAny(p string, roots ...string) bool {
	ap, err := filepath.Abs(p)
	if err != nil {
		return false
	}
	for _, r := range roots {
		ar, err := filepath.Abs(r)
		if err != nil {
			continue
		}
		if rel, err := filepath.Rel(ar, ap); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}
