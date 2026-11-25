package api

// Scan titles and descriptions: set at launch, or edited later from the
// dashboard (PATCH /api/scans/:id) and the MCP run_scan tool.

import (
	"net/http"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"github.com/h0tak88r/AutoAR/internal/db"
)

const (
	scanNameMax = 120
	scanDescMax = 2000
)

// cleanScanText strips control characters (keeping newlines in multi-line
// text), trims, and caps the length in runes.
func cleanScanText(s string, max int, multiline bool) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' && multiline:
			b.WriteRune(r)
		case r == '\t' || r == '\n' || r == '\r':
			b.WriteRune(' ')
		case unicode.IsControl(r):
			// dropped
		default:
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if !multiline {
		out = strings.Join(strings.Fields(out), " ")
	}
	if rs := []rune(out); len(rs) > max {
		out = strings.TrimSpace(string(rs[:max]))
	}
	return out
}

// applyScanMeta saves name/description (nil = unchanged). A scan launched a
// moment ago may not have its DB row yet, so the values are stashed first and
// picked up by the runner at CreateScan; found reports whether the row existed.
func applyScanMeta(scanID string, name, desc *string) (found bool, err error) {
	stashScanMeta(scanID, name, desc)
	found, err = db.UpdateScanMeta(scanID, name, desc)
	if err != nil {
		return false, err
	}
	if found {
		dropScanMeta(scanID)
	}
	return found, nil
}

type scanMetaReq struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

// apiUpdateScanMeta (PATCH /api/scans/:id) renames a scan and/or sets its
// description. An empty string clears the field.
func apiUpdateScanMeta(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" || len(id) > 128 || strings.ContainsAny(id, " /\\") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scan id"})
		return
	}
	var req scanMetaReq
	if err := c.ShouldBindJSON(&req); err != nil || (req.Name == nil && req.Description == nil) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "send name and/or description"})
		return
	}
	if req.Name != nil {
		v := cleanScanText(*req.Name, scanNameMax, false)
		req.Name = &v
	}
	if req.Description != nil {
		v := cleanScanText(*req.Description, scanDescMax, true)
		req.Description = &v
	}
	found, err := applyScanMeta(id, req.Name, req.Description)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	detail := ""
	if req.Name != nil {
		detail = "title: " + *req.Name
	}
	auditActor(currentUsername(c), "scan.edit", id, detail)
	status := "saved"
	if !found {
		status = "pending" // row not written yet; the runner applies it at create
	}
	resp := gin.H{"status": status, "scan_id": id}
	if req.Name != nil {
		resp["name"] = *req.Name
	}
	if req.Description != nil {
		resp["description"] = *req.Description
	}
	c.JSON(http.StatusOK, resp)
}

// nucleiTemplateTitle names a nuclei run after its template when the
// operator gave no name: "Nuclei: <info.name>" for raw YAML, the file/ID
// otherwise. Untitled templates fall back to "" (the UI shows type + target).
func nucleiTemplateTitle(template string) string {
	template = strings.TrimSpace(template)
	if template == "" {
		return ""
	}
	label := ""
	if strings.Contains(template, "\n") || strings.HasPrefix(template, "id:") {
		var t struct {
			ID   string `yaml:"id"`
			Info struct {
				Name string `yaml:"name"`
			} `yaml:"info"`
		}
		if yaml.Unmarshal([]byte(template), &t) == nil {
			label = t.Info.Name
			if label == "" {
				label = t.ID
			}
		}
	} else {
		label = strings.TrimSuffix(strings.TrimSuffix(filepath.Base(template), ".yaml"), ".yml")
	}
	label = cleanScanText(label, scanNameMax-len("Nuclei: "), false)
	if label == "" {
		return ""
	}
	return "Nuclei: " + label
}
