package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/db"
)

// reportTemplatesDir returns the directory for storing report template files.
// Override with AUTOAR_TEMPLATES_DIR env var to persist across container restarts.
func reportTemplatesDir() string {
	if d := os.Getenv("AUTOAR_TEMPLATES_DIR"); d != "" {
		return d
	}
	return "report_templates"
}

var reportTemplatesMigrateOnce sync.Once

func defaultReportTemplateContent() string {
	return "# Security Assessment Report\n\n## Executive Summary\nThis report summarizes the findings of the security assessment conducted on {{domain}}.\n\n## Findings\n{{findings}}\n"
}

func normalizeTemplateName(raw string) string {
	name := strings.TrimSpace(raw)
	name = strings.TrimSuffix(name, ".md")
	name = filepath.Base(name)
	if name == "." || name == "/" || name == "" {
		return ""
	}
	return name
}

func ensureReportTemplatesMigrated() {
	reportTemplatesMigrateOnce.Do(func() {
		if err := db.Init(); err != nil {
			log.Printf("[report-templates] db init failed: %v", err)
			return
		}
		if err := db.EnsureSchema(); err != nil {
			log.Printf("[report-templates] db schema ensure failed: %v", err)
			return
		}

		templates, err := db.ListReportTemplates()
		if err != nil {
			log.Printf("[report-templates] list existing templates failed: %v", err)
			return
		}
		if len(templates) > 0 {
			return
		}

		// Migrate legacy local templates if present.
		if entries, err := os.ReadDir(reportTemplatesDir()); err == nil {
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".md") {
					continue
				}
				name := normalizeTemplateName(e.Name())
				if name == "" {
					continue
				}
				path := filepath.Join(reportTemplatesDir(), e.Name())
				content, readErr := os.ReadFile(path)
				if readErr != nil {
					log.Printf("[report-templates] failed reading legacy template %s: %v", path, readErr)
					continue
				}
				if upErr := db.UpsertReportTemplate(name, string(content)); upErr != nil {
					log.Printf("[report-templates] failed migrating template %s: %v", name, upErr)
				}
			}
		}

		templates, _ = db.ListReportTemplates()
		if len(templates) == 0 {
			_ = db.UpsertReportTemplate("default", defaultReportTemplateContent())
		}
	})
}

func apiListReportTemplates(c *gin.Context) {
	ensureReportTemplatesMigrated()
	templates, err := db.ListReportTemplates()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list templates"})
		return
	}

	names := make([]string, 0, len(templates))
	for _, t := range templates {
		if t.Name != "" {
			names = append(names, t.Name)
		}
	}
	sort.Strings(names)
	c.JSON(http.StatusOK, names)
}

func apiGetReportTemplate(c *gin.Context) {
	ensureReportTemplatesMigrated()
	name := normalizeTemplateName(c.Param("name"))
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Template name is required"})
		return
	}

	template, err := db.GetReportTemplate(name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Template not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"name":    template.Name,
		"content": template.Content,
	})
}

func apiSaveReportTemplate(c *gin.Context) {
	ensureReportTemplatesMigrated()
	var req struct {
		Name    string `json:"name" binding:"required"`
		Content string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	name := normalizeTemplateName(req.Name)
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Template name is invalid"})
		return
	}
	if err := db.UpsertReportTemplate(name, req.Content); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save template"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "name": name})
}

func apiDeleteReportTemplate(c *gin.Context) {
	ensureReportTemplatesMigrated()
	name := normalizeTemplateName(c.Param("name"))
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Template name is required"})
		return
	}

	if err := db.DeleteReportTemplate(name); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Failed to delete template"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type reportTemplateImportItem struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

type reportTemplatesExportPayload struct {
	Version    int                        `json:"version"`
	ExportedAt string                     `json:"exported_at"`
	Templates  []reportTemplateImportItem `json:"templates"`
}

func decodeReportTemplatesPayload(raw []byte) ([]reportTemplateImportItem, error) {
	var payload reportTemplatesExportPayload
	if err := json.Unmarshal(raw, &payload); err == nil && len(payload.Templates) > 0 {
		return payload.Templates, nil
	}

	var wrapped struct {
		Templates []reportTemplateImportItem `json:"templates"`
	}
	if err := json.Unmarshal(raw, &wrapped); err == nil && len(wrapped.Templates) > 0 {
		return wrapped.Templates, nil
	}

	var plain []reportTemplateImportItem
	if err := json.Unmarshal(raw, &plain); err == nil && len(plain) > 0 {
		return plain, nil
	}
	return nil, errors.New("invalid template import format")
}

func apiExportReportTemplates(c *gin.Context) {
	ensureReportTemplatesMigrated()
	templates, err := db.ListReportTemplates()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list templates"})
		return
	}
	sort.Slice(templates, func(i, j int) bool { return templates[i].Name < templates[j].Name })

	out := make([]reportTemplateImportItem, 0, len(templates))
	for _, t := range templates {
		out = append(out, reportTemplateImportItem{Name: t.Name, Content: t.Content})
	}

	payload := reportTemplatesExportPayload{
		Version:    1,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		Templates:  out,
	}
	c.Header("Content-Disposition", `attachment; filename="report-templates-export.json"`)
	c.JSON(http.StatusOK, payload)
}

func apiImportReportTemplates(c *gin.Context) {
	ensureReportTemplatesMigrated()
	overwrite := c.DefaultPostForm("overwrite", "true") != "false"

	var raw []byte
	file, err := c.FormFile("file")
	if err == nil && file != nil {
		fh, openErr := file.Open()
		if openErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to open import file"})
			return
		}
		defer fh.Close()
		raw, err = io.ReadAll(fh)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read import file"})
			return
		}
	} else {
		raw, err = io.ReadAll(c.Request.Body)
		if err != nil || len(strings.TrimSpace(string(raw))) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Import payload is required"})
			return
		}
	}

	items, err := decodeReportTemplatesPayload(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	imported := 0
	skipped := 0
	for _, item := range items {
		name := normalizeTemplateName(item.Name)
		if name == "" || strings.TrimSpace(item.Content) == "" {
			skipped++
			continue
		}
		if !overwrite {
			if _, getErr := db.GetReportTemplate(name); getErr == nil {
				skipped++
				continue
			}
		}
		if upErr := db.UpsertReportTemplate(name, item.Content); upErr != nil {
			skipped++
			continue
		}
		imported++
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"imported": imported,
		"skipped":  skipped,
	})
}
