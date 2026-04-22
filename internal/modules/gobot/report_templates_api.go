package gobot

import (
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

const reportTemplatesDir = "report_templates"

func init() {
	// Ensure templates directory exists
	if _, err := os.Stat(reportTemplatesDir); os.IsNotExist(err) {
		_ = os.MkdirAll(reportTemplatesDir, 0755)
		// Add a sample template
		sample := "# Security Assessment Report\n\n## Executive Summary\nThis report summarizes the findings of the security assessment conducted on {{domain}}.\n\n## Findings\n{{findings}}\n"
		_ = ioutil.WriteFile(filepath.Join(reportTemplatesDir, "default.md"), []byte(sample), 0644)
	}
}

func apiListReportTemplates(c *gin.Context) {
	files, err := ioutil.ReadDir(reportTemplatesDir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read templates directory"})
		return
	}

	var templates []string
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".md") {
			templates = append(templates, strings.TrimSuffix(f.Name(), ".md"))
		}
	}

	c.JSON(http.StatusOK, templates)
}

func apiGetReportTemplate(c *gin.Context) {
	name := c.Param("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Template name is required"})
		return
	}

	// Basic path traversal protection
	name = filepath.Base(name)
	path := filepath.Join(reportTemplatesDir, name+".md")

	content, err := ioutil.ReadFile(path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Template not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"name":    name,
		"content": string(content),
	})
}

func apiSaveReportTemplate(c *gin.Context) {
	var req struct {
		Name    string `json:"name" binding:"required"`
		Content string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Basic path traversal protection
	name := filepath.Base(req.Name)
	if !strings.HasSuffix(name, ".md") {
		name += ".md"
	}
	path := filepath.Join(reportTemplatesDir, name)

	if err := ioutil.WriteFile(path, []byte(req.Content), 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save template"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "name": strings.TrimSuffix(name, ".md")})
}

func apiDeleteReportTemplate(c *gin.Context) {
	name := c.Param("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Template name is required"})
		return
	}

	// Basic path traversal protection
	name = filepath.Base(name)
	path := filepath.Join(reportTemplatesDir, name+".md")

	if err := os.Remove(path); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete template"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
