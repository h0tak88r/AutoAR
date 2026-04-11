package gobot

import (
	"embed"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
)

//go:embed ui/index.html ui/styles.css ui/app.js
var uiFiles embed.FS

// serveDashboardUI serves the embedded SPA.
// It reads files directly from the embed.FS — no http.FileServer to avoid
// redirect loops that the FileServer introduces for directory paths.
func serveDashboardUI(c *gin.Context) {
	// filepath param is "" when matched by r.GET("/ui", ...) and "/<rest>" for r.GET("/ui/*filepath", ...)
	filePath := strings.TrimPrefix(c.Param("filepath"), "/")

	if filePath == "" {
		filePath = "index.html"
	}

	// Try to read the requested file from the embedded FS
	content, err := uiFiles.ReadFile("ui/" + filePath)
	if err != nil {
		// SPA fallback — unknown paths return index.html (client-side routing)
		content, err = uiFiles.ReadFile("ui/index.html")
		if err != nil {
			c.String(http.StatusNotFound, "AutoAR UI not found")
			return
		}
		filePath = "index.html"
	}

	// Determine MIME type from extension; default to text/plain
	ext := strings.ToLower(path.Ext(filePath))
	ct := mime.TypeByExtension(ext)
	if ct == "" {
		switch ext {
		case ".css":
			ct = "text/css; charset=utf-8"
		case ".js":
			ct = "application/javascript; charset=utf-8"
		case ".html":
			ct = "text/html; charset=utf-8"
		default:
			ct = "text/plain; charset=utf-8"
		}
	}

	c.Data(http.StatusOK, ct, content)
}
