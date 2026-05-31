package api

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

//go:embed all:ui
var embeddedUI embed.FS

func serveDashboardUI(c *gin.Context) {
	uiRoot, err := fs.Sub(embeddedUI, "ui")
	if err != nil {
		c.String(http.StatusInternalServerError, "UI assets unavailable")
		return
	}

	reqPath := strings.TrimPrefix(c.Param("filepath"), "/")
	if reqPath == "" {
		reqPath = "index.html"
	}

	cleanPath := strings.TrimPrefix(path.Clean("/"+reqPath), "/")
	if cleanPath == "." || cleanPath == "" {
		cleanPath = "index.html"
	}

	// Serve real static files directly; fallback to the first available UI entry page.
	if stat, statErr := fs.Stat(uiRoot, cleanPath); statErr == nil && !stat.IsDir() {
		serveEmbeddedFile(c, uiRoot, cleanPath)
		return
	}
	if stat, statErr := fs.Stat(uiRoot, cleanPath); statErr == nil && stat.IsDir() {
		dirIndex := path.Join(cleanPath, "index.html")
		if idxStat, idxErr := fs.Stat(uiRoot, dirIndex); idxErr == nil && !idxStat.IsDir() {
			serveEmbeddedFile(c, uiRoot, dirIndex)
			return
		}
	}

	for _, candidate := range []string{"index.html", "apkauditor/index.html", "ipaauditor/index.html", "adbauditor/index.html"} {
		if stat, statErr := fs.Stat(uiRoot, candidate); statErr == nil && !stat.IsDir() {
			serveEmbeddedFile(c, uiRoot, candidate)
			return
		}
	}

	c.String(http.StatusNotFound, "UI entrypoint not found")
}

// serveStaticData serves static JSON data files from web/static/data directory
func serveStaticData(c *gin.Context) {
	reqPath := strings.TrimPrefix(c.Param("filepath"), "/")
	if reqPath == "" {
		c.String(http.StatusNotFound, "Not found")
		return
	}

	// Construct the file path relative to project root
	filePath := filepath.Join("web", "static", "data", reqPath)

	// Security: prevent directory traversal
	cleanPath := filepath.Clean(filePath)
	if !strings.HasPrefix(cleanPath, "web/static/data/") {
		c.String(http.StatusForbidden, "Access denied")
		return
	}

	// Check if file exists
	if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
		c.String(http.StatusNotFound, "File not found")
		return
	}

	// Read and serve the file
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error reading file")
		return
	}

	// Set content type based on extension
	contentType := mime.TypeByExtension(filepath.Ext(cleanPath))
	if contentType == "" {
		contentType = "application/json"
	}

	c.Data(http.StatusOK, contentType, data)
}

func serveEmbeddedFile(c *gin.Context, fsys fs.FS, filePath string) {
	data, err := fs.ReadFile(fsys, filePath)
	if err != nil {
		c.String(http.StatusNotFound, "Not found")
		return
	}
	contentType := mime.TypeByExtension(filepath.Ext(filePath))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	c.Data(http.StatusOK, contentType, data)
}
