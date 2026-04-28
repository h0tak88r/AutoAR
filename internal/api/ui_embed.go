package api

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
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

	for _, candidate := range []string{"index.html", "apkauditor/index.html", "ipaauditor/index.html", "adbauditor/index.html"} {
		if stat, statErr := fs.Stat(uiRoot, candidate); statErr == nil && !stat.IsDir() {
			serveEmbeddedFile(c, uiRoot, candidate)
			return
		}
	}

	c.String(http.StatusNotFound, "UI entrypoint not found")
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
