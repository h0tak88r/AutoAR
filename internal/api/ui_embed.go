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

// serveStaticData serves static JSON data files from web/static/data directory.
// It searches multiple base paths so it works regardless of the binary's cwd.
func serveStaticData(c *gin.Context) {
	reqPath := strings.TrimPrefix(c.Param("filepath"), "/")
	if reqPath == "" {
		c.String(http.StatusNotFound, "Not found")
		return
	}

	// Candidate base directories to search for web/static/data
	var candidates []string
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, cwd)
	}
	if exePath, err := os.Executable(); err == nil {
		if exeDir := filepath.Dir(exePath); exeDir != "." {
			candidates = append(candidates, exeDir)
			// Handle macOS app bundles: binary is inside AutoAR.app/Contents/MacOS/
			if strings.Contains(exeDir, ".app/Contents/MacOS") {
				candidates = append(candidates, filepath.Join(exeDir, "..", "..", ".."))
			}
		}
	}

	var resolvedPath string
	for _, base := range candidates {
		candidate := filepath.Join(base, "web", "static", "data", reqPath)
		candidate = filepath.Clean(candidate)
		// Security: prevent directory traversal
		if !strings.HasPrefix(filepath.ToSlash(candidate)+"/", "web/static/data/") {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			resolvedPath = candidate
			break
		}
	}

	if resolvedPath == "" {
		c.String(http.StatusNotFound, "File not found")
		return
	}

	data, err := os.ReadFile(resolvedPath)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error reading file")
		return
	}

	contentType := mime.TypeByExtension(filepath.Ext(resolvedPath))
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
