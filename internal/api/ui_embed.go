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

	relPath := filepath.Join("web", "static", "data", reqPath)
	cleanRelPath := filepath.Clean(relPath)
	// Security: prevent directory traversal
	if !strings.HasPrefix(filepath.ToSlash(cleanRelPath), "web/static/data/") {
		c.String(http.StatusForbidden, "Access denied")
		return
	}

	var resolvedPath string
	for _, base := range candidates {
		candidate := filepath.Join(base, cleanRelPath)
		candidate = filepath.Clean(candidate)
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

// Dashboard Content-Security-Policy. The dashboard renders attacker-controlled
// data (scan results, scope strings, feed titles) and keeps the admin JWT in
// localStorage, so the policy's main job is defence in depth against
// exfiltration: fetch/XHR only to this origin, no third-party images, no
// plugins, no <base> or form-target tricks, framing only by ourselves.
// script-src still needs 'unsafe-inline' for the existing inline handlers.
// All dashboard scripts (incl. marked/DOMPurify) are vendored under /ui, so no
// CDN is allowed.
const (
	cspBase = "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data: blob:; " +
		"worker-src 'self' blob:; " +
		"frame-src 'self'; " +
		"object-src 'none'; " +
		"base-uri 'self'; " +
		"frame-ancestors 'self'; " +
		"form-action 'self'"
	cspSelfStyles  = "style-src 'self' 'unsafe-inline'; font-src 'self' data:"
	cspGoogleFonts = "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com"
	cspConnectSelf = "connect-src 'self'"
	// Security Lab's JS-regex scanner and dependency checker fetch URLs the
	// user pastes (target JS bundles, raw.githubusercontent.com manifests…), so
	// its documents may connect to any http(s) origin.
	cspConnectAny = "connect-src 'self' https: http:"
	// The APK/IPA auditors parse attacker-supplied archives client-side and need
	// no dashboard auth, so their pages are always sandboxed into an opaque
	// origin (no allow-same-origin) — also when opened directly / in a new tab,
	// not only through the dashboard's sandboxed <iframe>.
	cspAuditorSandbox = "sandbox allow-scripts allow-downloads allow-forms allow-popups allow-modals"
)

// dashboardCSP returns the Content-Security-Policy for an embedded UI file.
// The mobile/ADB auditors load Google Fonts; Security Lab needs arbitrary
// fetches; everything else (the SPA itself) gets the strict policy.
func dashboardCSP(filePath string) string {
	top := filePath
	if i := strings.IndexByte(top, '/'); i >= 0 {
		top = top[:i]
	}
	styles, connect, extra := cspSelfStyles, cspConnectSelf, ""
	switch top {
	case "apkauditor", "ipaauditor":
		styles = cspGoogleFonts
		if strings.HasSuffix(filePath, ".html") {
			extra = "; " + cspAuditorSandbox
		}
	case "adbauditor":
		styles = cspGoogleFonts
	case "securitylab":
		connect = cspConnectAny
	}
	return cspBase + "; " + styles + "; " + connect + extra
}

// setDashboardSecurityHeaders applies the browser hardening headers to every
// embedded UI response (pages, scripts, workers, assets).
func setDashboardSecurityHeaders(c *gin.Context, filePath string) {
	h := c.Writer.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("Content-Security-Policy", dashboardCSP(filePath))
}

func serveEmbeddedFile(c *gin.Context, fsys fs.FS, filePath string) {
	data, err := fs.ReadFile(fsys, filePath)
	if err != nil {
		c.String(http.StatusNotFound, "Not found")
		return
	}
	setDashboardSecurityHeaders(c, filePath)
	// UI assets change with every deploy; without an explicit Cache-Control
	// browsers heuristically cache them and a post-deploy refresh can mix a
	// stale stylesheet with fresh markup (half-themed pages). Revalidate
	// always — the files are small and embedded, so this is cheap.
	c.Header("Cache-Control", "no-cache")
	contentType := mime.TypeByExtension(filepath.Ext(filePath))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	c.Data(http.StatusOK, contentType, data)
}
