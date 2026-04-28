package api

import (
	"crypto/md5"
	"embed"
	"fmt"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
)

//go:embed ui/index.html ui/styles.css ui/app.js ui/logo.png ui/apkauditor ui/ipaauditor ui/adbauditor ui/securitylab
var uiFiles embed.FS

// serveDashboardUI serves the embedded SPA.
// It reads files directly from the embed.FS — no http.FileServer to avoid
// redirect loops that the FileServer introduces for directory paths.
func serveDashboardUI(c *gin.Context) {
	// filepath param is "" when matched by r.GET("/ui", ...) and "/<rest>" for r.GET("/ui/*filepath", ...)
	filePath := strings.TrimPrefix(c.Param("filepath"), "/")

	if filePath == "" {
		filePath = "index.html"
	} else if filePath == "apkauditor" || filePath == "apkauditor/" {
		filePath = "apkauditor/index.html"
	} else if filePath == "ipaauditor" || filePath == "ipaauditor/" {
		filePath = "ipaauditor/index.html"
	} else if filePath == "adbauditor" || filePath == "adbauditor/" {
		filePath = "adbauditor/index.html"
	} else if filePath == "securitylab" || filePath == "securitylab/" {
		filePath = "securitylab/index.html"
	}

	// ── APK Auditor auth gate ─────────────────────────────────────────────────
	// The apkauditor HTML page is guarded server-side so direct navigation to
	// /ui/apkauditor/ without a valid session is blocked.  Sub-assets (.js/.css)
	// are served freely — they are inert without the protected HTML wrapper.
	//
	// Same-origin iframe requests (Sec-Fetch-Dest: iframe, Sec-Fetch-Site: same-origin)
	// are explicitly allowed — they come from within the authenticated SPA itself.
	if (strings.HasPrefix(filePath, "apkauditor") || strings.HasPrefix(filePath, "ipaauditor") || strings.HasPrefix(filePath, "adbauditor") || strings.HasPrefix(filePath, "securitylab")) &&
		(strings.HasSuffix(filePath, ".html") || filePath == "apkauditor/index.html" || filePath == "ipaauditor/index.html" || filePath == "adbauditor/index.html" || filePath == "securitylab/index.html") &&
		dashboardAPIAuthEnforced() {

		// Trust same-origin iframe requests — the SPA already gated them.
		isSameOriginIframe := c.GetHeader("Sec-Fetch-Dest") == "iframe" &&
			c.GetHeader("Sec-Fetch-Site") == "same-origin"

		if !isSameOriginIframe {
			// Accept token from Authorization: Bearer … header or autoar_token cookie.
			raw := ""
			if ah := strings.TrimSpace(c.GetHeader("Authorization")); strings.HasPrefix(ah, "Bearer ") {
				raw = strings.TrimSpace(ah[len("Bearer "):])
			}
			if raw == "" {
				raw, _ = c.Cookie("autoar_token")
			}

			if raw == "" || verifyLocalJWT(raw) != nil {
				// Redirect browser to the SPA; the JS auth gate will show login.
				c.Redirect(http.StatusFound, "/ui")
				return
			}
		}
	}
	// ─────────────────────────────────────────────────────────────────────────

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

	// Cache control: JS/CSS must never be served stale — no-store forces a fresh
	// fetch every time. HTML gets an ETag so back-nav is fast but content is fresh.
	switch ext {
	case ".js", ".css":
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		c.Header("Pragma", "no-cache")
	case ".html":
		etag := fmt.Sprintf(`"%x"`, md5.Sum(content))
		c.Header("Cache-Control", "no-cache")
		c.Header("ETag", etag)
		if c.GetHeader("If-None-Match") == etag {
			c.Status(http.StatusNotModified)
			return
		}
	}

	c.Data(http.StatusOK, ct, content)
}
