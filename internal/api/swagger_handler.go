package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/version"
)

func swaggerDocsHandler(c *gin.Context) {
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AutoAR API Docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js" crossorigin></script>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js" crossorigin></script>
  <script>
    window.onload = function () {
      SwaggerUIBundle({
        url: "/api/openapi.json",
        dom_id: "#swagger-ui",
        presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
        layout: "StandaloneLayout",
      });
    };
  </script>
</body>
</html>`))
}

func openapiSpecHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"openapi": "3.0.3",
		"info": gin.H{
			"title":       "AutoAR API",
			"description": "Automated Attack Reconnaissance — scan domains, enumerate subdomains, detect vulnerabilities",
			"version":     version.Version,
		},
		"servers": []gin.H{
			{"url": "/"},
		},
		"security": []gin.H{
			{"bearerAuth": []string{}},
		},
		"components": gin.H{
			"securitySchemes": gin.H{
				"bearerAuth": gin.H{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "JWT",
				},
			},
			"schemas": gin.H{
				"ScanRequest": gin.H{
					"type": "object",
					"properties": gin.H{
						"domain":    gin.H{"type": "string", "description": "Target domain"},
						"subdomain": gin.H{"type": "string", "description": "Target subdomain"},
						"url":       gin.H{"type": "string", "description": "Target URL"},
					},
				},
				"ScanResponse": gin.H{
					"type": "object",
					"properties": gin.H{
						"scan_id": gin.H{"type": "string"},
						"status":  gin.H{"type": "string"},
						"message": gin.H{"type": "string"},
						"command": gin.H{"type": "string"},
					},
				},
			},
		},
		"paths": gin.H{
			"/health": gin.H{
				"get": gin.H{
					"summary":   "Health check",
					"security":  []gin.H{},
					"responses": gin.H{"200": gin.H{"description": "Healthy"}},
				},
			},
			"/api": gin.H{
				"get": gin.H{
					"summary":   "API root",
					"security":  []gin.H{},
					"responses": gin.H{"200": gin.H{"description": "API version and status"}},
				},
			},
			"/api/config": gin.H{
				"get": gin.H{
					"summary":   "Public configuration",
					"security":  []gin.H{},
					"responses": gin.H{"200": gin.H{"description": "Public app config"}},
				},
			},
			"/api/auth/login": gin.H{
				"post": gin.H{
					"summary":  "Local authentication",
					"security": []gin.H{},
					"requestBody": gin.H{
						"content": gin.H{
							"application/json": gin.H{
								"schema": gin.H{
									"type": "object",
									"properties": gin.H{
										"username": gin.H{"type": "string"},
										"password": gin.H{"type": "string"},
									},
								},
							},
						},
					},
					"responses": gin.H{
						"200": gin.H{"description": "JWT token issued"},
						"401": gin.H{"description": "Invalid credentials"},
					},
				},
			},
			"/api/dashboard/stats": gin.H{
				"get": gin.H{
					"summary":   "Dashboard statistics",
					"responses": gin.H{"200": gin.H{"description": "Scan and domain stats"}},
				},
			},
			"/api/domains": gin.H{
				"get": gin.H{
					"summary":   "List domains",
					"responses": gin.H{"200": gin.H{"description": "Domain list"}},
				},
				"post": gin.H{
					"summary": "Add domain",
					"requestBody": gin.H{
						"content": gin.H{
							"application/json": gin.H{
								"schema": gin.H{
									"type":       "object",
									"properties": gin.H{"domain": gin.H{"type": "string"}},
									"required":   []string{"domain"},
								},
							},
						},
					},
					"responses": gin.H{"200": gin.H{"description": "Domain added"}},
				},
			},
			"/api/domains/{domain}": gin.H{
				"delete": gin.H{
					"summary": "Delete domain",
					"parameters": []gin.H{
						{"name": "domain", "in": "path", "required": true, "schema": gin.H{"type": "string"}},
					},
					"responses": gin.H{"200": gin.H{"description": "Domain deleted"}},
				},
			},
			"/api/domains/{domain}/subdomains": gin.H{
				"get": gin.H{
					"summary": "List subdomains for domain",
					"parameters": []gin.H{
						{"name": "domain", "in": "path", "required": true, "schema": gin.H{"type": "string"}},
					},
					"responses": gin.H{"200": gin.H{"description": "Subdomain list"}},
				},
			},
			"/api/subdomains": gin.H{
				"get": gin.H{
					"summary": "All subdomains (paginated)",
					"parameters": []gin.H{
						{"name": "page", "in": "query", "schema": gin.H{"type": "integer"}},
						{"name": "per_page", "in": "query", "schema": gin.H{"type": "integer"}},
					},
					"responses": gin.H{"200": gin.H{"description": "Paginated subdomains"}},
				},
			},
			"/api/scans": gin.H{
				"get": gin.H{
					"summary":   "List all scans",
					"responses": gin.H{"200": gin.H{"description": "Scan list"}},
				},
			},
			"/api/scans/{id}": gin.H{
				"get": gin.H{
					"summary": "Get scan details",
					"parameters": []gin.H{
						{"name": "id", "in": "path", "required": true, "schema": gin.H{"type": "string"}},
					},
					"responses": gin.H{"200": gin.H{"description": "Scan record"}},
				},
			},
			"/api/scans/{id}/results/summary": gin.H{
				"get": gin.H{
					"summary": "Scan results summary",
					"parameters": []gin.H{
						{"name": "id", "in": "path", "required": true, "schema": gin.H{"type": "string"}},
					},
					"responses": gin.H{"200": gin.H{"description": "Results summary"}},
				},
			},
			"/api/scans/{id}/report": gin.H{
				"get": gin.H{
					"summary": "Get scan report",
					"parameters": []gin.H{
						{"name": "id", "in": "path", "required": true, "schema": gin.H{"type": "string"}},
					},
					"responses": gin.H{"200": gin.H{"description": "Scan report"}},
				},
			},
			"/api/system/limits": gin.H{
				"get": gin.H{
					"summary":   "Runtime resource limits",
					"responses": gin.H{"200": gin.H{"description": "Current system limits"}},
				},
			},
			"/scan/domain_run": gin.H{
				"post": gin.H{
					"summary": "Full domain scan",
					"requestBody": gin.H{
						"content": gin.H{
							"application/json": gin.H{
								"schema": gin.H{"$ref": "#/components/schemas/ScanRequest"},
							},
						},
					},
					"responses": gin.H{
						"200": gin.H{
							"description": "Scan started",
							"content":     gin.H{"application/json": gin.H{"schema": gin.H{"$ref": "#/components/schemas/ScanResponse"}}},
						},
					},
				},
			},
			"/scan/subdomains": gin.H{
				"post": gin.H{
					"summary":   "Enumerate subdomains",
					"responses": gin.H{"200": gin.H{"description": "Scan started"}},
				},
			},
			"/scan/livehosts": gin.H{
				"post": gin.H{
					"summary":   "Filter live hosts",
					"responses": gin.H{"200": gin.H{"description": "Scan started"}},
				},
			},
			"/scan/urls": gin.H{
				"post": gin.H{
					"summary":   "Collect URLs and JS endpoints",
					"responses": gin.H{"200": gin.H{"description": "Scan started"}},
				},
			},
			"/scan/js": gin.H{
				"post": gin.H{
					"summary":   "Analyze JavaScript",
					"responses": gin.H{"200": gin.H{"description": "Scan started"}},
				},
			},
			"/scan/nuclei": gin.H{
				"post": gin.H{
					"summary":   "Run Nuclei vulnerability templates",
					"responses": gin.H{"200": gin.H{"description": "Scan started"}},
				},
			},
			"/scan/dns": gin.H{
				"post": gin.H{
					"summary":   "DNS scan (takeover / dangling-IP)",
					"responses": gin.H{"200": gin.H{"description": "Scan started"}},
				},
			},
			"/scan/s3": gin.H{
				"post": gin.H{
					"summary":   "S3 bucket scan",
					"responses": gin.H{"200": gin.H{"description": "Scan started"}},
				},
			},
			"/scan/github": gin.H{
				"post": gin.H{
					"summary":   "GitHub repository scanning",
					"responses": gin.H{"200": gin.H{"description": "Scan started"}},
				},
			},
			"/scan/ports": gin.H{
				"post": gin.H{
					"summary":   "Port scan (Naabu)",
					"responses": gin.H{"200": gin.H{"description": "Scan started"}},
				},
			},
			"/scan/tech": gin.H{
				"post": gin.H{
					"summary":   "Technology fingerprinting",
					"responses": gin.H{"200": gin.H{"description": "Scan started"}},
				},
			},
			"/scan/ffuf": gin.H{
				"post": gin.H{
					"summary":   "Web fuzzing (FFuf)",
					"responses": gin.H{"200": gin.H{"description": "Scan started"}},
				},
			},
			"/scan/misconfig": gin.H{
				"post": gin.H{
					"summary":   "Cloud misconfiguration scan",
					"responses": gin.H{"200": gin.H{"description": "Scan started"}},
				},
			},
			"/scan/zerodays": gin.H{
				"post": gin.H{
					"summary":   "Zero-day vulnerability check (CVE-2025-55182, CVE-2025-14847)",
					"responses": gin.H{"200": gin.H{"description": "Scan started"}},
				},
			},
			"/scan/recon": gin.H{
				"post": gin.H{
					"summary":   "Unified recon (subdomains + livehosts + tech + cnames)",
					"responses": gin.H{"200": gin.H{"description": "Scan started"}},
				},
			},
			"/scan/{scan_id}/status": gin.H{
				"get": gin.H{
					"summary": "Get scan status",
					"parameters": []gin.H{
						{"name": "scan_id", "in": "path", "required": true, "schema": gin.H{"type": "string"}},
					},
					"responses": gin.H{"200": gin.H{"description": "Scan status"}},
				},
			},
			"/scan/{scan_id}/results": gin.H{
				"get": gin.H{
					"summary": "Get scan results",
					"parameters": []gin.H{
						{"name": "scan_id", "in": "path", "required": true, "schema": gin.H{"type": "string"}},
					},
					"responses": gin.H{"200": gin.H{"description": "Scan results"}},
				},
			},
			"/keyhack/search": gin.H{
				"post": gin.H{
					"summary":   "Search API keys",
					"responses": gin.H{"200": gin.H{"description": "KeyHack search results"}},
				},
			},
			"/keyhack/validate": gin.H{
				"post": gin.H{
					"summary":   "Validate API keys",
					"responses": gin.H{"200": gin.H{"description": "Validation results"}},
				},
			},
		},
	})
}
