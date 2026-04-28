package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/db"
)

// GET /api/keyhacks - List all keyhack templates
func apiListKeyhacks(c *gin.Context) {
	_ = db.Init()
	templates, err := db.ListKeyhackTemplates()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, templates)
}

// GET /api/keyhacks/search?q=query - Search keyhack templates
func apiSearchKeyhacks(c *gin.Context) {
	_ = db.Init()
	query := strings.TrimSpace(c.Query("q"))
	if query == "" {
		templates, err := db.ListKeyhackTemplates()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, templates)
		return
	}

	templates, err := db.SearchKeyhackTemplates(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, templates)
}
