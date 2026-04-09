package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PageHandler struct {
	db *pgxpool.Pool
}

func NewPageHandler(db *pgxpool.Pool) *PageHandler {
	return &PageHandler{db: db}
}

func (h *PageHandler) Index(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{})
}

func (h *PageHandler) Stats(c *gin.Context) {
	c.HTML(http.StatusOK, "stats.html", gin.H{})
}

func (h *PageHandler) Category(c *gin.Context) {
	id := c.Param("id")

	var name, description, severity string
	err := h.db.QueryRow(c, `SELECT name, description, severity FROM attack_categories WHERE id = $1`, id).
		Scan(&name, &description, &severity)
	if err != nil {
		c.HTML(http.StatusNotFound, "404.html", gin.H{"Path": c.Request.URL.Path})
		return
	}

	c.HTML(http.StatusOK, "category.html", gin.H{
		"ID":          id,
		"Name":        name,
		"Description": description,
		"Severity":    severity,
	})
}
