package honeypot

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CatchAllHandler struct {
	db *pgxpool.Pool
}

func NewCatchAllHandler(db *pgxpool.Pool) *CatchAllHandler {
	return &CatchAllHandler{db: db}
}

func (h *CatchAllHandler) Handle(c *gin.Context) {
	ip := clientIP(c)
	userAgent := c.GetHeader("User-Agent")

	headers, _ := json.Marshal(flattenHeaders(c.Request.Header))
	bodyBytes, _ := io.ReadAll(c.Request.Body)

	_, err := h.db.Exec(context.Background(),
		`INSERT INTO url_probes
			(ip, method, path, query_string, headers, body, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		ip, c.Request.Method, c.Request.URL.Path, c.Request.URL.RawQuery,
		headers, bodyBytes, userAgent,
	)
	if err != nil {
		log.Printf("honeypot/catchall: insert error: %v", err)
	}

	c.HTML(http.StatusNotFound, "404.html", gin.H{
		"Path": c.Request.URL.Path,
	})
}
