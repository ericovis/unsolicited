package honeypot

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type FormHandler struct {
	db *pgxpool.Pool
}

func NewFormHandler(db *pgxpool.Pool) *FormHandler {
	return &FormHandler{db: db}
}

func (h *FormHandler) HandleSubscribe(c *gin.Context) {
	h.captureForm(c, "subscribe")
}

func (h *FormHandler) HandleLogin(c *gin.Context) {
	h.captureForm(c, "login")
}

func (h *FormHandler) HandleRegister(c *gin.Context) {
	h.captureForm(c, "register")
}

func (h *FormHandler) captureForm(c *gin.Context, formName string) {
	ip := clientIP(c)
	userAgent := c.GetHeader("User-Agent")

	headers, _ := json.Marshal(flattenHeaders(c.Request.Header))

	bodyBytes, _ := io.ReadAll(c.Request.Body)
	body := parseBody(c.ContentType(), bodyBytes)

	_, err := h.db.Exec(context.Background(),
		`INSERT INTO form_submissions
			(form_name, ip, user_agent, headers, body)
		VALUES ($1, $2, $3, $4, $5)`,
		formName, ip, userAgent, headers, body,
	)
	if err != nil {
		log.Printf("honeypot/forms: insert error: %v", err)
	}

	// Return a plausible success page to keep bots engaged
	c.HTML(http.StatusOK, "success.html", gin.H{
		"FormName": formName,
	})
}

// clientIP extracts the real client IP, respecting X-Forwarded-For.
func clientIP(c *gin.Context) string {
	ip := c.ClientIP()
	// Strip port if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		candidate := ip[:idx]
		if strings.Count(ip, ":") == 1 { // IPv4:port
			ip = candidate
		}
	}
	return ip
}

func flattenHeaders(h http.Header) map[string]string {
	flat := make(map[string]string, len(h))
	for k, v := range h {
		flat[k] = strings.Join(v, ", ")
	}
	return flat
}

func parseBody(contentType string, raw []byte) json.RawMessage {
	if strings.Contains(contentType, "application/json") {
		if json.Valid(raw) {
			return raw
		}
	}
	// For form-encoded or anything else, store as a JSON string
	b, _ := json.Marshal(string(raw))
	return b
}
