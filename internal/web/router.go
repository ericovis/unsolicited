package web

import (
	"html/template"
	"net/http"

	"github.com/ericovis/unsolicited/internal/honeypot"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/render"
	"github.com/jackc/pgx/v5/pgxpool"
)

// templateRenderer creates separate template sets per page so that
// each page's {{ define "content" }} does not collide with others.
type templateRenderer struct {
	templates map[string]*template.Template
}

func (t *templateRenderer) Instance(name string, data any) render.Render {
	return &render.HTML{
		Template: t.templates[name],
		Name:     "layout",
		Data:     data,
	}
}

func loadTemplates() *templateRenderer {
	r := &templateRenderer{templates: make(map[string]*template.Template)}
	pages := []string{
		"index.html", "stats.html", "category.html",
		"events.html", "success.html", "404.html",
	}
	for _, page := range pages {
		r.templates[page] = template.Must(
			template.ParseFiles("templates/layout.html", "templates/"+page),
		)
	}
	return r
}

func NewRouter(db *pgxpool.Pool) *gin.Engine {
	r := gin.Default()

	r.HTMLRender = loadTemplates()
	r.Static("/static", "./static")

	r.GET("/favicon.ico", func(c *gin.Context) {
		c.File("./static/favicon.svg")
	})

	r.GET("/robots.txt", func(c *gin.Context) {
		c.String(http.StatusOK, "User-agent: *\nDisallow: /\n")
	})

	// Page handlers
	pages := NewPageHandler(db)
	r.GET("/", pages.Index)
	r.GET("/stats", pages.Stats)
	r.GET("/stats/category/:id", pages.Category)

	// Honeypot form endpoints
	forms := honeypot.NewFormHandler(db)
	r.POST("/subscribe", forms.HandleSubscribe)
	r.POST("/login", forms.HandleLogin)
	r.POST("/register", forms.HandleRegister)

	// Stats API (JSON)
	stats := NewStatsAPI(db)
	api := r.Group("/api/stats")
	{
		api.GET("/overview", stats.Overview)
		api.GET("/timeseries", stats.Timeseries)
		api.GET("/categories", stats.Categories)
		api.GET("/events", stats.Events)
		api.GET("/events/:id", stats.EventDetail)
	}

	// Catch-all for URL probing (must be last)
	catchAll := honeypot.NewCatchAllHandler(db)
	r.NoRoute(func(c *gin.Context) {
		// Skip static assets to avoid noise
		if len(c.Request.URL.Path) > 1 {
			catchAll.Handle(c)
			return
		}
		c.HTML(http.StatusNotFound, "404.html", gin.H{"Path": c.Request.URL.Path})
	})

	return r
}
