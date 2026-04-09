package web

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/ericovis/unsolicited/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type StatsAPI struct {
	db *pgxpool.Pool
}

func NewStatsAPI(db *pgxpool.Pool) *StatsAPI {
	return &StatsAPI{db: db}
}

func (s *StatsAPI) Overview(c *gin.Context) {
	var overview models.StatsOverview

	queries := []struct {
		total, h24, d7 *int64
		table          string
	}{
		{&overview.FormTotal, &overview.Form24h, &overview.Form7d, "form_submissions"},
		{&overview.SSHTotal, &overview.SSH24h, &overview.SSH7d, "ssh_attempts"},
		{&overview.URLTotal, &overview.URL24h, &overview.URL7d, "url_probes"},
	}

	for _, q := range queries {
		s.db.QueryRow(c, fmt.Sprintf("SELECT COUNT(*) FROM %s", q.table)).Scan(q.total)
		s.db.QueryRow(c, fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE created_at > NOW() - INTERVAL '24 hours'", q.table)).Scan(q.h24)
		s.db.QueryRow(c, fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE created_at > NOW() - INTERVAL '7 days'", q.table)).Scan(q.d7)
	}

	c.JSON(http.StatusOK, overview)
}

func (s *StatsAPI) Timeseries(c *gin.Context) {
	rangeParam := c.DefaultQuery("range", "24h")

	var interval, bucketSize string
	switch rangeParam {
	case "7d":
		interval = "7 days"
		bucketSize = "6 hours"
	case "30d":
		interval = "30 days"
		bucketSize = "1 day"
	default:
		interval = "24 hours"
		bucketSize = "1 hour"
	}

	query := fmt.Sprintf(`
		WITH buckets AS (
			SELECT time_bucket('%s', ts) AS bucket
			FROM generate_series(NOW() - INTERVAL '%s', NOW(), INTERVAL '%s') AS ts
		),
		forms AS (
			SELECT time_bucket('%s', created_at) AS bucket, COUNT(*) AS cnt
			FROM form_submissions WHERE created_at > NOW() - INTERVAL '%s'
			GROUP BY 1
		),
		ssh AS (
			SELECT time_bucket('%s', created_at) AS bucket, COUNT(*) AS cnt
			FROM ssh_attempts WHERE created_at > NOW() - INTERVAL '%s'
			GROUP BY 1
		),
		urls AS (
			SELECT time_bucket('%s', created_at) AS bucket, COUNT(*) AS cnt
			FROM url_probes WHERE created_at > NOW() - INTERVAL '%s'
			GROUP BY 1
		)
		SELECT b.bucket,
			COALESCE(f.cnt, 0) AS form_count,
			COALESCE(s.cnt, 0) AS ssh_count,
			COALESCE(u.cnt, 0) AS url_count
		FROM buckets b
		LEFT JOIN forms f ON f.bucket = b.bucket
		LEFT JOIN ssh s ON s.bucket = b.bucket
		LEFT JOIN urls u ON u.bucket = b.bucket
		ORDER BY b.bucket`,
		bucketSize, interval, bucketSize,
		bucketSize, interval,
		bucketSize, interval,
		bucketSize, interval)

	rows, err := s.db.Query(c, query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var points []models.TimeseriesPoint
	for rows.Next() {
		var p models.TimeseriesPoint
		if err := rows.Scan(&p.Bucket, &p.FormCount, &p.SSHCount, &p.URLCount); err != nil {
			continue
		}
		points = append(points, p)
	}

	c.JSON(http.StatusOK, points)
}

func (s *StatsAPI) Categories(c *gin.Context) {
	rows, err := s.db.Query(c, `
		SELECT ac.id, ac.name, ac.description, ac.severity, COUNT(et.id) AS event_count
		FROM attack_categories ac
		LEFT JOIN event_tags et ON et.category_id = ac.id
		GROUP BY ac.id, ac.name, ac.description, ac.severity
		ORDER BY event_count DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var cats []models.CategoryStats
	for rows.Next() {
		var cat models.CategoryStats
		if err := rows.Scan(&cat.ID, &cat.Name, &cat.Description, &cat.Severity, &cat.EventCount); err != nil {
			continue
		}
		cats = append(cats, cat)
	}

	c.JSON(http.StatusOK, cats)
}

func (s *StatsAPI) Events(c *gin.Context) {
	eventType := c.Query("type")
	category := c.Query("category")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 50
	}
	offset := (page - 1) * limit

	// Build unified event query from all three tables
	var unions []string
	var args []any
	argIdx := 1

	tables := map[string]struct {
		table, summary string
	}{
		"form": {"form_submissions", "'Form: ' || form_name"},
		"ssh":  {"ssh_attempts", "'SSH: ' || username || '@' || COALESCE(host(ip)::text, '')"},
		"url":  {"url_probes", "method || ' ' || path"},
	}

	typesToQuery := []string{"form", "ssh", "url"}
	if eventType != "" {
		typesToQuery = []string{eventType}
	}

	for _, t := range typesToQuery {
		info, ok := tables[t]
		if !ok {
			continue
		}

		where := "WHERE 1=1"
		if category != "" {
			where += fmt.Sprintf(` AND id IN (SELECT event_id FROM event_tags WHERE event_type = '%s' AND category_id = $%d)`, t, argIdx)
			args = append(args, category)
			argIdx++
		}

		unions = append(unions, fmt.Sprintf(
			`SELECT id::text, created_at, '%s' AS event_type, COALESCE(host(ip)::text, '') AS ip,
				%s AS summary
			FROM %s %s`, t, info.summary, info.table, where))
	}

	if len(unions) == 0 {
		c.JSON(http.StatusOK, []models.UnifiedEvent{})
		return
	}

	fullQuery := ""
	for i, u := range unions {
		if i > 0 {
			fullQuery += " UNION ALL "
		}
		fullQuery += u
	}

	fullQuery = fmt.Sprintf(`SELECT * FROM (%s) combined ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		fullQuery, argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := s.db.Query(c, fullQuery, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var events []models.UnifiedEvent
	for rows.Next() {
		var e models.UnifiedEvent
		if err := rows.Scan(&e.ID, &e.CreatedAt, &e.EventType, &e.IP, &e.Summary); err != nil {
			continue
		}
		events = append(events, e)
	}
	rows.Close()

	// Fetch categories for each event
	for i, e := range events {
		catRows, err := s.db.Query(c, `
			SELECT ac.name FROM event_tags et
			JOIN attack_categories ac ON ac.id = et.category_id
			WHERE et.event_id = $1 AND et.event_type = $2`, e.ID, e.EventType)
		if err != nil {
			continue
		}
		for catRows.Next() {
			var name string
			if catRows.Scan(&name) == nil {
				events[i].Categories = append(events[i].Categories, name)
			}
		}
		catRows.Close()
	}

	c.JSON(http.StatusOK, events)
}

func (s *StatsAPI) EventDetail(c *gin.Context) {
	id := c.Param("id")

	// Try each table
	var result gin.H

	// Form submission
	var fs models.FormSubmission
	err := s.db.QueryRow(c, `SELECT id::text, created_at, form_name, COALESCE(host(ip)::text,''), user_agent, headers, body, classified
		FROM form_submissions WHERE id = $1`, id).
		Scan(&fs.ID, &fs.CreatedAt, &fs.FormName, &fs.IP, &fs.UserAgent, &fs.Headers, &fs.Body, &fs.Classified)
	if err == nil {
		result = gin.H{"type": "form", "data": fs}
	}

	if result == nil {
		var sa models.SSHAttempt
		err = s.db.QueryRow(c, `SELECT id::text, created_at, COALESCE(host(ip)::text,''), username, password, public_key, client_version, session_id, classified
			FROM ssh_attempts WHERE id = $1`, id).
			Scan(&sa.ID, &sa.CreatedAt, &sa.IP, &sa.Username, &sa.Password, &sa.PublicKey, &sa.ClientVersion, &sa.SessionID, &sa.Classified)
		if err == nil {
			result = gin.H{"type": "ssh", "data": sa}
		}
	}

	if result == nil {
		var up models.URLProbe
		err = s.db.QueryRow(c, `SELECT id::text, created_at, COALESCE(host(ip)::text,''), method, path, query_string, headers, body, user_agent, classified
			FROM url_probes WHERE id = $1`, id).
			Scan(&up.ID, &up.CreatedAt, &up.IP, &up.Method, &up.Path, &up.QueryString, &up.Headers, &up.Body, &up.UserAgent, &up.Classified)
		if err == nil {
			result = gin.H{"type": "url", "data": up}
		}
	}

	if result == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "event not found"})
		return
	}

	c.JSON(http.StatusOK, result)
}
