package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/ericovis/unsolicited/internal/classifier"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Worker struct {
	db         *pgxpool.Pool
	classifier *classifier.Classifier
}

func New(db *pgxpool.Pool, cls *classifier.Classifier) *Worker {
	return &Worker{db: db, classifier: cls}
}

func (w *Worker) Start(ctx context.Context) {
	log.Println("worker: classification worker started")
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("worker: shutting down")
			return
		case <-ticker.C:
			w.processUnclassified(ctx)
		}
	}
}

func (w *Worker) processUnclassified(ctx context.Context) {
	// Process one of each type per tick to be fair
	w.classifyOne(ctx, "form", `
		SELECT id, form_name, COALESCE(host(ip)::text,''), user_agent, body
		FROM form_submissions WHERE classified = FALSE
		ORDER BY created_at ASC LIMIT 1`)

	w.classifyOne(ctx, "ssh", `
		SELECT id, username, password, public_key, COALESCE(host(ip)::text,''), client_version
		FROM ssh_attempts WHERE classified = FALSE
		ORDER BY created_at ASC LIMIT 1`)

	w.classifyOne(ctx, "url", `
		SELECT id, method, path, query_string, COALESCE(host(ip)::text,''), user_agent, headers
		FROM url_probes WHERE classified = FALSE
		ORDER BY created_at ASC LIMIT 1`)
}

func (w *Worker) classifyOne(ctx context.Context, eventType, query string) {
	rows, err := w.db.Query(ctx, query)
	if err != nil {
		log.Printf("worker: query %s error: %v", eventType, err)
		return
	}
	defer rows.Close()

	if !rows.Next() {
		return
	}

	var id string
	var description string

	switch eventType {
	case "form":
		var formName, ip, userAgent string
		var body json.RawMessage
		if err := rows.Scan(&id, &formName, &ip, &userAgent, &body); err != nil {
			log.Printf("worker: scan form error: %v", err)
			return
		}
		description = fmt.Sprintf("Form: %s\nIP: %s\nUser-Agent: %s\nBody: %s",
			formName, ip, userAgent, string(body))

	case "ssh":
		var username, password, publicKey, ip, clientVersion string
		if err := rows.Scan(&id, &username, &password, &publicKey, &ip, &clientVersion); err != nil {
			log.Printf("worker: scan ssh error: %v", err)
			return
		}
		description = fmt.Sprintf("Username: %s\nPassword: %s\nPublic Key: %s\nIP: %s\nClient: %s",
			username, password, publicKey, ip, clientVersion)

	case "url":
		var method, path, queryString, ip, userAgent string
		var headers json.RawMessage
		if err := rows.Scan(&id, &method, &path, &queryString, &ip, &userAgent, &headers); err != nil {
			log.Printf("worker: scan url error: %v", err)
			return
		}
		description = fmt.Sprintf("Method: %s\nPath: %s\nQuery: %s\nIP: %s\nUser-Agent: %s\nHeaders: %s",
			method, path, queryString, ip, userAgent, string(headers))
	}

	rows.Close()

	result, rawAnalysis, err := w.classifier.Classify(ctx, eventType, description)
	if err != nil {
		log.Printf("worker: classify %s/%s error: %v", eventType, id, err)
		// Mark as classified anyway to avoid infinite retries, but with no tags
		w.markClassified(ctx, eventType, id)
		return
	}

	// Upsert category
	var categoryID string
	err = w.db.QueryRow(ctx,
		`INSERT INTO attack_categories (name, description, severity)
		VALUES ($1, $2, $3)
		ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description
		RETURNING id`,
		result.Category, result.Description, result.Severity,
	).Scan(&categoryID)
	if err != nil {
		log.Printf("worker: upsert category error: %v", err)
		return
	}

	// Create event tag
	_, err = w.db.Exec(ctx,
		`INSERT INTO event_tags (event_id, event_type, category_id, confidence, raw_analysis)
		VALUES ($1, $2, $3, $4, $5)`,
		id, eventType, categoryID, result.Confidence, rawAnalysis,
	)
	if err != nil {
		log.Printf("worker: insert event_tag error: %v", err)
		return
	}

	w.markClassified(ctx, eventType, id)
	log.Printf("worker: classified %s/%s as %q (%s, %.0f%%)",
		eventType, id, result.Category, result.Severity, result.Confidence*100)
}

func (w *Worker) markClassified(ctx context.Context, eventType, id string) {
	var table string
	switch eventType {
	case "form":
		table = "form_submissions"
	case "ssh":
		table = "ssh_attempts"
	case "url":
		table = "url_probes"
	}

	_, err := w.db.Exec(ctx,
		fmt.Sprintf("UPDATE %s SET classified = TRUE WHERE id = $1", table), id)
	if err != nil {
		log.Printf("worker: mark classified error: %v", err)
	}
}
