package database

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

var migrations = []string{
	`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`,
	`CREATE EXTENSION IF NOT EXISTS timescaledb`,

	// Form submissions
	`CREATE TABLE IF NOT EXISTS form_submissions (
		id UUID DEFAULT uuid_generate_v4(),
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		form_name TEXT NOT NULL,
		ip INET,
		user_agent TEXT,
		headers JSONB,
		body JSONB,
		country_code TEXT,
		country_name TEXT,
		city TEXT,
		latitude DOUBLE PRECISION,
		longitude DOUBLE PRECISION,
		asn INTEGER,
		asn_org TEXT,
		classified BOOLEAN NOT NULL DEFAULT FALSE
	)`,

	// SSH attempts
	`CREATE TABLE IF NOT EXISTS ssh_attempts (
		id UUID DEFAULT uuid_generate_v4(),
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		ip INET,
		username TEXT,
		password TEXT,
		public_key TEXT,
		client_version TEXT,
		session_id TEXT,
		country_code TEXT,
		country_name TEXT,
		city TEXT,
		latitude DOUBLE PRECISION,
		longitude DOUBLE PRECISION,
		asn INTEGER,
		asn_org TEXT,
		classified BOOLEAN NOT NULL DEFAULT FALSE
	)`,

	// URL probes
	`CREATE TABLE IF NOT EXISTS url_probes (
		id UUID DEFAULT uuid_generate_v4(),
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		ip INET,
		method TEXT,
		path TEXT,
		query_string TEXT,
		headers JSONB,
		body BYTEA,
		user_agent TEXT,
		country_code TEXT,
		country_name TEXT,
		city TEXT,
		latitude DOUBLE PRECISION,
		longitude DOUBLE PRECISION,
		asn INTEGER,
		asn_org TEXT,
		classified BOOLEAN NOT NULL DEFAULT FALSE
	)`,

	// Attack categories
	`CREATE TABLE IF NOT EXISTS attack_categories (
		id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
		name TEXT UNIQUE NOT NULL,
		description TEXT,
		severity TEXT CHECK (severity IN ('low', 'medium', 'high', 'critical'))
	)`,

	// Event tags (links events to categories)
	`CREATE TABLE IF NOT EXISTS event_tags (
		id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
		event_id UUID NOT NULL,
		event_type TEXT NOT NULL CHECK (event_type IN ('form', 'ssh', 'url')),
		category_id UUID NOT NULL REFERENCES attack_categories(id),
		confidence DOUBLE PRECISION,
		raw_analysis TEXT,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
}

var hypertables = []string{
	`SELECT create_hypertable('form_submissions', 'created_at', if_not_exists => TRUE)`,
	`SELECT create_hypertable('ssh_attempts', 'created_at', if_not_exists => TRUE)`,
	`SELECT create_hypertable('url_probes', 'created_at', if_not_exists => TRUE)`,
}

var indexes = []string{
	// Form submissions indexes
	`CREATE INDEX IF NOT EXISTS idx_form_submissions_ip ON form_submissions (ip)`,
	`CREATE INDEX IF NOT EXISTS idx_form_submissions_classified ON form_submissions (classified) WHERE classified = FALSE`,
	`CREATE INDEX IF NOT EXISTS idx_form_submissions_country ON form_submissions (country_code)`,

	// SSH attempts indexes
	`CREATE INDEX IF NOT EXISTS idx_ssh_attempts_ip ON ssh_attempts (ip)`,
	`CREATE INDEX IF NOT EXISTS idx_ssh_attempts_classified ON ssh_attempts (classified) WHERE classified = FALSE`,
	`CREATE INDEX IF NOT EXISTS idx_ssh_attempts_country ON ssh_attempts (country_code)`,

	// URL probes indexes
	`CREATE INDEX IF NOT EXISTS idx_url_probes_ip ON url_probes (ip)`,
	`CREATE INDEX IF NOT EXISTS idx_url_probes_classified ON url_probes (classified) WHERE classified = FALSE`,
	`CREATE INDEX IF NOT EXISTS idx_url_probes_country ON url_probes (country_code)`,
	`CREATE INDEX IF NOT EXISTS idx_url_probes_path ON url_probes (path)`,

	// Event tags indexes
	`CREATE INDEX IF NOT EXISTS idx_event_tags_event ON event_tags (event_type, event_id)`,
	`CREATE INDEX IF NOT EXISTS idx_event_tags_category ON event_tags (category_id)`,
}

func RunMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	for i, m := range migrations {
		if _, err := pool.Exec(ctx, m); err != nil {
			return fmt.Errorf("migration %d failed: %w", i, err)
		}
	}

	for i, h := range hypertables {
		if _, err := pool.Exec(ctx, h); err != nil {
			log.Printf("hypertable %d (may already exist): %v", i, err)
		}
	}

	for i, idx := range indexes {
		if _, err := pool.Exec(ctx, idx); err != nil {
			return fmt.Errorf("index %d failed: %w", i, err)
		}
	}

	log.Println("database migrations completed")
	return nil
}
