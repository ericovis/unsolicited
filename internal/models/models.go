package models

import (
	"encoding/json"
	"time"
)

type FormSubmission struct {
	ID         string          `json:"id"`
	CreatedAt  time.Time       `json:"created_at"`
	FormName   string          `json:"form_name"`
	IP         string          `json:"ip"`
	UserAgent  string          `json:"user_agent"`
	Headers    json.RawMessage `json:"headers"`
	Body       json.RawMessage `json:"body"`
	Classified bool            `json:"classified"`
}

type SSHAttempt struct {
	ID            string    `json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	IP            string    `json:"ip"`
	Username      string    `json:"username"`
	Password      string    `json:"password"`
	PublicKey     string    `json:"public_key"`
	ClientVersion string    `json:"client_version"`
	SessionID     string    `json:"session_id"`
	Classified    bool      `json:"classified"`
}

type URLProbe struct {
	ID          string          `json:"id"`
	CreatedAt   time.Time       `json:"created_at"`
	IP          string          `json:"ip"`
	Method      string          `json:"method"`
	Path        string          `json:"path"`
	QueryString string          `json:"query_string"`
	Headers     json.RawMessage `json:"headers"`
	Body        []byte          `json:"body"`
	UserAgent   string          `json:"user_agent"`
	Classified  bool            `json:"classified"`
}

type AttackCategory struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type EventTag struct {
	ID          string    `json:"id"`
	EventID     string    `json:"event_id"`
	EventType   string    `json:"event_type"`
	CategoryID  string    `json:"category_id"`
	Confidence  float64   `json:"confidence"`
	RawAnalysis string    `json:"raw_analysis"`
	CreatedAt   time.Time `json:"created_at"`
}

// UnifiedEvent is used for displaying events in the feed across all types.
type UnifiedEvent struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	EventType  string    `json:"event_type"`
	IP         string    `json:"ip"`
	Summary    string    `json:"summary"`
	Categories []string  `json:"categories,omitempty"`
}

// StatsOverview holds aggregate counters.
type StatsOverview struct {
	FormTotal int64 `json:"form_total"`
	Form24h   int64 `json:"form_24h"`
	Form7d    int64 `json:"form_7d"`
	SSHTotal  int64 `json:"ssh_total"`
	SSH24h    int64 `json:"ssh_24h"`
	SSH7d     int64 `json:"ssh_7d"`
	URLTotal  int64 `json:"url_total"`
	URL24h    int64 `json:"url_24h"`
	URL7d     int64 `json:"url_7d"`
}

type TimeseriesPoint struct {
	Bucket    time.Time `json:"bucket"`
	FormCount int64     `json:"form_count"`
	SSHCount  int64     `json:"ssh_count"`
	URLCount  int64     `json:"url_count"`
}

type CategoryStats struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	EventCount  int64  `json:"event_count"`
}

// ClassificationResult is the expected JSON from the LLM.
type ClassificationResult struct {
	Category    string  `json:"category"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
}
