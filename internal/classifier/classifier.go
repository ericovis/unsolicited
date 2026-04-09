package classifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ericovis/unsolicited/internal/models"
)

type Classifier struct {
	ollamaURL string
	model     string
	client    *http.Client
}

func New(ollamaURL, model string) *Classifier {
	return &Classifier{
		ollamaURL: ollamaURL,
		model:     model,
		client:    &http.Client{Timeout: 120 * time.Second},
	}
}

const systemPrompt = `You are a cybersecurity analyst. Analyze the following honeypot event and classify the attack.

Return ONLY valid JSON with this exact structure:
{
  "category": "Category Name",
  "severity": "low|medium|high|critical",
  "description": "Brief description of the attack pattern",
  "confidence": 0.0-1.0
}

Known categories (use these when applicable, or create new ones):
- CVE Exploit: Attempts to exploit a known CVE vulnerability
- WordPress Admin Hijack: Attempts to access WordPress admin panels
- SQL Injection: SQL injection attempts in form fields or URLs
- Credential Stuffing: Brute force login with common credentials
- Directory Traversal: Path traversal attacks (../ patterns)
- Shellshock: Bash Shellshock exploit attempts
- Log4Shell: Log4j/Log4Shell exploitation attempts
- PHP Exploitation: Attacks targeting PHP files/functions
- Web Shell Upload: Attempts to upload web shells
- Bot Reconnaissance: Automated scanning/fingerprinting
- SSH Brute Force: Automated SSH login attempts with common passwords
- SSH Key Scan: Probing SSH with various keys
- Spam Bot: Form spam submissions
- Generic Bot Scan: General automated scanning with no specific exploit

Only return the JSON object, no other text.`

func (c *Classifier) Classify(ctx context.Context, eventType, eventDescription string) (*models.ClassificationResult, string, error) {
	prompt := fmt.Sprintf("Event type: %s\n\nEvent details:\n%s", eventType, eventDescription)

	reqBody := map[string]any{
		"model":  c.model,
		"system": systemPrompt,
		"prompt": prompt,
		"stream": false,
		"options": map[string]any{
			"temperature": 1.0,
			"top_p":       0.95,
			"top_k":       64,
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ollamaURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("ollama returned %d: %s", resp.StatusCode, string(respBody))
	}

	var ollamaResp struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(respBody, &ollamaResp); err != nil {
		return nil, "", fmt.Errorf("unmarshal ollama response: %w", err)
	}

	rawAnalysis := ollamaResp.Response

	// Try to extract JSON from the response (LLM may wrap it in markdown)
	jsonStr := extractJSON(rawAnalysis)

	var result models.ClassificationResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, rawAnalysis, fmt.Errorf("parse classification JSON: %w (raw: %s)", err, rawAnalysis)
	}

	// Validate severity
	switch result.Severity {
	case "low", "medium", "high", "critical":
	default:
		result.Severity = "medium"
	}

	if result.Confidence < 0 || result.Confidence > 1 {
		result.Confidence = 0.5
	}

	return &result, rawAnalysis, nil
}

// extractJSON tries to find a JSON object in a string that may contain markdown fences.
func extractJSON(s string) string {
	// Try to find JSON between code fences
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] == '{' {
			start = i
			break
		}
	}
	if start == -1 {
		return s
	}

	depth := 0
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}

	return s[start:]
}
