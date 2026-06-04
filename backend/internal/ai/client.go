// Package ai wraps the LLM provider behind a small interface so the rest of
// the app doesn't depend on Anthropic specifics. Following the same
// interface-first pattern as storage.Store: handlers depend on Client, the
// concrete AnthropicClient is wired at startup, and the whole feature can be
// disabled at boot if no API key is provided.
//
// We hit Anthropic's Messages API over HTTP directly rather than pulling in
// the official SDK. The wire format is small (one POST, one JSON body), the
// SDK adds a meaningful dependency tail, and using net/http keeps the
// interview story clean: "look, no magic, just an HTTP call."
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/braidman/tenexai-assessment/backend/internal/models"
	"github.com/braidman/tenexai-assessment/backend/internal/storage"
)

// ErrNotConfigured is returned by NewAnthropicClient when ANTHROPIC_API_KEY
// is unset. Handlers translate this into a 503 so the rest of the app keeps
// working without an API key.
var ErrNotConfigured = errors.New("AI not configured: ANTHROPIC_API_KEY is unset")

// Client is the smallest surface a handler needs to call the LLM. Two methods
// because we have two distinct prompts; sharing a generic Complete() would
// just push prompt construction into the handler layer.
type Client interface {
	GenerateBriefing(ctx context.Context, summary *storage.Summary, anomalies []models.Anomaly) (string, error)
	ExplainAnomaly(ctx context.Context, a models.Anomaly, entry *models.LogEntry) (string, error)
}

// AnthropicClient is a thin HTTP wrapper around the Messages API.
// https://docs.anthropic.com/en/api/messages
type AnthropicClient struct {
	apiKey string
	model  string
	http   *http.Client
}

// NewAnthropicClient returns ErrNotConfigured if apiKey is empty so the caller
// can gate the feature without nil checks scattered through the handler code.
func NewAnthropicClient(apiKey, model string) (*AnthropicClient, error) {
	if apiKey == "" {
		return nil, ErrNotConfigured
	}
	if model == "" {
		model = "claude-haiku-4-5-20251001"
	}
	return &AnthropicClient{
		apiKey: apiKey,
		model:  model,
		// 30s ceiling: Haiku usually returns in 1-2s, but we don't want a hung
		// upstream to wedge a handler indefinitely.
		http: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// --- wire types ---

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type messagesRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system,omitempty"`
	Messages  []message `json:"messages"`
}

type messagesResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Error      *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *AnthropicClient) post(ctx context.Context, req messagesRequest) (string, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	// 2023-06-01 is the long-stable Messages API version; bumping it can
	// silently change field shapes so we pin explicitly.
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	res, err := c.http.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("http do: %w", err)
	}
	defer res.Body.Close()
	rawBody, _ := io.ReadAll(res.Body)

	if res.StatusCode != http.StatusOK {
		// Surface the API's error message verbatim to make debugging easy
		// (rate limit, bad key, model not found, etc.).
		return "", fmt.Errorf("anthropic %d: %s", res.StatusCode, string(rawBody))
	}

	var out messagesResponse
	if err := json.Unmarshal(rawBody, &out); err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	if out.Error != nil {
		return "", fmt.Errorf("anthropic error: %s", out.Error.Message)
	}
	// Concatenate every text block. Today Haiku returns a single block, but
	// future models can interleave reasoning/text blocks (extended thinking,
	// tool-use, etc.). Defensive concat costs nothing and survives the
	// upgrade.
	var sb bytes.Buffer
	for _, b := range out.Content {
		if b.Type == "text" {
			sb.WriteString(b.Text)
		}
	}
	if sb.Len() == 0 {
		return "", fmt.Errorf("no text content in response")
	}
	return sb.String(), nil
}

// --- briefing ---

const briefingSystem = `You are a senior SOC analyst writing a concise briefing for Tier-1 handover.
Your job: read structured findings from a rule-based detector and translate them into a triage-ready note.
Be precise. Reference specific IPs, users, and URLs from the input. Do not invent facts.
Format:
- One short paragraph framing the upload (volume, blocked rate, what stands out).
- A bulleted "Priority actions" list, highest impact first, with the specific entity to act on.
- A one-line "Plausible false positives" note.
Keep the entire briefing under 200 words. Use markdown.`

func (c *AnthropicClient) GenerateBriefing(ctx context.Context, summary *storage.Summary, anomalies []models.Anomaly) (string, error) {
	// Compact JSON keeps the prompt cheap and forces structure. We trim
	// anomalies to the top 20 by confidence to bound prompt size for huge
	// uploads (one full anomaly row is ~200 chars).
	if len(anomalies) > 20 {
		anomalies = anomalies[:20]
	}
	payload := map[string]any{
		"summary":   summary,
		"anomalies": anomalies,
	}
	userJSON, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	return c.post(ctx, messagesRequest{
		Model:     c.model,
		MaxTokens: 800,
		System:    briefingSystem,
		Messages: []message{
			{Role: "user", Content: "Here are the rule-based findings for this log upload. Write the SOC briefing.\n\n" + string(userJSON)},
		},
	})
}

// --- per-anomaly explanation ---

const explainSystem = `You are a senior SOC analyst. Given one anomaly detected by a rule, explain it to a Tier-1 analyst.
Structure your answer in three short sections using markdown headings:
- **What this likely means** — interpret the pattern in plain English.
- **Recommended actions** — 2-3 bullets, priority order, with the specific entity to act on.
- **Plausible false positives** — one short paragraph.
Keep the entire explanation under 130 words. Do not invent facts; if the input doesn't tell you something, don't speculate about it.`

func (c *AnthropicClient) ExplainAnomaly(ctx context.Context, a models.Anomaly, entry *models.LogEntry) (string, error) {
	payload := map[string]any{
		"anomaly":   a,
		"log_entry": entry, // may be nil for upload-wide anomalies
	}
	userJSON, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	return c.post(ctx, messagesRequest{
		Model:     c.model,
		MaxTokens: 400,
		System:    explainSystem,
		Messages: []message{
			{Role: "user", Content: "Explain this anomaly.\n\n" + string(userJSON)},
		},
	})
}
