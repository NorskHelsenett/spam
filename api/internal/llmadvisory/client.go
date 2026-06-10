package llmadvisory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// chatTimeout bounds one completion. The endpoint runs a reasoning
// model — generation regularly takes several seconds; a hung upstream
// shouldn't pin the worker for longer than this.
const chatTimeout = 90 * time.Second

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Stream      bool          `json:"stream"`
	Messages    []chatMessage `json:"messages"`
	Temperature float32       `json:"temperature"`
	TopK        int           `json:"top_k,omitempty"`
	TopP        float32       `json:"top_p,omitempty"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Content   string `json:"content"`
			Reasoning string `json:"reasoning"`
		} `json:"message"`
	} `json:"choices"`
}

// Chat sends one system+user exchange and returns the assistant text.
// Quirks handled here, learned from probing the real endpoint:
//   - reasoning models spend hidden "reasoning" tokens that count
//     toward max_tokens — an empty content with finish_reason=length
//     means the budget was too small, which we surface explicitly;
//   - replies sometimes arrive wrapped in markdown code fences.
func Chat(ctx context.Context, s Settings, userPayload string) (string, error) {
	body, err := json.Marshal(chatRequest{
		Model:  s.Model,
		Stream: false,
		Messages: []chatMessage{
			{Role: "system", Content: s.SystemPrompt},
			{Role: "user", Content: userPayload},
		},
		Temperature: s.Temperature,
		TopK:        s.TopK,
		TopP:        s.TopP,
		MaxTokens:   s.MaxTokens,
	})
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(ctx, chatTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.BaseURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.APIKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("llm endpoint returned %d", resp.StatusCode)
	}

	var out chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", errors.New("llm response had no choices")
	}
	ch := out.Choices[0]
	content := strings.TrimSpace(ch.Message.Content)
	// length means the budget ran out: either reasoning consumed it
	// all (empty content) or the answer is cut mid-sentence. A
	// truncated advisory must never be cached — fail loudly instead.
	if ch.FinishReason == "length" {
		return "", errors.New("finish_reason=length — raise max_tokens (reasoning counts toward the budget)")
	}
	if content == "" {
		return "", errors.New("llm returned empty content")
	}
	return stripFences(content), nil
}

// stripFences unwraps a ```...``` block (optionally ```json) when the
// whole reply is fenced.
func stripFences(s string) string {
	if !strings.HasPrefix(s, "```") {
		return s
	}
	body := strings.TrimPrefix(s, "```")
	if i := strings.IndexByte(body, '\n'); i >= 0 {
		body = body[i+1:] // drop the language tag line
	}
	body = strings.TrimSuffix(strings.TrimSpace(body), "```")
	return strings.TrimSpace(body)
}

// Verdict is the parsed shadow-mode agent decision.
type Verdict struct {
	Verdict       string   `json:"verdict"`
	Justification string   `json:"justification"`
	Confidence    float32  `json:"confidence"`
	MissingData   []string `json:"missing_data"`
}

// ParseVerdict extracts and normalizes the verdict JSON. Models
// occasionally invent verdict values ("suppressible",
// "not-applicable") — anything that isn't clearly a suppression vote
// normalizes to "keep" so the shadow data errs conservative.
func ParseVerdict(raw string) (Verdict, error) {
	start := strings.IndexByte(raw, '{')
	end := strings.LastIndexByte(raw, '}')
	if start < 0 || end <= start {
		return Verdict{}, errors.New("no JSON object in verdict reply")
	}
	var v Verdict
	if err := json.Unmarshal([]byte(raw[start:end+1]), &v); err != nil {
		return Verdict{}, err
	}
	switch strings.ToLower(strings.TrimSpace(v.Verdict)) {
	case "suppress", "suppressible", "not_applicable", "not-applicable":
		v.Verdict = "suppress"
	default:
		v.Verdict = "keep"
	}
	if v.Confidence < 0 {
		v.Confidence = 0
	}
	if v.Confidence > 1 {
		v.Confidence = 1
	}
	return v, nil
}
