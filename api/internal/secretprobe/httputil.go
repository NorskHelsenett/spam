package secretprobe

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// Response is a simplified HTTP response for probe functions.
type Response struct {
	Status int
	Body   string
	Header http.Header
}

var probeClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // don't follow redirects
	},
}

// probeLoggerKey is the context key for the audit logger.
type probeLoggerKey struct{}

// probeHashKey is the context key for the current secret hash.
type probeHashKey struct{}

// probeRuleKey is the context key for the current rule ID.
type probeRuleKey struct{}

// WithAuditLogger attaches an audit logger to the context.
func WithAuditLogger(ctx context.Context, logger *AuditLogger) context.Context {
	return context.WithValue(ctx, probeLoggerKey{}, logger)
}

// WithProbeIdentity attaches the secret hash and rule ID for audit logging.
func WithProbeIdentity(ctx context.Context, hash, ruleID string) context.Context {
	ctx = context.WithValue(ctx, probeHashKey{}, hash)
	ctx = context.WithValue(ctx, probeRuleKey{}, ruleID)
	return ctx
}

// HTTPGet makes a GET request with the given headers.
func HTTPGet(ctx context.Context, url string, headers map[string]string) (*Response, error) {
	return doRequest(ctx, http.MethodGet, url, headers, "")
}

// HTTPPost makes a POST request with the given headers and body.
func HTTPPost(ctx context.Context, url string, headers map[string]string, body string) (*Response, error) {
	return doRequest(ctx, http.MethodPost, url, headers, body)
}

func doRequest(ctx context.Context, method, url string, headers map[string]string, body string) (*Response, error) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		logAudit(ctx, method, url, headers, 0, "", err.Error(), 0)
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := probeClient.Do(req)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		logAudit(ctx, method, url, headers, 0, "", err.Error(), elapsed)
		return nil, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	r := &Response{
		Status: resp.StatusCode,
		Body:   string(b),
		Header: resp.Header,
	}

	logAudit(ctx, method, url, headers, r.Status, r.Body, "", elapsed)
	return r, nil
}

func logAudit(ctx context.Context, method, url string, headers map[string]string, status int, body, errMsg string, durationMs int64) {
	logger, _ := ctx.Value(probeLoggerKey{}).(*AuditLogger)
	if logger == nil {
		return
	}
	hash, _ := ctx.Value(probeHashKey{}).(string)
	ruleID, _ := ctx.Value(probeRuleKey{}).(string)

	// Redact auth values in header log — store type only.
	safeHeaders := map[string]string{}
	for k, v := range headers {
		lower := strings.ToLower(k)
		if lower == "authorization" || lower == "private-token" {
			parts := strings.SplitN(v, " ", 2)
			if len(parts) == 2 {
				safeHeaders[k] = parts[0] + " [REDACTED]"
			} else {
				safeHeaders[k] = "[REDACTED]"
			}
		} else {
			safeHeaders[k] = v
		}
	}
	headerJSON, _ := json.Marshal(safeHeaders)

	logger.Log(ProbeAuditLog{
		SecretHash:     hash,
		RuleID:         ruleID,
		Method:         method,
		URL:            url,
		RequestHeaders: string(headerJSON),
		StatusCode:     status,
		ResponseBody:   body,
		Error:          errMsg,
		Duration:       durationMs,
	})
}

// Unknown returns a standard "unknown" probe output for unexpected HTTP responses.
func Unknown(r *Response) ProbeOutput {
	reason := "unexpected response"
	if r != nil {
		reason = http.StatusText(r.Status)
	}
	return ProbeOutput{Status: StatusUnknown, Reason: reason}
}
