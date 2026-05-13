// Package ror is a thin client for the NHN Register of Reporting (ROR)
// API at https://api.ror.nhn.no. The first user is the ACL pipeline
// stage that derives a user's accessible clusters from ROR ACLs;
// other consumers may follow.
//
// Auth: the user's EntraID bearer token is forwarded per-request as
// `Authorization: Bearer <token>`. ROR's Swagger documents an
// additional X-API-KEY header, but in practice the user token alone
// is accepted, so no service-side key is wired here.
package ror

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is a thin authenticated HTTP client for the ROR API.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// New builds a client. baseURL defaults to the production endpoint
// (https://api.ror.nhn.no) when empty; tests and staging can override.
func New(baseURL string) *Client {
	if baseURL == "" {
		baseURL = "https://api.ror.nhn.no"
	}
	return &Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// RawResponse is what the probe handler echoes back so we can see
// exactly what ROR returned without any client-side reshaping.
type RawResponse struct {
	Status      int               `json:"status"`
	ContentType string            `json:"content_type,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        json.RawMessage   `json:"body,omitempty"`
	BodyText    string            `json:"body_text,omitempty"`
}

// Do issues an authenticated request. accessToken is the user's
// EntraID bearer token; passing "" omits the header (which ROR
// will reject with 401 in production).
func (c *Client) Do(ctx context.Context, accessToken, method, path string, body any) (*RawResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("ror client not configured")
	}
	url := c.BaseURL + path

	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		rdr = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	out := &RawResponse{
		Status:      resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') && json.Valid(trimmed) {
		out.Body = trimmed
	} else {
		out.BodyText = string(raw)
	}
	return out, nil
}

// FilterRequest is the body shape POST /v1/clusters/filter and
// POST /v1/acl/filter both expect.
type FilterRequest struct {
	Filters     []FilterMetadata `json:"filters"`
	GlobalFilter any             `json:"globalFilter,omitempty"`
	Limit       int              `json:"limit,omitempty"`
	Skip        int              `json:"skip,omitempty"`
	Sort        []SortMetadata   `json:"sort,omitempty"`
}

// FilterMetadata mirrors apicontracts.FilterMetadata. Fields are kept
// as `any` because the upstream schema is loose (operators vary by
// field type) and we have not yet committed to a concrete subset.
type FilterMetadata struct {
	Field    string `json:"field,omitempty"`
	Operator string `json:"operator,omitempty"`
	Value    any    `json:"value,omitempty"`
}

// SortMetadata mirrors apicontracts.SortMetadata.
type SortMetadata struct {
	Field string `json:"field,omitempty"`
	Order int    `json:"order,omitempty"`
}
