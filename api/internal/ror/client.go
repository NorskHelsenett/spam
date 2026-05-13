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

// GlobalScopeSubject is the magic subject id used by ROR for global
// access grants. When `scopes.ror.subject.globalscope.<action> = true`,
// the user has that access against every resource in the system.
const GlobalScopeSubject = "globalscope"

// LookupResponse mirrors the body returned by GET /v1/acl/lookup.
// Shape (per the ROR team):
//
//	{
//	  "scopes": {
//	    "<scope>": {              // "cluster", "ror", "project", ...
//	      "subject": {
//	        "<subject-id>": {     // cluster id, or "globalscope"
//	          "read": bool,
//	          "create": bool,
//	          "update": bool,
//	          "delete": bool,
//	          "owner": bool,
//	          "kuberneteslogon": bool
//	        }
//	      }
//	    }
//	  }
//	}
//
// We deserialize the full permission set so V2 work (write-flavoured
// guards, kubeconfig flows) can reuse this without another round trip.
type LookupResponse struct {
	Scopes map[string]LookupScope `json:"scopes"`
}

// LookupScope is the per-scope envelope; `subject` is keyed by the
// resource id (cluster id, project id, etc.) — or GlobalScopeSubject
// when the grant is system-wide.
type LookupScope struct {
	Subject map[string]LookupAccess `json:"subject"`
}

// LookupAccess is the per-subject permission tuple. All actions are
// captured so we don't have to re-call the endpoint for write checks
// later.
type LookupAccess struct {
	Read            bool `json:"read"`
	Create          bool `json:"create"`
	Update          bool `json:"update"`
	Delete          bool `json:"delete"`
	Owner           bool `json:"owner"`
	KubernetesLogon bool `json:"kuberneteslogon"`
}

// LookupACL issues GET /v1/acl/lookup?scope=&access= and decodes the
// response into a typed LookupResponse. Pass scope="" / access="" to
// omit the filter — callers typically pass scope="cluster" plus
// access="read" for the cluster-visibility flow.
func (c *Client) LookupACL(ctx context.Context, accessToken, scope, access string) (*LookupResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("ror client not configured")
	}
	path := "/v1/acl/lookup"
	q := []string{}
	if scope != "" {
		q = append(q, "scope="+scope)
	}
	if access != "" {
		q = append(q, "access="+access)
	}
	if len(q) > 0 {
		path += "?" + strings.Join(q, "&")
	}

	res, err := c.Do(ctx, accessToken, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if res.Status < 200 || res.Status >= 300 {
		body := res.BodyText
		if body == "" && len(res.Body) > 0 {
			body = string(res.Body)
		}
		return nil, fmt.Errorf("ror lookup: status %d: %s", res.Status, body)
	}
	if len(res.Body) == 0 {
		return &LookupResponse{}, nil
	}
	var out LookupResponse
	if err := json.Unmarshal(res.Body, &out); err != nil {
		return nil, fmt.Errorf("decode lookup response: %w", err)
	}
	return &out, nil
}
