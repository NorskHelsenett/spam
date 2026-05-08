package uiapi

import (
	"net/http"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/ror"
)

// AdminRORProbeHandler hits the candidate ROR endpoints we'd use to
// derive cluster ACL grants and echoes back the raw responses so an
// admin can confirm which one returns "clusters this user can see"
// before we wire the result into the ACL provider chain.
//
// Endpoints probed:
//   - POST /v1/clusters/filter — paginated cluster list (most likely fit)
//   - POST /v1/acl/filter      — paginated ACL list
//   - GET  /v1/acl/scopes      — scope catalog (sanity-check auth path)
//
// Uses the caller's persisted EntraID access token + the configured
// service API key. Admin-only; output includes the raw upstream body
// (HTTP status, headers, JSON), so it's not safe to expose more
// broadly.
func AdminRORProbeHandler(authService *auth.Service, client *ror.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if client == nil {
			http.Error(w, "ROR client not configured (set ROR_BASE_URL / ROR_API_KEY)", http.StatusServiceUnavailable)
			return
		}

		token, err := authService.AccessTokenForRequest(r)
		if err != nil {
			http.Error(w, "decode access token failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if token == "" {
			http.Error(w, "no EntraID access token on session — re-login may be required", http.StatusPreconditionFailed)
			return
		}

		emptyFilter := ror.FilterRequest{Limit: 25}

		type probeCase struct {
			Name   string          `json:"name"`
			Method string          `json:"method"`
			Path   string          `json:"path"`
			Result *ror.RawResponse `json:"result,omitempty"`
			Error  string          `json:"error,omitempty"`
		}

		cases := []struct {
			name   string
			method string
			path   string
			body   any
		}{
			{"clusters_filter_empty", "POST", "/v1/clusters/filter", emptyFilter},
			{"acl_filter_empty", "POST", "/v1/acl/filter", emptyFilter},
			{"acl_scopes", "GET", "/v1/acl/scopes", nil},
		}

		results := make([]probeCase, 0, len(cases))
		for _, tc := range cases {
			out := probeCase{Name: tc.name, Method: tc.method, Path: tc.path}
			res, err := client.Do(r.Context(), token, tc.method, tc.path, tc.body)
			if err != nil {
				out.Error = err.Error()
			} else {
				out.Result = res
			}
			results = append(results, out)
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"base_url":    client.BaseURL,
			"api_key_set": client.APIKey != "",
			"results":     results,
		})
	}
}
