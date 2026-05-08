package uiapi

import (
	"encoding/json"
	"net/http"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/ror"
)

// MeClustersHandler returns the clusters the calling user can see in
// ROR, derived from their EntraID identity. Authenticated by session
// cookie only — any approved user may read their own access list, no
// admin role required. The endpoint forwards the user's persisted
// EntraID access token and the service-configured X-API-KEY to ROR.
//
// Response shape is the upstream JSON unchanged plus a top-level
// `status` and `endpoint` field, so the consumer can see exactly what
// ROR returned during the integration probe phase. Once we settle on
// a single endpoint and shape, this handler will reduce to a typed
// `{clusters: [...]}` payload.
func MeClustersHandler(authService *auth.Service, client *ror.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.LoadSession(r); err != nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		if client == nil {
			http.Error(w, "ROR integration not configured", http.StatusServiceUnavailable)
			return
		}

		token, err := authService.AccessTokenForRequest(r)
		if err != nil {
			http.Error(w, "decode access token failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if token == "" {
			http.Error(w, "no EntraID access token on session — please log out and back in", http.StatusPreconditionFailed)
			return
		}

		// Empty filter — server-side ACL on ROR is expected to limit
		// the result set to clusters the caller can see. Pagination is
		// ignored on the first pass; if the user has > 200 clusters
		// we'll add a follow-up call.
		body := ror.FilterRequest{Limit: 200}
		res, err := client.Do(r.Context(), token, "POST", "/v1/clusters/filter", body)
		if err != nil {
			http.Error(w, "ror call failed: "+err.Error(), http.StatusBadGateway)
			return
		}

		out := map[string]any{
			"endpoint": "/v1/clusters/filter",
			"status":   res.Status,
		}
		if len(res.Body) > 0 {
			out["upstream"] = json.RawMessage(res.Body)
		} else if res.BodyText != "" {
			out["upstream_text"] = res.BodyText
		}
		writeJSON(w, http.StatusOK, out)
	}
}
