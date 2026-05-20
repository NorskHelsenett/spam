package uiapi

import (
	"net/http"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/ror"
)

// meClusterAccess is the per-cluster slice returned to the SPA. It
// mirrors ror.LookupAccess but lives here so the upstream type isn't
// part of our public contract.
type meClusterAccess struct {
	ClusterID       string `json:"cluster_id"`
	Read            bool   `json:"read"`
	Create          bool   `json:"create"`
	Update          bool   `json:"update"`
	Delete          bool   `json:"delete"`
	Owner           bool   `json:"owner"`
	KubernetesLogon bool   `json:"kuberneteslogon"`
}

type meClustersResponse struct {
	GlobalRead bool              `json:"global_read"`
	Clusters   []meClusterAccess `json:"clusters"`
}

// MeClustersHandler returns the clusters the calling user can see in
// ROR, derived from their EntraID identity. Authenticated by session
// cookie only — any approved user may read their own access list, no
// admin role required.
//
// Calls GET /v1/acl/lookup on ROR with the user's session-decrypted
// (auto-refreshed) access token and projects the response onto a flat
// list plus a `global_read` flag for ror.globalscope.read=true users.
// All permission flags are included so the SPA can mark write-only
// access differently from read access.
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
			http.Error(w, "no OIDC access token on session — please log out and back in", http.StatusPreconditionFailed)
			return
		}

		lookup, err := client.LookupACL(r.Context(), token, "", "")
		if err != nil {
			http.Error(w, "ror lookup failed: "+err.Error(), http.StatusBadGateway)
			return
		}

		resp := meClustersResponse{Clusters: []meClusterAccess{}}
		if rorScope, ok := lookup.Scopes["ror"]; ok {
			if g, ok := rorScope.Subject[ror.GlobalScopeSubject]; ok && g.Read {
				resp.GlobalRead = true
			}
		}
		if clusterScope, ok := lookup.Scopes["cluster"]; ok {
			for id, access := range clusterScope.Subject {
				resp.Clusters = append(resp.Clusters, meClusterAccess{
					ClusterID:       id,
					Read:            access.Read,
					Create:          access.Create,
					Update:          access.Update,
					Delete:          access.Delete,
					Owner:           access.Owner,
					KubernetesLogon: access.KubernetesLogon,
				})
			}
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
