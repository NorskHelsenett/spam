package uiapi

import (
	"net/http"
	"strings"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/ror"
	"gorm.io/gorm"
)

// meClusterAccess is the per-cluster slice returned to the SPA. It
// mirrors ror.LookupAccess but lives here so the upstream type isn't
// part of our public contract.
//
// ClusterID is the canonical kube-system UID used as the join key
// everywhere else in SPAM — resolved from whatever identifier ROR
// happened to key the grant by (slug, UID, or ROR name). DisplayName
// and the ROR fields are filled when the grant resolves to a known
// clusters-table row; Resolved is false when it doesn't, in which case
// ClusterID falls back to the (whitespace-trimmed) raw ROR key so the
// grant is still visible rather than silently dropped.
type meClusterAccess struct {
	ClusterID       string `json:"cluster_id"`
	DisplayName     string `json:"display_name,omitempty"`
	RorSlug         string `json:"ror_slug,omitempty"`
	RorClusterName  string `json:"ror_cluster_name,omitempty"`
	RorEnv          string `json:"ror_env,omitempty"`
	Resolved        bool   `json:"resolved"`
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
//
// ROR keys cluster grants inconsistently — sometimes by kube-system UID
// (a UUID), sometimes by ROR slug (often with stray whitespace), and
// the raw keys are leaky to consume downstream. We normalize here: trim
// the key, resolve it against the clusters table (cluster_id / ror_slug
// / ror_cluster_name, the same identifiers ClusterDetailHandler
// accepts), and emit the canonical cluster_id plus a display name so
// callers never have to special-case the upstream format. Grants that
// resolve to the same cluster are merged (permissions OR-ed).
func MeClustersHandler(db *gorm.DB, authService *auth.Service, client *ror.Client) http.HandlerFunc {
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

		clusterScope, ok := lookup.Scopes["cluster"]
		if !ok || len(clusterScope.Subject) == 0 {
			writeJSON(w, http.StatusOK, resp)
			return
		}

		// Trim ROR's keys up front and drop empties — ROR slugs arrive
		// with stray whitespace ("t-pps-001-y5r1 ") that breaks every
		// exact-match join downstream.
		access := make(map[string]ror.LookupAccess, len(clusterScope.Subject))
		idents := make([]string, 0, len(clusterScope.Subject))
		for rawID, a := range clusterScope.Subject {
			id := strings.TrimSpace(rawID)
			if id == "" {
				continue
			}
			access[id] = a
			idents = append(idents, id)
		}

		resp.Clusters = resolveMeClusters(r, db, idents, access)
		writeJSON(w, http.StatusOK, resp)
	}
}

// resolveMeClusters maps each (trimmed) ROR subject id to a canonical
// clusters-table row and collapses the result onto a per-cluster slice,
// merging permissions when two ROR keys resolve to the same cluster.
func resolveMeClusters(r *http.Request, db *gorm.DB, idents []string, access map[string]ror.LookupAccess) []meClusterAccess {
	type clusterRow struct {
		ClusterID      string
		DisplayName    string
		RorSlug        string
		RorClusterName string
		RorEnv         string
	}

	// One indexed read resolves every grant. Match on any of the three
	// identifier columns; the guards keep empty ror_* columns from
	// matching a blank-but-present grant key (idents are non-empty).
	var rows []clusterRow
	if db != nil && len(idents) > 0 {
		_ = db.WithContext(r.Context()).Raw(`
			SELECT cluster_id, display_name, ror_slug, ror_cluster_name, ror_env
			FROM clusters
			WHERE cluster_id IN (?)
			   OR (ror_slug <> '' AND ror_slug IN (?))
			   OR (ror_cluster_name <> '' AND ror_cluster_name IN (?))
		`, idents, idents, idents).Scan(&rows).Error
	}

	// Index resolved rows by every identifier they answer to, so a ROR
	// key in any column finds its canonical cluster_id.
	byIdent := make(map[string]clusterRow, len(rows)*3)
	for _, row := range rows {
		if row.ClusterID != "" {
			byIdent[row.ClusterID] = row
		}
		if row.RorSlug != "" {
			if _, seen := byIdent[row.RorSlug]; !seen {
				byIdent[row.RorSlug] = row
			}
		}
		if row.RorClusterName != "" {
			if _, seen := byIdent[row.RorClusterName]; !seen {
				byIdent[row.RorClusterName] = row
			}
		}
	}

	// Collapse onto canonical cluster_id (or the raw key when
	// unresolved), OR-ing permissions across colliding grants. ordered
	// preserves first-seen order so the output is stable.
	merged := make(map[string]*meClusterAccess, len(idents))
	ordered := make([]string, 0, len(idents))
	for _, id := range idents {
		a := access[id]
		row, resolved := byIdent[id]

		key := id
		if resolved && row.ClusterID != "" {
			key = row.ClusterID
		}

		entry, exists := merged[key]
		if !exists {
			entry = &meClusterAccess{ClusterID: key}
			if resolved {
				entry.DisplayName = row.DisplayName
				entry.RorSlug = row.RorSlug
				entry.RorClusterName = row.RorClusterName
				entry.RorEnv = row.RorEnv
				entry.Resolved = true
			}
			merged[key] = entry
			ordered = append(ordered, key)
		}
		entry.Read = entry.Read || a.Read
		entry.Create = entry.Create || a.Create
		entry.Update = entry.Update || a.Update
		entry.Delete = entry.Delete || a.Delete
		entry.Owner = entry.Owner || a.Owner
		entry.KubernetesLogon = entry.KubernetesLogon || a.KubernetesLogon
	}

	out := make([]meClusterAccess, 0, len(ordered))
	for _, key := range ordered {
		out = append(out, *merged[key])
	}
	return out
}
