package scam

import (
	"net/http"

	"github.com/NorskHelsenett/spam/internal/acl"
)

// clusterACLFilter resolves the caller's cluster-read grants into a
// SQL fragment that is AND'd into the `live` CTE WHERE clause. Caller
// uses it like:
//
//	frag, aclArgs, deny := clusterACLFilter(r)
//	if deny { writeJSON(w, 200, empty); return }
//	sql := cteFor(r, frag) + `SELECT ... FROM live ...`
//	db.Raw(sql, append(aclArgs, otherArgs...)...).Scan(&rows)
//
// Results:
//   - fragment = "TRUE" (no args) → admin or wildcard grant; no-op
//     filter.
//   - fragment = "(cr.data->>'cluster_id' IN (?))" with one args entry
//     (a []string of readable cluster ids) → grant-scoped.
//   - deny = true → no readable clusters; caller should short-circuit.
func clusterACLFilter(r *http.Request) (string, []any, bool) {
	return clusterACLFilterCol(r, "cr.data->>'cluster_id'")
}

// clusterACLFilterCol is the same ACL resolution as clusterACLFilter
// but emits the IN-clause against an arbitrary column expression. Used
// by handlers that read from materialised views with a typed
// cluster_id column (e.g. host_exposure.cluster_id) rather than the
// JSONB-extracted cr.data->>'cluster_id'.
func clusterACLFilterCol(r *http.Request, col string) (string, []any, bool) {
	subj := acl.SubjectFromRequest(r)
	if subj.IsAdmin {
		return "TRUE", nil, false
	}

	provider := acl.ProviderFromRequest(r)
	if provider == nil {
		return "", nil, true
	}
	patterns, err := provider.Grants(r.Context(), subj, acl.ScopeCluster)
	if err != nil {
		// Fail closed.
		return "", nil, true
	}

	var ids []string
	for _, p := range patterns {
		if p.IsWildcard() {
			return "TRUE", nil, false
		}
		if p.ClusterID != "" {
			ids = append(ids, p.ClusterID)
		}
	}
	if len(ids) == 0 {
		return "", nil, true
	}
	return "(" + col + " IN (?))", []any{ids}, false
}

// canReadCluster is the per-cluster gate used by chain-style handlers
// that take an explicit cluster_id query parameter.
func canReadCluster(r *http.Request, clusterID string) (bool, error) {
	subj := acl.SubjectFromRequest(r)
	return acl.CanReadCluster(r.Context(), acl.ProviderFromRequest(r), subj, clusterID)
}
