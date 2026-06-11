package scam

import (
	"net/http"

	"github.com/NorskHelsenett/spam/internal/acl"
	"github.com/NorskHelsenett/spam/internal/hiddenns"
	"gorm.io/gorm"
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
//   - fragment with two `?` placeholders bound to the same []string of
//     pattern identifiers → grant-scoped. The IN-clause subquery
//     resolves each identifier as either a cluster_id (kube-system
//     UID, used by local grants) or a ror_slug (used by ROR-sourced
//     grants); see clusterACLFilterCol for the rationale.
//   - deny = true → no readable clusters; caller should short-circuit.
func clusterACLFilter(r *http.Request) (string, []any, bool) {
	return clusterACLFilterCol(r, "cr.data->>'cluster_id'")
}

// ClusterACLFilterCol is the exported entry point for handlers outside
// the scam package (e.g. uiapi.ImageDetailHandler) that need to scope
// a cluster_record read to the caller's grants. Delegates to the
// unexported implementation.
func ClusterACLFilterCol(r *http.Request, col string) (string, []any, bool) {
	return clusterACLFilterCol(r, col)
}

// clusterACLFilterCol is the same ACL resolution as clusterACLFilter
// but emits the IN-clause against an arbitrary column expression. Used
// by handlers that read from materialised views with a typed
// cluster_id column (e.g. host_exposure.cluster_id) rather than the
// JSONB-extracted cr.data->>'cluster_id'.
//
// Pattern identifiers may speak either of two identity domains:
//   - LocalProvider stores admin-curated grants by cluster_id
//     (kube-system Namespace UID), which is the join key used
//     everywhere else in the schema.
//   - RORProvider returns ROR-sourced grants identified by ROR slug.
//
// The subquery resolves both by joining through the `clusters` table,
// so the caller never has to know which provider sourced a grant. Each
// pattern that matches by cluster_id OR by ror_slug contributes the
// row's cluster_id to the IN-clause; the outer column is filtered
// against that authoritative set.
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
	frag := "(" + col + " IN (SELECT cluster_id FROM clusters WHERE cluster_id IN (?) OR (ror_slug <> '' AND ror_slug IN (?))))"
	return frag, []any{ids, ids}, false
}

// hiddenNamespaceWhere compiles the admin-curated hidden-namespace
// patterns (hiddenns package) into an "AND …" fragment over the given
// namespace column, or "" when nothing should be filtered. Admin and
// global_reader keep the unfiltered fleet view — hiding administrative
// namespaces (nhn-scam, nhn-ror, …) is a focus aid for regular users,
// not an access boundary.
func hiddenNamespaceWhere(r *http.Request, db *gorm.DB, col string) (string, []any) {
	subj := acl.SubjectFromRequest(r)
	if subj.IsAdmin || subj.IsGlobalReader {
		return "", nil
	}
	frag, args := hiddenns.Clause(r.Context(), db, col)
	if frag == "" {
		return "", nil
	}
	return "AND " + frag, args
}

// hiddenNamespaceMatch is the Go-side twin of hiddenNamespaceWhere for
// handlers that group rows in memory (ClusterChainHandler). Returns a
// predicate that reports whether a namespace should be hidden from the
// caller.
func hiddenNamespaceMatch(r *http.Request, db *gorm.DB) func(string) bool {
	subj := acl.SubjectFromRequest(r)
	if subj.IsAdmin || subj.IsGlobalReader {
		return func(string) bool { return false }
	}
	return hiddenns.MatcherFor(hiddenns.Patterns(r.Context(), db))
}

// canReadCluster is the per-cluster gate used by chain-style handlers
// that take an explicit cluster_id query parameter.
//
// Patterns sourced from ROR identify the cluster by slug rather than
// kube-system UID. When the direct equality check misses, fall through
// to a binding lookup and re-check against the slug — the RORProvider
// cache makes the second Grants call cheap.
func canReadCluster(r *http.Request, db *gorm.DB, clusterID string) (bool, error) {
	subj := acl.SubjectFromRequest(r)
	if subj.IsAdmin {
		return true, nil
	}
	p := acl.ProviderFromRequest(r)
	if ok, err := acl.CanReadCluster(r.Context(), p, subj, clusterID); err != nil || ok {
		return ok, err
	}
	var rorSlug string
	_ = db.WithContext(r.Context()).Raw(
		`SELECT ror_slug FROM clusters WHERE cluster_id = ? AND ror_slug <> ''`,
		clusterID,
	).Scan(&rorSlug).Error
	if rorSlug == "" {
		return false, nil
	}
	return acl.CanReadCluster(r.Context(), p, subj, rorSlug)
}
