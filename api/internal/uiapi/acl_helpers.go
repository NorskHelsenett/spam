package uiapi

import (
	"net/http"

	"github.com/NorskHelsenett/spam/internal/acl"
	"gorm.io/gorm"
)

// readableClusterIDSet returns the set of cluster_ids the subject can
// see plus a bool indicating "unrestricted" (admin / global_reader /
// wildcard grant). Clusters default to deny so a subject with no
// grants returns an empty set with unrestricted=false — the caller
// filters everything out.
//
// This helper lives here (not in scam/acl.go) so uiapi can reuse it
// without reaching into the scam package's unexported filter.
func readableClusterIDSet(r *http.Request, _ *gorm.DB) (map[string]struct{}, bool, error) {
	subj := acl.SubjectFromRequest(r)
	if subj.IsAdmin || subj.IsGlobalReader {
		return nil, true, nil
	}
	provider := acl.ProviderFromRequest(r)
	if provider == nil {
		return map[string]struct{}{}, false, nil
	}
	patterns, err := provider.Grants(r.Context(), subj, acl.ScopeCluster)
	if err != nil {
		return nil, false, err
	}
	set := make(map[string]struct{}, len(patterns))
	for _, p := range patterns {
		if p.IsWildcard() {
			return nil, true, nil
		}
		if p.ClusterID != "" {
			set[p.ClusterID] = struct{}{}
		}
	}
	return set, false, nil
}

// aclWhereFragment turns an acl.Clause into a (sql, args) pair suitable
// for splicing into a raw SQL WHERE list with `AND ` + fragment.
//
//   - Unrestricted → returns ("TRUE", nil). The caller still interpolates
//     the fragment and passes no extra args; the resulting WHERE is
//     equivalent to no ACL filter.
//   - Deny-all → returns ("FALSE", nil). The caller still interpolates
//     the fragment; Postgres short-circuits.
//   - Otherwise → returns ("("+SQL+")", Args). Parentheses isolate the
//     OR inside the clause from surrounding AND operators.
func aclWhereFragment(c acl.Clause) (string, []any) {
	if c.Unrestricted {
		return "TRUE", nil
	}
	if c.Deny() {
		return "FALSE", nil
	}
	return "(" + c.SQL + ")", c.Args
}

// canReadRepoByID loads the repo row for repoID and evaluates the
// caller's grants via acl.CanReadRepo. A missing repo returns
// (false, nil) — the handler should respond with 404 via
// notFoundOrForbidden so existence isn't leaked.
func canReadRepoByID(r *http.Request, db *gorm.DB, repoID string) (bool, error) {
	if repoID == "" {
		return false, nil
	}
	var row struct {
		Provider           string
		ProviderInstanceID string
		Org                string
		Slug               string
		IsPrivate          bool
	}
	if err := db.WithContext(r.Context()).
		Table("repos").
		Select("provider, provider_instance_id, org, slug, is_private").
		Where("id = ?", repoID).
		Scan(&row).Error; err != nil {
		return false, err
	}
	if row.Provider == "" && row.Slug == "" && row.Org == "" {
		// repo not found
		return false, nil
	}
	return acl.CanReadRepo(r.Context(), acl.ProviderFromRequest(r), acl.SubjectFromRequest(r), row.IsPrivate, acl.ScopePattern{
		Provider:           row.Provider,
		ProviderInstanceID: row.ProviderInstanceID,
		Owner:              row.Org,
		Slug:               row.Slug,
	})
}

// notFoundOrForbidden collapses 403-on-private and 404-on-missing into
// a single response so error messages never hint at the existence of
// a private resource the caller can't see.
func notFoundOrForbidden(w http.ResponseWriter) {
	http.Error(w, "not found", http.StatusNotFound)
}

// requireUnrestrictedRepos is the gate for aggregate handlers whose
// queries are too tangled to retrofit ACL filtering into. Returns true
// only for admins and callers with a wildcard repo grant (e.g. the
// grandfathered global_reader migration row). Restricted callers get
// 404 so existence of aggregate data isn't leaked.
//
// This is a deliberately narrow allow-list: anyone who'd have seen the
// aggregate under the pre-ACL model still sees it today, but users
// with genuinely scoped grants don't. Tighter per-subject scoping is
// a post-Phase-3 follow-up.
func requireUnrestrictedRepos(w http.ResponseWriter, r *http.Request) bool {
	if hasUnrestrictedRepos(r) {
		return true
	}
	notFoundOrForbidden(w)
	return false
}

// hasUnrestrictedRepos is the bool-returning counterpart to
// requireUnrestrictedRepos. Handlers that want to dispatch between a
// cached cross-tenant path and a scoped per-subject recompute use this
// to pick a branch without writing a 404; the scoped branch then
// handles its own ACL filtering.
func hasUnrestrictedRepos(r *http.Request) bool {
	subj := acl.SubjectFromRequest(r)
	if subj.IsAdmin || subj.IsGlobalReader {
		return true
	}
	prov := acl.ProviderFromRequest(r)
	if prov == nil {
		return false
	}
	patterns, err := prov.Grants(r.Context(), subj, acl.ScopeRepo)
	if err != nil {
		return false
	}
	for _, p := range patterns {
		if p.IsWildcard() {
			return true
		}
	}
	return false
}

// dependencyACLFragments compiles the readable-repo set into three
// WHERE fragments the dependency detail query needs:
//
//   - sbomRepoFilter    : applied where asset_type = 'REPO_COMMIT'. Matches
//                         when the repo_commit's repo is readable.
//   - sbomImageFilter   : applied where asset_type = 'IMAGE_DIGEST'. Matches
//                         when the image has verified_source=true AND its
//                         source_repo_id is readable.
//   - manifestFilter    : applied on the manifests → repos relation.
//
// For unrestricted callers all three collapse to TRUE with no args.
// For restricted callers with no readable repos all three collapse to
// FALSE (and thus no rows).
func dependencyACLFragments(unrestricted bool, readableIDs []string) (string, []any, string, []any, string, []any) {
	if unrestricted {
		return "TRUE", nil, "TRUE", nil, "TRUE", nil
	}
	if len(readableIDs) == 0 {
		return "FALSE", nil, "FALSE", nil, "FALSE", nil
	}
	// Each fragment needs its own args slice since we splice them
	// in at different positions in the query arg list.
	repoCommitFilter := "s.asset_ref_id IN (SELECT rc.id FROM repo_commits rc WHERE rc.repo_id IN ?)"
	imageDigestFilter := "s.asset_ref_id IN (SELECT d.id FROM image_digests d WHERE d.verified_source = true AND d.source_repo_id IN ?)"
	manifestRepoFilter := "m.repo_id IN ?"
	return repoCommitFilter, []any{readableIDs},
		imageDigestFilter, []any{readableIDs},
		manifestRepoFilter, []any{readableIDs}
}

// readableRepoIDSet returns the set of repo IDs the subject can see,
// plus a bool indicating "unrestricted" (admin or wildcard grant).
// When unrestricted is true, callers may skip post-filtering.
//
// Note: public repos (is_private = false) are always readable, so they
// are included in the returned set even for callers with no grants.
func readableRepoIDSet(r *http.Request, db *gorm.DB) (map[string]struct{}, bool, error) {
	clause, err := acl.ReadableRepoClause(r.Context(), acl.ProviderFromRequest(r), acl.SubjectFromRequest(r), "repos")
	if err != nil {
		return nil, false, err
	}
	if clause.Unrestricted {
		return nil, true, nil
	}
	var ids []string
	q := db.WithContext(r.Context()).Table("repos").Select("id")
	if clause.SQL != "" {
		q = q.Where(clause.SQL, clause.Args...)
	}
	if err := q.Scan(&ids).Error; err != nil {
		return nil, false, err
	}
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return set, false, nil
}

// canReadSBOM resolves an SBOM to its bound repo and delegates to
// canReadRepoByID. For REPO_COMMIT bindings, the owning repo is
// reached through repo_commits. For IMAGE_DIGEST bindings, access is
// inherited from the image's source_repo_id only when verified_source
// is true — unsigned-image SBOMs fall back to admin-only.
func canReadSBOM(r *http.Request, db *gorm.DB, sbomID string) (bool, error) {
	if sbomID == "" {
		return false, nil
	}
	var row struct{ RepoID string }
	err := db.WithContext(r.Context()).Raw(`
		SELECT CASE
		  WHEN b.asset_type = 'REPO_COMMIT' THEN COALESCE((
		    SELECT rc.repo_id FROM repo_commits rc WHERE rc.id = b.asset_ref_id LIMIT 1
		  ), '')
		  WHEN b.asset_type = 'IMAGE_DIGEST' THEN COALESCE((
		    SELECT d.source_repo_id FROM image_digests d
		    WHERE d.id = b.asset_ref_id AND d.verified_source = true AND d.source_repo_id <> ''
		    LIMIT 1
		  ), '')
		END AS repo_id
		FROM sbom_bindings b
		WHERE b.sbom_id = ?
		LIMIT 1
	`, sbomID).Scan(&row).Error
	if err != nil {
		return false, err
	}
	if row.RepoID == "" {
		// Unbound SBOM or bound to an unsigned image. Only admins
		// get to see those until an explicit image grant path is
		// modeled.
		return acl.SubjectFromRequest(r).IsAdmin, nil
	}
	return canReadRepoByID(r, db, row.RepoID)
}
