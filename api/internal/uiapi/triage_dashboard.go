package uiapi

import (
	"fmt"
	"net/http"

	"github.com/NorskHelsenett/spam/internal/acl"
	"github.com/NorskHelsenett/spam/internal/assetrisk"
	"github.com/NorskHelsenett/spam/internal/auth"
	"gorm.io/gorm"
)

// TriageHandler returns the asset-centric triage view: scope inventory
// + three-tier ranked queue (fix_now / this_week / watch). One fat
// endpoint — the page renders all three sections in a single load.
//
// GET /api/triage?watch_limit=&watch_offset=&watch_q=
//
// ACL: every branch (repo / image / cluster) is independently scoped
// using the same clause helpers as the per-tab handlers. A caller with
// only repo grants gets repo rows; a caller with only cluster grants
// gets cluster rows. Restricted callers don't get notFoundOrForbidden
// because the page is the *entry point* of the app — returning a
// scoped, possibly-empty triage list is the right answer.
func TriageHandler(db *gorm.DB, _ *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireApproved(w, r) {
			return
		}

		q := r.URL.Query()
		params := assetrisk.TriageParams{
			WatchLimit:  parseIntDefault(q.Get("watch_limit"), 0),
			WatchOffset: parseIntDefault(q.Get("watch_offset"), 0),
			WatchSearch: q.Get("watch_q"),
		}

		subj := acl.SubjectFromRequest(r)
		prov := acl.ProviderFromRequest(r)

		repoClause, err := acl.ReadableRepoClause(r.Context(), prov, subj, "r")
		if err != nil {
			http.Error(w, "failed to scope results", http.StatusInternalServerError)
			return
		}
		imageClause, err := acl.ReadableImageClause(r.Context(), prov, subj, "d")
		if err != nil {
			http.Error(w, "failed to scope results", http.StatusInternalServerError)
			return
		}

		params.RepoSQL, params.RepoArgs = triageRepoFragment(repoClause)
		params.ImageSQL, params.ImageArgs = triageImageFragment(imageClause)
		params.ClusterSQL, params.ClusterArgs = triageClusterFragment(r, db)

		resp, err := assetrisk.LoadTriage(r.Context(), db, params)
		if err != nil {
			http.Error(w, "failed to load triage", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// triageRepoFragment scopes the asset_id (which holds repos.id::text
// for repo rows) against the readable-repo set.
func triageRepoFragment(c acl.Clause) (string, []any) {
	if c.Unrestricted {
		return "TRUE", nil
	}
	if c.Deny() {
		return "FALSE", nil
	}
	return fmt.Sprintf("asset_id IN (SELECT r.id FROM repos r WHERE %s)", c.SQL), c.Args
}

// triageImageFragment scopes the asset_id (image_digests.id::text)
// against the readable-image set.
func triageImageFragment(c acl.Clause) (string, []any) {
	if c.Unrestricted {
		return "TRUE", nil
	}
	if c.Deny() {
		return "FALSE", nil
	}
	return fmt.Sprintf("asset_id IN (SELECT d.id FROM image_digests d WHERE %s)", c.SQL), c.Args
}

// triageClusterFragment scopes the asset_id (which holds cluster_id
// for cluster rows). Admins / global readers / wildcard grants get
// "TRUE"; restricted callers get an IN-list of their grant cluster_ids;
// no grants returns "FALSE" so cluster rows drop out entirely.
func triageClusterFragment(r *http.Request, db *gorm.DB) (string, []any) {
	set, unrestricted, err := readableClusterIDSet(r, db)
	if err != nil || (set == nil && !unrestricted) {
		return "FALSE", nil
	}
	if unrestricted {
		return "TRUE", nil
	}
	if len(set) == 0 {
		return "FALSE", nil
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	return "asset_id IN ?", []any{ids}
}
